package credentials

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const passwordCanary = "machine-password-canary-do-not-emit"

func writeCredential(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal("unable to create credential fixture")
	}
	return path
}

func validCredentialBody() string {
	return "url: http://crowdsec:8080\nlogin: crowdshield-dev\npassword: " + passwordCanary + "\n"
}

func testLoader() Loader {
	return Loader{MaxBytes: DefaultMaxBytes, StrictPermissions: true, AllowedHTTPHosts: []string{"crowdsec"}}
}

func TestLoadValidCredential(t *testing.T) {
	creds, err := testLoader().Load(writeCredential(t, validCredentialBody(), 0o600))
	if err != nil {
		t.Fatal("valid credential rejected")
	}
	defer creds.Destroy()
	if creds.Login() != "crowdshield-dev" || creds.Password() != passwordCanary {
		t.Fatal("credential fields not available to protocol boundary")
	}
	if endpoint := creds.Endpoint(); endpoint.Scheme != "http" || endpoint.Host != "crowdsec:8080" {
		t.Fatal("credential endpoint not normalized")
	}
}

func TestCredentialFormattingIsRedacted(t *testing.T) {
	creds, err := testLoader().Load(writeCredential(t, validCredentialBody(), 0o600))
	if err != nil {
		t.Fatal("valid credential rejected")
	}
	defer creds.Destroy()
	for _, rendered := range []string{
		fmt.Sprint(creds),
		fmt.Sprintf("%v", creds),
		fmt.Sprintf("%+v", creds),
		fmt.Sprintf("%#v", creds),
	} {
		if strings.Contains(rendered, passwordCanary) {
			t.Fatal("credential formatting disclosed password")
		}
	}
}

func TestLoadRejectsMissingMalformedAndUnknownFieldsWithoutLeak(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "missing password", body: "url: http://crowdsec:8080\nlogin: crowdshield-dev\n"},
		{name: "malformed", body: "url: [\npassword: " + passwordCanary + "\n"},
		{name: "unknown", body: validCredentialBody() + "token: " + passwordCanary + "\n"},
		{name: "second document", body: validCredentialBody() + "---\n{}\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := testLoader().Load(writeCredential(t, tc.body, 0o600))
			if err == nil {
				t.Fatal("invalid credential accepted")
			}
			if strings.Contains(err.Error(), passwordCanary) {
				t.Fatal("credential error disclosed password")
			}
		})
	}
}

func TestLoadRejectsOversizedCredential(t *testing.T) {
	loader := testLoader()
	loader.MaxBytes = 32
	_, err := loader.Load(writeCredential(t, validCredentialBody(), 0o600))
	if err == nil || !IsCategory(err, ErrSize) {
		t.Fatal("oversized credential accepted")
	}
}

func TestLoadRejectsUnsafePermissions(t *testing.T) {
	path := writeCredential(t, validCredentialBody(), 0o644)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal("unable to set credential fixture mode")
	}
	_, err := testLoader().Load(path)
	if err == nil || !IsCategory(err, ErrPermissions) {
		t.Fatal("unsafe credential permissions accepted")
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	link := filepath.Join(dir, "link.yaml")
	if err := os.WriteFile(target, []byte(validCredentialBody()), 0o600); err != nil {
		t.Fatal("unable to create target")
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal("unable to create symlink")
	}
	_, err := testLoader().Load(link)
	if err == nil || !IsCategory(err, ErrFileType) {
		t.Fatal("credential symlink accepted")
	}
}

func TestPlainHTTPIsRestrictedToExplicitHosts(t *testing.T) {
	body := "url: http://remote.example.invalid:8080\nlogin: crowdshield-dev\npassword: " + passwordCanary + "\n"
	_, err := testLoader().Load(writeCredential(t, body, 0o600))
	if err == nil || !IsCategory(err, ErrURL) {
		t.Fatal("unapproved plaintext LAPI host accepted")
	}
}

func TestDestroyClearsPassword(t *testing.T) {
	creds, err := testLoader().Load(writeCredential(t, validCredentialBody(), 0o600))
	if err != nil {
		t.Fatal("valid credential rejected")
	}
	creds.Destroy()
	if creds.Password() != "" {
		t.Fatal("destroy did not clear password")
	}
}
