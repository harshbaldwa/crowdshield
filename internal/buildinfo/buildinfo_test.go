package buildinfo

import (
	"runtime"
	"testing"
)

func TestCurrentUsesSafeDevelopmentDefaults(t *testing.T) {
	got := Current()
	if got.Name != "crowdshield" {
		t.Fatal("unexpected binary name")
	}
	if got.Version != "dev" || got.Revision != "unknown" || got.BuildDate != "unknown" {
		t.Fatal("unsafe or unstable development build metadata")
	}
	if got.GoVersion != runtime.Version() {
		t.Fatal("Go runtime version not reported")
	}
}

func TestInfoStringIsStable(t *testing.T) {
	info := Info{
		Name:      "crowdshield",
		Version:   "1.2.3",
		Revision:  "abc123",
		BuildDate: "2026-07-17T00:00:00Z",
		GoVersion: "go1.26.5",
		GOOS:      "linux",
		GOARCH:    "amd64",
	}
	const want = "crowdshield 1.2.3 (revision abc123, built 2026-07-17T00:00:00Z, go1.26.5 linux/amd64)"
	if got := info.String(); got != want {
		t.Fatal("build information format changed")
	}
}
