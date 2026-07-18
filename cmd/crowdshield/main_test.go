package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersionDoesNotRequireConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatal("version command failed")
	}
	if !strings.HasPrefix(stdout.String(), "crowdshield dev ") {
		t.Fatal("version output missing safe build identity")
	}
	if stderr.Len() != 0 {
		t.Fatal("version wrote unexpected diagnostic output")
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"not-a-command"}, &stdout, &stderr); code != 2 {
		t.Fatal("unexpected usage exit code")
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage:") {
		t.Fatal("unknown command did not return concise usage")
	}
}
