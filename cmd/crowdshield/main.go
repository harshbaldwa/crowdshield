package main

import (
	"fmt"
	"io"
	"os"

	"crowdshield/internal/buildinfo"
)

const usage = "usage: crowdshield <run|sync|status|validate-config|list-feeds|explain|prune|version> [options]"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		_, _ = fmt.Fprintln(stdout, buildinfo.Current().String())
		return 0
	}

	_, _ = fmt.Fprintln(stderr, usage)
	return 2
}
