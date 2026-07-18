// Package buildinfo exposes immutable build metadata populated with linker flags.
package buildinfo

import (
	"fmt"
	"runtime"
)

const Name = "crowdshield"

// These values are overridden at build time with -ldflags. They intentionally
// contain no host, path, or credential information in development builds.
var (
	Version   = "dev"
	Revision  = "unknown"
	BuildDate = "unknown"
)

// Info is the public, non-sensitive build identity.
type Info struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Revision  string `json:"revision"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
}

// Current returns metadata for the running binary.
func Current() Info {
	return Info{
		Name:      Name,
		Version:   Version,
		Revision:  Revision,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
	}
}

// String renders a stable administrator-facing version line.
func (i Info) String() string {
	return fmt.Sprintf("%s %s (revision %s, built %s, %s %s/%s)",
		i.Name, i.Version, i.Revision, i.BuildDate, i.GoVersion, i.GOOS, i.GOARCH)
}
