package version

import "fmt"

// Build variables are set with -ldflags for release builds.
var (
	Version   = "devel"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func String() string {
	return fmt.Sprintf("version=%s commit=%s build_time=%s", Version, Commit, BuildTime)
}
