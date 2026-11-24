package sdkinfo

import (
	"runtime/debug"
	"strings"
)

const (
	Name       = "tinfoil-go"
	modulePath = "github.com/tinfoilsh/tinfoil-go"
)

func Version() string {
	return version(debug.ReadBuildInfo())
}

func version(info *debug.BuildInfo, ok bool) string {
	if !ok {
		return "unknown"
	}
	if info.Main.Path == modulePath {
		return buildModuleVersion(&info.Main)
	}
	for _, dependency := range info.Deps {
		if dependency.Path == modulePath {
			return buildModuleVersion(dependency)
		}
	}
	return "unknown"
}

func buildModuleVersion(module *debug.Module) string {
	if module.Replace != nil {
		module = module.Replace
	}
	version := strings.TrimPrefix(module.Version, "v")
	if version == "" || version == "(devel)" {
		return "devel"
	}
	return version
}

// IsRelease reports whether version, as Version returns it, names a release
// of this module rather than a development build ("devel") or a build
// without the module in its build information ("unknown").
func IsRelease(version string) bool {
	return version != "" && version != "devel" && version != "unknown"
}
