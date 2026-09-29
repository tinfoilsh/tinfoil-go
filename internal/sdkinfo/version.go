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
