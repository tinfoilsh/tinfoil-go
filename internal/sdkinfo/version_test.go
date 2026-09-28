package sdkinfo

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	tests := []struct {
		name    string
		info    *debug.BuildInfo
		ok      bool
		version string
	}{
		{name: "released main module", info: &debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "v1.2.3"}}, ok: true, version: "1.2.3"},
		{name: "released dependency", info: &debug.BuildInfo{Main: debug.Module{Path: "example.com/app"}, Deps: []*debug.Module{{Path: modulePath, Version: "v2.3.4"}}}, ok: true, version: "2.3.4"},
		{name: "local replacement", info: &debug.BuildInfo{Main: debug.Module{Path: "example.com/app"}, Deps: []*debug.Module{{Path: modulePath, Version: "v1.2.3", Replace: &debug.Module{Path: "../tinfoil-go"}}}}, ok: true, version: "devel"},
		{name: "development build", info: &debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "(devel)"}}, ok: true, version: "devel"},
		{name: "missing build info", ok: false, version: "unknown"},
		{name: "module absent", info: &debug.BuildInfo{Main: debug.Module{Path: "example.com/app"}}, ok: true, version: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.version, version(tt.info, tt.ok))
		})
	}
}
