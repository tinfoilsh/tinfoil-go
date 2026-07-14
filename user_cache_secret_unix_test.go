package tinfoil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserCacheSecretRejectsSymlinksWithoutTouchingTargets(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, userCacheSecretDirName)
	require.NoError(t, os.MkdirAll(dir, 0o700))

	target := filepath.Join(home, "symlink-target")
	targetContents := []byte("target-secret")
	require.NoError(t, os.WriteFile(target, targetContents, 0o644))
	if err := os.Symlink(target, filepath.Join(dir, userCacheSecretFileName)); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	require.NotEqual(t, string(targetContents), DefaultUserCacheSecret())
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, targetContents, got)
	requireFileMode(t, target, 0o644)
}

func TestUserCacheSecretRejectsSymlinkDirectoryWithoutTouchingTarget(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	target := filepath.Join(home, "target")
	require.NoError(t, os.Mkdir(target, 0o755))
	marker := filepath.Join(target, "marker")
	require.NoError(t, os.WriteFile(marker, []byte("unchanged"), 0o644))
	if err := os.Symlink(target, filepath.Join(home, userCacheSecretDirName)); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	require.NotEmpty(t, DefaultUserCacheSecret())
	requireFileMode(t, target, 0o755)
	got, err := os.ReadFile(marker)
	require.NoError(t, err)
	require.Equal(t, []byte("unchanged"), got)
	_, err = os.Lstat(filepath.Join(target, userCacheSecretFileName))
	require.True(t, os.IsNotExist(err))
}

func TestUserCacheSecretRejectsNonRegularFilesWithoutChmod(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, userCacheSecretDirName)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	nonRegular := filepath.Join(dir, userCacheSecretFileName)
	require.NoError(t, os.Mkdir(nonRegular, 0o755))

	require.NotEmpty(t, DefaultUserCacheSecret())
	requireFileMode(t, nonRegular, 0o755)
}
