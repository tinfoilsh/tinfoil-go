package tinfoil

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadUserCacheSecretFileRejectsStaticSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	contents := []byte("target-secret")
	require.NoError(t, os.WriteFile(target, contents, 0o644))
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	_, err := readUserCacheSecretFile(link)
	require.Error(t, err)
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, contents, got)
	requireFileMode(t, target, 0o644)
}

func TestValidateUserCacheSecretDirRejectsStaticSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Mkdir(target, 0o755))
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	require.Error(t, validateUserCacheSecretDir(link))
	requireFileMode(t, target, 0o755)
}

func TestUserCacheSecretPathsRejectUnexpectedTypes(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	directory := filepath.Join(dir, "directory")
	require.NoError(t, os.WriteFile(file, []byte("unchanged"), 0o644))
	require.NoError(t, os.Mkdir(directory, 0o755))

	require.Error(t, validateUserCacheSecretDir(file))
	_, err := readUserCacheSecretFile(directory)
	require.Error(t, err)
	requireFileMode(t, file, 0o644)
	requireFileMode(t, directory, 0o755)
}

func TestUserCacheSecretPathsPreserveNotExist(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	require.ErrorIs(t, validateUserCacheSecretDir(missing), fs.ErrNotExist)
	_, err := readUserCacheSecretFile(missing)
	require.ErrorIs(t, err, fs.ErrNotExist)
}
