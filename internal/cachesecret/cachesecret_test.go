package cachesecret

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveExplicitOptionWins(t *testing.T) {
	require.Equal(t, "explicit", Resolve("explicit"))
}

func TestResolveSharesOneGeneratedSecretPerProcess(t *testing.T) {
	first := Resolve("")
	require.Len(t, first, 64, "expected a hex-encoded 256-bit secret")
	require.Equal(t, first, Resolve(""), "every client in the process must share the generated secret")
	require.NotEqual(t, first, Resolve("explicit"))
}

// setHome points the home directory at dir for the test.
func setHome(t *testing.T, dir string) {
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

// TestResolveReadsNoEnvironmentOrFile sets the environment variable and the
// home-directory file that earlier versions read, each on its own and then
// together, and shows that neither value is used and that no file is created.
func TestResolveReadsNoEnvironmentOrFile(t *testing.T) {
	const fromEnv, fromFile = "from-env", "from-file"
	writeOldFile := func(t *testing.T) (dir string) {
		home := t.TempDir()
		setHome(t, home)
		dir = filepath.Join(home, ".tinfoil")
		require.NoError(t, os.Mkdir(dir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "user_cache_secret"), []byte(fromFile), 0o600))
		return dir
	}
	requireGenerated := func(t *testing.T) {
		t.Helper()
		secret := Resolve("")
		require.NotEqual(t, fromEnv, secret)
		require.NotEqual(t, fromFile, secret)
		require.Len(t, secret, 64)
		require.Equal(t, "explicit", Resolve("explicit"))
	}

	t.Run("environment variable", func(t *testing.T) {
		t.Setenv("TINFOIL_USER_CACHE_SECRET", fromEnv)
		home := t.TempDir()
		setHome(t, home)
		requireGenerated(t)
		entries, err := os.ReadDir(home)
		require.NoError(t, err)
		require.Empty(t, entries, "no secret file or directory is created")
	})

	t.Run("home-directory file", func(t *testing.T) {
		t.Setenv("TINFOIL_USER_CACHE_SECRET", "")
		dir := writeOldFile(t)
		requireGenerated(t)
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1, "nothing is written next to the old file")
	})

	t.Run("both", func(t *testing.T) {
		t.Setenv("TINFOIL_USER_CACHE_SECRET", fromEnv)
		writeOldFile(t)
		requireGenerated(t)
	})
}

func TestObjectKeys(t *testing.T) {
	keys, ok := ObjectKeys([]byte(` {"model":"a", "n":{"model":"b"}, "mod\u0065l":[1,{"x":2}]} ` + "\n"))
	require.True(t, ok)
	require.Equal(t, []string{"model", "n", "model"}, keys, "repeats are kept, nested members are skipped and names are decoded")

	keys, ok = ObjectKeys([]byte(`{}`))
	require.True(t, ok)
	require.Empty(t, keys)

	for _, body := range []string{``, `[]`, `"model"`, `null`, `{"model":"a"`, `{"model":"a"}}`, `{"model":"a"} {}`, `{"model":}`, `{"a":1,}`} {
		_, ok := ObjectKeys([]byte(body))
		require.False(t, ok, "%q is not exactly one JSON object", body)
	}
}
