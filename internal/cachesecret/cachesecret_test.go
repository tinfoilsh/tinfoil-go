package cachesecret

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// unsetUserCacheSecretEnv removes TINFOIL_USER_CACHE_SECRET for the test (a
// developer .env loaded by TestMain may set it) and restores it afterwards.
func unsetUserCacheSecretEnv(t *testing.T) {
	t.Helper()
	t.Setenv(userCacheSecretEnv, "placeholder") // registers restoration
	require.NoError(t, os.Unsetenv(userCacheSecretEnv))
}

func TestResolveUserCacheSecretPrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	t.Run("explicit option beats environment", func(t *testing.T) {
		t.Setenv(userCacheSecretEnv, "from-env")
		require.Equal(t, "explicit", Resolve("explicit", true))
	})

	t.Run("explicit empty falls through to environment", func(t *testing.T) {
		t.Setenv(userCacheSecretEnv, "from-env")
		require.Equal(t, "from-env", Resolve("", true))
	})

	t.Run("environment beats generation and touches no file", func(t *testing.T) {
		t.Setenv(userCacheSecretEnv, "from-env")
		require.Equal(t, "from-env", Resolve("", false))
		_, err := os.Stat(filepath.Join(home, userCacheSecretDirName))
		require.True(t, os.IsNotExist(err), "an environment-provided secret must not create the secret file")
	})

	t.Run("environment set but empty falls through to generation", func(t *testing.T) {
		t.Setenv(userCacheSecretEnv, "")
		require.Len(t, Resolve("", false), 64)
		_, err := os.Stat(filepath.Join(home, userCacheSecretDirName, userCacheSecretFileName))
		require.NoError(t, err)
	})
}

func TestUserCacheSecretGenerateAndPersist(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	first := Resolve("", false)
	require.Len(t, first, 64, "expected a hex-encoded 256-bit secret")

	path := filepath.Join(home, userCacheSecretDirName, userCacheSecretFileName)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// A second resolution (a new client, or another SDK on the same machine)
	// must reuse the persisted secret, not mint a new namespace.
	require.Equal(t, first, Resolve("", false))
}

func TestUserCacheSecretAdoptsExistingFile(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, userCacheSecretDirName)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	// Trailing newline: the file may be hand-edited or written by another SDK.
	require.NoError(t, os.WriteFile(filepath.Join(dir, userCacheSecretFileName), []byte("shared-secret\n"), 0o600))

	require.Equal(t, "shared-secret", Resolve("", false))
}

func TestUserCacheSecretRejectsInvalidUTF8WithoutRewriting(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, userCacheSecretDirName)
	path := filepath.Join(dir, userCacheSecretFileName)
	corrupted := []byte{0xff, 0xfe, 'a'}
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(path, corrupted, 0o600))

	first := Resolve("", false)
	require.Len(t, first, 64)
	require.Equal(t, first, Resolve("", false))
	persisted, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, corrupted, persisted)
}

func TestUserCacheSecretAcceptsPermissiveExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose POSIX permission bits")
	}
	unsetUserCacheSecretEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, userCacheSecretDirName)
	path := filepath.Join(dir, userCacheSecretFileName)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(path, []byte("shared-secret"), 0o600))
	require.NoError(t, os.Chmod(dir, 0o777))
	require.NoError(t, os.Chmod(path, 0o666))

	require.Equal(t, "shared-secret", Resolve("", false))
	requireFileMode(t, dir, 0o777)
	requireFileMode(t, path, 0o666)
}

func TestUserCacheSecretLeavesBlankFileUntouched(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, userCacheSecretDirName)
	path := filepath.Join(dir, userCacheSecretFileName)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(path, []byte("  \n"), 0o600))

	first := Resolve("", false)
	require.Len(t, first, 64)
	require.Equal(t, first, Resolve("", false))
	written, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("  \n"), written)
}

func TestUserCacheSecretConcurrentProcesses(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, userCacheSecretDirName, userCacheSecretFileName)
	secrets := runUserCacheSecretContenders(t, home, userCacheSecretContenderCount)
	for _, secret := range secrets {
		require.Equal(t, secrets[0], secret, "all processes must adopt the elected value")
		require.Len(t, secret, 64)
	}
	persisted, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, secrets[0], strings.TrimSpace(string(persisted)))
	requireFileMode(t, path, 0o600)
}

func TestUserCacheSecretSubprocess(t *testing.T) {
	if os.Getenv("TINFOIL_CACHE_SECRET_HELPER") != "1" {
		return
	}
	_ = os.Unsetenv(userCacheSecretEnv)
	fmt.Println("ready")
	var release [1]byte
	if _, err := io.ReadFull(os.Stdin, release[:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println(Resolve("", false))
	os.Exit(0)
}

const userCacheSecretContenderCount = 8

type userCacheSecretContender struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr bytes.Buffer
}

func runUserCacheSecretContenders(t *testing.T, home string, count int) []string {
	t.Helper()
	contenders := make([]userCacheSecretContender, count)
	for i := range contenders {
		cmd := exec.Command(os.Args[0], "-test.run=^TestUserCacheSecretSubprocess$")
		cmd.Env = userCacheSecretHelperEnv(home)
		stdin, err := cmd.StdinPipe()
		require.NoError(t, err)
		stdout, err := cmd.StdoutPipe()
		require.NoError(t, err)
		contenders[i] = userCacheSecretContender{
			cmd:    cmd,
			stdin:  stdin,
			stdout: bufio.NewReader(stdout),
		}
		cmd.Stderr = &contenders[i].stderr
		require.NoError(t, cmd.Start())
		ready, err := contenders[i].stdout.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "ready", strings.TrimSpace(ready))
	}

	for i := range contenders {
		_, err := contenders[i].stdin.Write([]byte{1})
		require.NoError(t, err)
		require.NoError(t, contenders[i].stdin.Close())
	}

	secrets := make([]string, count)
	for i := range contenders {
		secret, err := contenders[i].stdout.ReadString('\n')
		require.NoError(t, err)
		waitErr := contenders[i].cmd.Wait()
		require.NoError(t, waitErr, contenders[i].stderr.String())
		secrets[i] = strings.TrimSpace(secret)
	}
	return secrets
}

func userCacheSecretHelperEnv(home string) []string {
	env := make([]string, 0, len(os.Environ())+3)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "HOME=") ||
			strings.HasPrefix(value, "USERPROFILE=") ||
			strings.HasPrefix(value, userCacheSecretEnv+"=") ||
			strings.HasPrefix(value, "TINFOIL_CACHE_SECRET_HELPER=") {
			continue
		}
		env = append(env, value)
	}
	return append(
		env,
		"HOME="+home,
		"USERPROFILE="+home,
		"TINFOIL_CACHE_SECRET_HELPER=1",
	)
}

func requireFileMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, mode, info.Mode().Perm())
}

func TestUserCacheSecretFallsBackWithoutHome(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	t.Setenv("HOME", "")

	first := Resolve("", false)
	require.NotEmpty(t, first, "no home directory must still yield a process-lifetime secret")
	require.Equal(t, first, Resolve("", false), "the in-memory fallback must be stable within the process")
}

func TestUserCacheSecretFallsBackWhenHomeNotADirectory(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	homeFile := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(homeFile, []byte("x"), 0o600))
	t.Setenv("HOME", homeFile)

	require.NotEmpty(t, Resolve("", false))
}

// captureTransport returns a userCacheSecretTransport whose inner round
// tripper records the outgoing body.
