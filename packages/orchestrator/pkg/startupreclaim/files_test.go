//go:build linux

package startupreclaim

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchingFilePaths(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	cacheDir := t.TempDir()
	matching := []string{
		filepath.Join(tmpDir, "fc-sbx-rand.sock"),
		filepath.Join(tmpDir, "uffd-sbx-rand.sock"),
		filepath.Join(tmpDir, "fc-metrics-sbx-rand.fifo"),
		filepath.Join(cacheDir, "rootfs-sbx-rand.cow"),
		filepath.Join(cacheDir, "rootfs-sbx-rand.link"),
	}
	for _, path := range matching {
		require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "fc.sock"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "rootfs-sbx.cow"), []byte("x"), 0o600))

	paths, err := matchingFilePaths(tmpDir, cacheDir)
	require.NoError(t, err)
	require.ElementsMatch(t, matching, paths)
}
