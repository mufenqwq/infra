//go:build linux

package startupreclaim

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSlotIndexFromCmdline(t *testing.T) {
	t.Parallel()

	idx, ok := slotIndexFromCmdline([]string{"bash", "-c", "ip netns exec ns-7 /opt/firecracker --api-sock /tmp/fc.sock"})
	require.True(t, ok)
	require.Equal(t, 7, idx)

	_, ok = slotIndexFromCmdline([]string{"bash", "-c", "ip netns exec ns-0 /opt/firecracker"})
	require.False(t, ok)
}

func TestDiscoverFirecrackerProcessesUsesNetnsMatch(t *testing.T) {
	t.Parallel()

	procDir := t.TempDir()
	netnsDir := t.TempDir()
	nsTarget := filepath.Join(t.TempDir(), "netns-target")
	require.NoError(t, os.WriteFile(nsTarget, []byte("ns"), 0o600))
	require.NoError(t, os.Symlink(nsTarget, filepath.Join(netnsDir, "ns-7")))

	createProc(t, procDir, 101, 100, []string{"/opt/firecracker", "--api-sock", "/tmp/fc.sock"}, nsTarget)
	createProc(t, procDir, 100, 1, []string{"bash", "-c", "ip netns exec ns-7 /opt/firecracker"}, "")
	createProc(t, procDir, 200, 1, []string{"bash", "-c", "not firecracker"}, "")

	procs, err := discoverFirecrackerProcesses(procDir, netnsDir)
	require.NoError(t, err)
	require.Len(t, procs, 1)
	require.Equal(t, 101, procs[0].PID)
	require.Equal(t, 7, procs[0].SlotIdx)
	require.Equal(t, "ns-7", procs[0].Namespace)
}

func TestDiscoverFirecrackerProcessesFallsBackToAncestorCmdline(t *testing.T) {
	t.Parallel()

	procDir := t.TempDir()
	netnsDir := t.TempDir()

	createProc(t, procDir, 101, 100, []string{"firecracker", "--api-sock", "/tmp/fc.sock"}, "")
	createProc(t, procDir, 100, 1, []string{"bash", "-c", "mount --make-rprivate / && ip netns exec ns-8 firecracker"}, "")

	procs, err := discoverFirecrackerProcesses(procDir, netnsDir)
	require.NoError(t, err)
	require.Len(t, procs, 1)
	require.Equal(t, 8, procs[0].SlotIdx)
}

func createProc(t *testing.T, procDir string, pid, ppid int, cmdline []string, netnsTarget string) {
	t.Helper()

	pidDir := filepath.Join(procDir, strconv.Itoa(pid))
	require.NoError(t, os.MkdirAll(filepath.Join(pidDir, "ns"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte(strings.Join(cmdline, "\x00")+"\x00"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(pidDir, "status"), []byte("Name:\ttest\nPPid:\t"+strconv.Itoa(ppid)+"\n"), 0o600))
	if netnsTarget != "" {
		require.NoError(t, os.Symlink(netnsTarget, filepath.Join(pidDir, "ns", "net")))
	}
}
