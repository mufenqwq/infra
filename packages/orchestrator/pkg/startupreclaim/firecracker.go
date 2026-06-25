//go:build linux

package startupreclaim

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/network"
)

var namespacePattern = regexp.MustCompile(`\bns-([0-9]+)\b`)

type firecrackerProcess struct {
	PID       int
	SlotIdx   int
	Namespace string
}

func discoverFirecrackerProcesses(procDir, netnsDir string) ([]firecrackerProcess, error) {
	netnsByIdentity, err := netnsIdentities(netnsDir)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read proc directory: %w", err)
	}

	procs := make([]firecrackerProcess, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		cmdline, err := processCmdline(procDir, pid)
		if err != nil || !isFirecrackerCmdline(cmdline) {
			continue
		}

		slotIdx, namespace := slotFromProcessNamespace(procDir, pid, netnsByIdentity)
		if slotIdx == 0 {
			slotIdx, namespace = slotFromProcessAncestry(procDir, pid)
		}

		procs = append(procs, firecrackerProcess{PID: pid, SlotIdx: slotIdx, Namespace: namespace})
	}

	return procs, nil
}

func netnsIdentities(netnsDir string) (map[string]int, error) {
	entries, err := os.ReadDir(netnsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]int{}, nil
		}

		return nil, fmt.Errorf("failed to read netns directory: %w", err)
	}

	identities := make(map[string]int)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		idx, ok := network.SlotIndexFromNamespace(entry.Name())
		if !ok {
			continue
		}

		identity, err := namespaceIdentity(filepath.Join(netnsDir, entry.Name()))
		if err != nil {
			continue
		}

		identities[identity] = idx
	}

	return identities, nil
}

func slotFromProcessNamespace(procDir string, pid int, netnsByIdentity map[string]int) (int, string) {
	identity, err := namespaceIdentity(filepath.Join(procDir, strconv.Itoa(pid), "ns", "net"))
	if err != nil {
		return 0, ""
	}

	idx, ok := netnsByIdentity[identity]
	if !ok {
		return 0, ""
	}

	return idx, network.NamespaceName(idx)
}

func slotFromProcessAncestry(procDir string, pid int) (int, string) {
	for range 16 {
		ppid, err := processParentPID(procDir, pid)
		if err != nil || ppid <= 0 || ppid == pid {
			return 0, ""
		}

		cmdline, err := processCmdline(procDir, ppid)
		if err == nil {
			idx, ok := slotIndexFromCmdline(cmdline)
			if ok {
				return idx, network.NamespaceName(idx)
			}
		}

		pid = ppid
	}

	return 0, ""
}

func namespaceIdentity(path string) (string, error) {
	info, err := os.Stat(path)
	if err == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino), nil
		}
	}

	target, linkErr := os.Readlink(path)
	if linkErr == nil {
		return target, nil
	}
	if err != nil {
		return "", err
	}

	return "", linkErr
}

func processCmdline(procDir string, pid int) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(procDir, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil, err
	}

	data = bytes.TrimRight(data, "\x00")
	if len(data) == 0 {
		return nil, nil
	}

	parts := bytes.Split(data, []byte{0})
	cmdline := make([]string, 0, len(parts))
	for _, part := range parts {
		cmdline = append(cmdline, string(part))
	}

	return cmdline, nil
}

func processParentPID(procDir string, pid int) (int, error) {
	data, err := os.ReadFile(filepath.Join(procDir, strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}

	for line := range strings.SplitSeq(string(data), "\n") {
		value, ok := strings.CutPrefix(line, "PPid:")
		if !ok {
			continue
		}

		return strconv.Atoi(strings.TrimSpace(value))
	}

	return 0, fmt.Errorf("PPid not found for pid %d", pid)
}

func isFirecrackerCmdline(cmdline []string) bool {
	if len(cmdline) == 0 {
		return false
	}

	return strings.Contains(filepath.Base(cmdline[0]), "firecracker")
}

func slotIndexFromCmdline(cmdline []string) (int, bool) {
	for _, arg := range cmdline {
		match := namespacePattern.FindStringSubmatch(arg)
		if len(match) != 2 {
			continue
		}

		idx, ok := network.SlotIndexFromNamespace("ns-" + match[1])
		if ok {
			return idx, true
		}
	}

	return 0, false
}
