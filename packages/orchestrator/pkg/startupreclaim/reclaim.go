//go:build linux

package startupreclaim

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/cgroup"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/nbd"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/network"
	"github.com/e2b-dev/infra/packages/shared/pkg/logger"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage"
	"github.com/e2b-dev/infra/packages/shared/pkg/utils"
)

const (
	resourceFirecracker = "firecracker"
	resourceNBD         = "nbd"
	resourceNetwork     = "network"
	resourceCgroup      = "cgroup"
	resourceFile        = "file"

	procDir = "/proc"
)

var (
	meter = otel.Meter("github.com/e2b-dev/infra/packages/orchestrator/pkg/startupreclaim")

	reclaimedCounter = utils.Must(meter.Int64Counter("orchestrator.startup_reclaim.reclaimed",
		metric.WithDescription("Startup reclaim resources successfully reclaimed."),
		metric.WithUnit("{resource}"),
	))
	failedCounter = utils.Must(meter.Int64Counter("orchestrator.startup_reclaim.failed",
		metric.WithDescription("Startup reclaim resource cleanup failures."),
		metric.WithUnit("{resource}"),
	))
)

type Config struct {
	NetworkConfig network.Config
	EgressProxy   network.EgressProxy
	CgroupManager cgroup.Manager
	StorageConfig storage.Config
	TempDir       string
	ProcDir       string
	NetnsDir      string
	CgroupRoot    string
}

type Summary struct {
	Reclaimed map[string]int
	Failed    map[string]int
}

func (s Summary) totalReclaimed() int {
	return total(s.Reclaimed)
}

func (s Summary) totalFailed() int {
	return total(s.Failed)
}

func total(values map[string]int) int {
	total := 0
	for _, value := range values {
		total += value
	}

	return total
}

func Run(ctx context.Context, config Config) Summary {
	config = config.withDefaults()
	summary := Summary{Reclaimed: map[string]int{}, Failed: map[string]int{}}
	networkSlots := map[int]struct{}{}

	for _, proc := range discoverFirecrackers(ctx, config, &summary) {
		if proc.SlotIdx > 0 {
			networkSlots[proc.SlotIdx] = struct{}{}
		}
	}

	reclaimNBD(ctx, &summary)

	for _, idx := range discoverNetworkSlots(ctx, config.NetnsDir, &summary) {
		networkSlots[idx] = struct{}{}
	}
	reclaimNetworks(ctx, config, networkSlots, &summary)

	reclaimCgroups(ctx, config, &summary)
	reclaimFiles(ctx, config, &summary)

	fields := []zap.Field{
		zap.Any("reclaimed", summary.Reclaimed),
		zap.Any("failed", summary.Failed),
		zap.Int("total_reclaimed", summary.totalReclaimed()),
		zap.Int("total_failed", summary.totalFailed()),
	}
	if summary.totalReclaimed() > 0 || summary.totalFailed() > 0 {
		logger.L().Warn(ctx, "startup resource reclaim completed with leftover resources", fields...)
	} else {
		logger.L().Info(ctx, "startup resource reclaim completed cleanly", fields...)
	}

	return summary
}

func (c Config) withDefaults() Config {
	if c.TempDir == "" {
		c.TempDir = os.TempDir()
	}
	if c.ProcDir == "" {
		c.ProcDir = procDir
	}
	if c.NetnsDir == "" {
		c.NetnsDir = network.NetNamespacesDir
	}
	if c.CgroupRoot == "" {
		c.CgroupRoot = cgroup.RootCgroupPath
	}
	if c.EgressProxy == nil {
		c.EgressProxy = network.NewNoopEgressProxy()
	}

	return c
}

func discoverFirecrackers(ctx context.Context, config Config, summary *Summary) []firecrackerProcess {
	procs, err := discoverFirecrackerProcesses(config.ProcDir, config.NetnsDir)
	if err != nil {
		fail(ctx, summary, resourceFirecracker, err)

		return nil
	}

	for _, proc := range procs {
		pgid, err := syscall.Getpgid(proc.PID)
		if err != nil {
			fail(ctx, summary, resourceFirecracker, fmt.Errorf("failed to get firecracker pgid for pid %d: %w", proc.PID, err))

			continue
		}

		if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			fail(ctx, summary, resourceFirecracker, fmt.Errorf("failed to kill firecracker process group %d for pid %d: %w", pgid, proc.PID, err))

			continue
		}

		reclaim(ctx, summary, resourceFirecracker)
		logger.L().Warn(ctx, "killed orphaned firecracker process group",
			zap.Int("pid", proc.PID),
			zap.Int("pgid", pgid),
			zap.Int("slot_index", proc.SlotIdx),
			zap.String("namespace", proc.Namespace))
	}

	return procs
}

func reclaimNBD(ctx context.Context, summary *Summary) {
	devices, err := nbd.ConnectedDevices()
	if err != nil {
		fail(ctx, summary, resourceNBD, err)

		return
	}

	for _, device := range devices {
		if err := nbd.DisconnectDevice(ctx, device); err != nil {
			fail(ctx, summary, resourceNBD, fmt.Errorf("failed to disconnect nbd%d: %w", device, err))

			continue
		}

		reclaim(ctx, summary, resourceNBD)
	}
}

func discoverNetworkSlots(ctx context.Context, netnsDir string, summary *Summary) []int {
	slots, err := network.ListSlotNamespaces(netnsDir)
	if err != nil {
		fail(ctx, summary, resourceNetwork, err)

		return nil
	}

	return slots
}

func reclaimNetworks(ctx context.Context, config Config, slotSet map[int]struct{}, summary *Summary) {
	slots := make([]int, 0, len(slotSet))
	for slot := range slotSet {
		slots = append(slots, slot)
	}
	slices.Sort(slots)

	for _, idx := range slots {
		slot, err := network.NewSlot(fmt.Sprintf("startup-reclaim-%d", idx), idx, config.NetworkConfig, config.EgressProxy)
		if err != nil {
			fail(ctx, summary, resourceNetwork, err)

			continue
		}

		if err := slot.RemoveNetwork(); err != nil {
			fail(ctx, summary, resourceNetwork, fmt.Errorf("failed to remove network slot %d: %w", idx, err))

			continue
		}

		reclaim(ctx, summary, resourceNetwork)
	}
}

func reclaimCgroups(ctx context.Context, config Config, summary *Summary) {
	if config.CgroupManager == nil {
		fail(ctx, summary, resourceCgroup, errors.New("cgroup manager is nil"))

		return
	}

	names, err := cgroup.ListSandboxCgroups(config.CgroupRoot)
	if err != nil {
		fail(ctx, summary, resourceCgroup, err)

		return
	}

	for _, name := range names {
		if err := config.CgroupManager.Destroy(ctx, name); err != nil {
			fail(ctx, summary, resourceCgroup, fmt.Errorf("failed to remove cgroup %s: %w", name, err))

			continue
		}

		reclaim(ctx, summary, resourceCgroup)
	}
}

func reclaimFiles(ctx context.Context, config Config, summary *Summary) {
	paths, err := matchingFilePaths(config.TempDir, config.StorageConfig.SandboxCacheDir)
	if err != nil {
		fail(ctx, summary, resourceFile, err)

		return
	}

	for _, path := range paths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			fail(ctx, summary, resourceFile, fmt.Errorf("failed to remove %s: %w", path, err))

			continue
		}

		reclaim(ctx, summary, resourceFile)
	}
}

func matchingFilePaths(tempDir, sandboxCacheDir string) ([]string, error) {
	patterns := []string{
		filepath.Join(tempDir, "fc-*.sock"),
		filepath.Join(tempDir, "uffd-*.sock"),
		filepath.Join(tempDir, "fc-metrics-*.fifo"),
	}
	if sandboxCacheDir != "" {
		patterns = append(patterns,
			filepath.Join(sandboxCacheDir, "rootfs-*-*.cow"),
			filepath.Join(sandboxCacheDir, "rootfs-*-*.link"),
		)
	}

	paths := make([]string, 0)
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to glob %s: %w", pattern, err)
		}

		paths = append(paths, matches...)
	}

	slices.Sort(paths)

	return paths, nil
}

func reclaim(ctx context.Context, summary *Summary, resource string) {
	summary.Reclaimed[resource]++
	reclaimedCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("resource_type", resource)))
}

func fail(ctx context.Context, summary *Summary, resource string, err error) {
	summary.Failed[resource]++
	failedCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("resource_type", resource)))
	logger.L().Warn(ctx, "startup resource reclaim failed", zap.String("resource_type", resource), zap.Error(err))
}
