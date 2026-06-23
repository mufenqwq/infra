//go:build linux

package sandbox

import (
	"debug/elf"
	"sort"
	"sync"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/metadata"
)

// The deterministic set every resumed sandbox needs: the kernel image
// (text/rodata/data, run by any operation) plus the low 1 MiB of boot
// structures. For guest RAM ≤ 3 GiB the memfile offset equals the GPA, and
// Firecracker loads each vmlinux ELF PT_LOAD at its p_paddr, so those offsets
// are read straight from the ELF program headers.

const lowMemBytes int64 = 1 << 20

// maxKernelPaddr drops PT_LOAD entries whose p_paddr is implausibly high (a
// vmlinux carrying the kernel virtual address instead of the physical load).
const maxKernelPaddr int64 = 1 << 30

type offsetRange struct{ start, end int64 }

var (
	kernelRangesMu    sync.Mutex
	kernelRangesCache = map[string][]offsetRange{}
)

// resumePrefaultMapping builds a prefetch mapping covering the kernel image +
// low 1 MiB (kernelImage) and/or the first floorMiB of guest RAM. Returns nil
// if neither yields anything.
func resumePrefaultMapping(kernelPath string, blockSize int64, kernelImage bool, floorMiB int) *metadata.MemoryPrefetchMapping {
	if blockSize <= 0 {
		return nil
	}

	var ranges []offsetRange
	if kernelImage {
		ranges = append(ranges, offsetRange{start: 0, end: lowMemBytes})
		ranges = append(ranges, kernelImageRanges(kernelPath)...)
	}
	if floorMiB > 0 {
		ranges = append(ranges, offsetRange{start: 0, end: int64(floorMiB) << 20})
	}

	indices := blockIndicesForRanges(ranges, blockSize)
	if len(indices) == 0 {
		return nil
	}

	return &metadata.MemoryPrefetchMapping{Indices: indices, BlockSize: blockSize}
}

// mergePrefetchMappings unions static (fetched first) and empirical indices. On
// a block-size mismatch the empirical mapping is trusted.
func mergePrefetchMappings(static, empirical *metadata.MemoryPrefetchMapping) *metadata.MemoryPrefetchMapping {
	switch {
	case static == nil:
		return empirical
	case empirical == nil:
		return static
	case static.BlockSize != empirical.BlockSize:
		return empirical
	}

	seen := make(map[uint64]struct{}, len(static.Indices)+len(empirical.Indices))
	indices := make([]uint64, 0, len(static.Indices)+len(empirical.Indices))
	for _, src := range [][]uint64{static.Indices, empirical.Indices} {
		for _, idx := range src {
			if _, ok := seen[idx]; ok {
				continue
			}
			seen[idx] = struct{}{}
			indices = append(indices, idx)
		}
	}

	return &metadata.MemoryPrefetchMapping{Indices: indices, BlockSize: static.BlockSize}
}

// kernelImageRanges returns the kernel image extents from the vmlinux ELF,
// cached per path (nil is cached too, so a non-ELF kernel is parsed once).
func kernelImageRanges(path string) []offsetRange {
	kernelRangesMu.Lock()
	defer kernelRangesMu.Unlock()

	if r, ok := kernelRangesCache[path]; ok {
		return r
	}

	r := parseKernelImageRanges(path)
	kernelRangesCache[path] = r

	return r
}

func parseKernelImageRanges(path string) []offsetRange {
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var ranges []offsetRange
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Memsz == 0 {
			continue
		}

		start := int64(p.Paddr)
		end := start + int64(p.Memsz)
		if start < 0 || end <= start || start >= maxKernelPaddr {
			continue
		}

		ranges = append(ranges, offsetRange{start: start, end: end})
	}

	return ranges
}

// blockIndicesForRanges returns the sorted, de-duplicated block indices covering
// the given byte ranges.
func blockIndicesForRanges(ranges []offsetRange, blockSize int64) []uint64 {
	if blockSize <= 0 {
		return nil
	}

	seen := make(map[uint64]struct{})
	for _, r := range ranges {
		if r.end <= r.start {
			continue
		}
		for b := r.start / blockSize; b <= (r.end-1)/blockSize; b++ {
			seen[uint64(b)] = struct{}{}
		}
	}

	if len(seen) == 0 {
		return nil
	}

	indices := make([]uint64, 0, len(seen))
	for b := range seen {
		indices = append(indices, b)
	}
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })

	return indices
}
