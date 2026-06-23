//go:build linux

package sandbox

import (
	"reflect"
	"testing"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/metadata"
)

func TestBlockIndicesForRanges(t *testing.T) {
	const bs = 4096

	tests := []struct {
		name      string
		ranges    []offsetRange
		blockSize int64
		want      []uint64
	}{
		{"low 1 MiB", []offsetRange{{0, lowMemBytes}}, bs, seq(0, 256)},
		{"partial block rounds both ends", []offsetRange{{bs - 1, bs + 1}}, bs, []uint64{0, 1}},
		{"overlap deduped and sorted", []offsetRange{{2 * bs, 4 * bs}, {0, 1}, {3 * bs, 3*bs + 1}}, bs, []uint64{0, 2, 3}},
		{"hugepage block size", []offsetRange{{0, lowMemBytes}, {16 << 20, (16 << 20) + 1}}, 2 << 20, []uint64{0, 8}},
		{"empty range", []offsetRange{{5, 5}}, bs, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := blockIndicesForRanges(tt.ranges, tt.blockSize); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMergePrefetchMappings(t *testing.T) {
	static := &metadata.MemoryPrefetchMapping{Indices: []uint64{0, 1, 2}, BlockSize: 4096}
	empirical := &metadata.MemoryPrefetchMapping{Indices: []uint64{2, 3, 0, 4}, BlockSize: 4096}

	if got := mergePrefetchMappings(static, nil); got != static {
		t.Fatal("static,nil should return static")
	}
	if got := mergePrefetchMappings(nil, empirical); got != empirical {
		t.Fatal("nil,empirical should return empirical")
	}

	got := mergePrefetchMappings(static, empirical)
	if want := []uint64{0, 1, 2, 3, 4}; !reflect.DeepEqual(got.Indices, want) {
		t.Fatalf("merged indices = %v, want %v", got.Indices, want)
	}

	bad := &metadata.MemoryPrefetchMapping{Indices: []uint64{9}, BlockSize: 2 << 20}
	if got := mergePrefetchMappings(bad, empirical); got != empirical {
		t.Fatal("block-size mismatch should return empirical")
	}
}

func seq(start, end uint64) []uint64 {
	out := make([]uint64, 0, end-start)
	for i := start; i < end; i++ {
		out = append(out, i)
	}
	return out
}
