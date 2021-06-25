package common

const (
	// DummyHopLatency
	// FIXME: PoC-only: we use DummyHopLatency to provide dummy hop latency for the INT collector.
	//  EgressTimestamp should be used to calculate hop latency.
	DummyHopLatency = 500

	// CalicoPerfEventArray is the default name of BPF perf event array used by Calico to generate data plane events.
	CalicoPerfEventArray = "cali_report"

	// DefaultMapRoot is the default path where BPFFS should be mounted
	DefaultMapRoot = "/sys/fs/bpf"

	// DefaultMapPrefix is the default prefix for all BPF maps.
	DefaultMapPrefix = "tc/globals"
)
