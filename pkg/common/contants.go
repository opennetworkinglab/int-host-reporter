package common

const (
	// CalicoPerfEventArray is the default name of BPF perf event array used by Calico to generate data plane events.
	CalicoPerfEventArray = "cali_report"

	CalicoWatchlistMap = "cali_watchlist2"

	// DefaultMapRoot is the default path where BPFFS should be mounted
	DefaultMapRoot = "/sys/fs/bpf"

	// DefaultMapPrefix is the default prefix for all BPF maps.
	DefaultMapPrefix = "tc/globals"
)
