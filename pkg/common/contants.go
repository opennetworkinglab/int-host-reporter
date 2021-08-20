package common

const (
	// CalicoPerfEventArray is the default name of BPF perf event array used by Calico to generate data plane events.
	CalicoPerfEventArray = "cali_report"

	CalicoWatchlistMapProtoSrcAddr = "cali_watchlist_proto_srcaddr"

	CalicoWatchlistMapDstAddr = "cali_watchlist_dstaddr"

	INTEventsMap = "INT_EVENTS_MAP"

	// DefaultMapRoot is the default path where BPFFS should be mounted
	DefaultMapRoot = "/sys/fs/bpf"

	// DefaultMapPrefix is the default prefix for all BPF maps.
	DefaultMapPrefix = "tc/globals"
)
