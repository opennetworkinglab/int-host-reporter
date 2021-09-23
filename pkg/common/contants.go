// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-1.0

package common

const (
	INTWatchlistProtoSrcAddrMap = "WATCHLIST_PROTO_SRCADDR_MAP"

	INTWatchlistDstAddrMap = "WATCHLIST_DSTADDR_MAP"

	INTEventsMap = "INT_EVENTS_MAP"

	// DefaultMapRoot is the default path where BPFFS should be mounted
	DefaultMapRoot = "/sys/fs/bpf"

	// DefaultMapPrefix is the default prefix for all BPF maps.
	DefaultMapPrefix = "tc/globals"
)
