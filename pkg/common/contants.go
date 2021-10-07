// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package common

type CNIType uint32

const (
	CNITypeCilium = iota
	CNITypeCalicoEBPF
	CNITypeCalicoIPTables
)

const (
	INTWatchlistProtoSrcAddrMap = "WATCHLIST_PROTO_SRCADDR_MAP"

	INTWatchlistDstAddrMap = "WATCHLIST_DSTADDR_MAP"

	INTEventsMap = "INT_EVENTS_MAP"

	INTSharedMap = "SHARED_MAP"

	// DefaultMapRoot is the default path where BPFFS should be mounted
	DefaultMapRoot = "/sys/fs/bpf"

	// DefaultMapPrefix is the default prefix for all BPF maps.
	DefaultMapPrefix = "tc/globals"
)

const (
	// Common drop reasons
	DropReasonUnknown = 0
	DropReasonIPVersionInvalid = 25
	DropReasonIPTTLZero = 26
	DropReasonIPIHLInvalid = 30
	DropReasonIPInvalidChecksum = 31
	DropReasonRoutingMiss = 29
	DropReasonPortVLANMappingMiss = 55
	DropReasonTrafficManager = 71
	DropReasonACLDeny = 80
	DropReasonBridginMiss = 89

	// Calico-specific drop reasons
	DropReasonEncapFail = 180
	DropReasonDecapFail = 181
	DropReasonChecksumFail = 182
	DropReasonIPOptions = 183
	DropReasonUnauthSource = 184
)
