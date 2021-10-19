// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: GPL-2.0-only

/* Bridged metadata modes */
/* BMD_MODE_SKB_CB: use skb->cb to pass random packet identifier */
#define BMD_MODE_SKB_CB 0
/* BMD_MODE_SKB_PTR: use address of skb descriptor as packet identifier */
#define BMD_MODE_SKB_PTR 1
/* BMD_MODE_FLOW_HASH: use flow hash retrieved by bpf_get_hash_recalc() as packet identifier. */
#define BMD_MODE_FLOW_HASH 2

#ifndef BMD_MODE
#define BMD_MODE BMD_MODE_SKB_CB
#endif

#ifndef __NR_CPUS__
#define __NR_CPUS__ 1
#endif