# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

# Flags:
# -DBMD_MODE=<BMD_MODE_SKB_PTR | BMD_MODE_SKB_CB | BMD_MODE_SKB_FLOW_HASH>, default=BMD_MODE_SKB_CB
clang-10 -O2 -emit-llvm -g -c bpf/int-datapath.c -o - | llc-10 -march=bpf -filetype=obj -o /opt/out.o