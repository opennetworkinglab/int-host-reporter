# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

clang -O2 -emit-llvm -g -c bpf/int-datapath.c -o - | llc -march=bpf -filetype=obj -o /opt/out.o