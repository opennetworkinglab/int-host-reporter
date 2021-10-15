# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.15 as builder

WORKDIR /go/src/app
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

FROM ubuntu:20.10
COPY --from=builder /go/src/app .
COPY --from=builder /go/bin/int-host-reporter /usr/local/bin

RUN apt update
RUN apt install -y iproute2 clang-10 libbpf-dev llvm-10
RUN ./scripts/compile-bpf.sh

CMD ["int-host-reporter"]