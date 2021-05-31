# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-1.0

FROM golang:1.15 as builder

WORKDIR /go/src/app
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

FROM bitnami/minideb:buster
COPY --from=builder /go/bin/int-host-reporter /usr/local/bin

CMD ["int-host-reporter"]