# SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
#
# SPDX-License-Identifier: LicenseRef-ONF-Member-1.0

fmt:
	@echo
	@echo "===> Formatting Go files <==="
	@gofmt -s -l -w $(GO_FILES)

.golangci-bin:
	@echo "===> Installing Golangci-lint <==="
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $@ v1.41.1

golint: .golangci-bin
	@echo "===> Running golangci (linux) <==="
	@GOOS=linux $(CURDIR)/.golangci-bin/golangci-lint run -c $(CURDIR)/.golangci.yml

build:
	@echo "===> Building int-host-reporter image <==="
	docker build -t opennetworking/int-host-reporter:latest .