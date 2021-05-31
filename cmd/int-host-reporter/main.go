// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-1.0

package main

import (
	"fmt"
	"github.com/opennetworkinglab/int-host-reporter/pkg/inthostreporter"
	log "github.com/sirupsen/logrus"
)


func main() {
	fmt.Println("hello")
	log.SetLevel(log.DebugLevel)
	log.Debug("hello")

	intReporter := inthostreporter.NewIntHostReporter()
	// Blocking
	err := intReporter.Start()
	if err != nil {
		log.Fatalf("Error while running INT Host Reporter: %v", err)
	}
}