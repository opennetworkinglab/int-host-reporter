// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-1.0

package main

import (
	"flag"
	"github.com/opennetworkinglab/int-host-reporter/pkg/inthostreporter"
	log "github.com/sirupsen/logrus"
)


func main() {
	flag.Parse()
	log.SetLevel(log.DebugLevel)
	log.WithFields(log.Fields{
		"collector": *inthostreporter.INTCollectorServer,
		"switchID": *inthostreporter.INTSwitchID,
	}).Debug("Starting INT Host Reporter.")

	intReporter := inthostreporter.NewIntHostReporter()

	// Blocking
	err := intReporter.Start()
	if err != nil {
		log.Fatalf("Error while running INT Host Reporter: %v", err)
	}
}