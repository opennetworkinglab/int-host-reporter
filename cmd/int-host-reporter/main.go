// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-1.0

package main

import (
	"flag"
	"github.com/opennetworkinglab/int-host-reporter/pkg/common"
	"github.com/opennetworkinglab/int-host-reporter/pkg/inthostreporter"
	"github.com/opennetworkinglab/int-host-reporter/pkg/watchlist"
	log "github.com/sirupsen/logrus"
)

var (
	watchlistConfiguration = flag.String("watchlist-conf", "", "File with INT watchlist configuration")
	cniInUse = flag.String("cni", "", "Kubernetes CNI used by the cluster (supported CNIs: cilium, calico-ebpf, calico-legacy")
)

func init() {
	flag.StringVar(watchlistConfiguration, "f", "", "")
	flag.StringVar(cniInUse, "c", "", "")
}

func main() {
	flag.Parse()
	log.SetLevel(log.DebugLevel)
	log.WithFields(log.Fields{
		"collector": *inthostreporter.INTCollectorServer,
		"switchID": *inthostreporter.INTSwitchID,
	}).Debug("Starting INT Host Reporter.")

	err := common.ParseCNIType(*cniInUse)
	if err != nil {
		log.Fatalf("failed to start INT Host Reporter: %v", err.Error())
	}

	wlist := watchlist.NewINTWatchlist()
	if *watchlistConfiguration != "" {
		err := watchlist.FillFromFile(wlist, *watchlistConfiguration)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Fatal("Failed to parse the watchlist configuration file..")
		}
	}

	intReporter := inthostreporter.NewIntHostReporter(wlist)

	// Blocking
	err = intReporter.Start()
	if err != nil {
		log.Fatalf("Error while running INT Host Reporter: %v", err)
	}
}