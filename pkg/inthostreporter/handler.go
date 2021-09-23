// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-1.0

package inthostreporter

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/opennetworkinglab/int-host-reporter/pkg/dataplane"
	"github.com/opennetworkinglab/int-host-reporter/pkg/packet"
	"github.com/opennetworkinglab/int-host-reporter/pkg/watchlist"
	log "github.com/sirupsen/logrus"
	"math"
	"net"
	"strconv"
)

const (
	// TODO (tomasz): make it configurable
	rxChannelSize = 100
	rxWorkers     = 2
)

var (
	INTCollectorServer = flag.String("collector", "", "Address (IP:Port) of the INT collector server.")
	// FIXME: we provide Switch ID as a command line argument for now; it should be probably configured via ConfigMap.
	INTSwitchID = flag.String("switch-id", "", "Switch ID used by INT Host Reporter to identify the end host")

	DataInterface = flag.String("data-interface", "", "")
)

type ReportHandler struct {
	switchID uint32

	// thread-safe
	udpConn *net.UDPConn

	watchlist          []watchlist.INTWatchlistRule
	reportsChannel     chan dataplane.PacketMetadata
	dataPlaneInterface *dataplane.DataPlaneInterface
}

func NewReportHandler(dpi *dataplane.DataPlaneInterface) *ReportHandler {
	rh := &ReportHandler{}
	rh.dataPlaneInterface = dpi
	rh.reportsChannel = make(chan dataplane.PacketMetadata, rxChannelSize)
	return rh
}

func (rh *ReportHandler) SetINTWatchlist(watchlist []watchlist.INTWatchlistRule) {
	rh.watchlist = watchlist
}

func getSwitchID() (uint32, error) {
	swID, err := strconv.ParseUint(*INTSwitchID, 10, 32)
	if err == nil {
		return uint32(swID), nil
	}

	// try IP format
	ip := net.ParseIP(*INTSwitchID).To4()
	if ip != nil {
		return binary.BigEndian.Uint32(ip), nil
	}

	return 0, fmt.Errorf("unsupported format of switch ID")
}

func (rh *ReportHandler) Start() error {
	// TODO: use github.com/jessevdk/go-flags to configure mandatory flags.
	if *INTCollectorServer == "" || *INTSwitchID == "" {
		log.Fatal("The required flags are not provided")
	}

	switchID, err := getSwitchID()
	if err != nil {
		log.Fatalf("Failed to start: %v", err)
	}
	rh.switchID = switchID
	log.Debugf("INT Host Reporter will use switch ID = %v", rh.switchID)

	remoteAddr, err := net.ResolveUDPAddr("udp", *INTCollectorServer)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", &net.UDPAddr{}, remoteAddr)
	if err != nil {
		return err
	}
	rh.udpConn = conn

	rh.dataPlaneInterface.SetEventChannel(rh.reportsChannel)
	for i := 0; i < rxWorkers; i++ {
		log.Debugf("Starting RX worker %d listening for data plane events.", i)
		go rh.rxFn(i)
	}

	log.Debug("All RX workers started.")
	return nil
}

func (rh *ReportHandler) applyWatchlist(pktMd dataplane.PacketMetadata) bool {
	packetLog := log.Fields{
		"protocol" : pktMd.Protocol,
		"src-addr" : pktMd.SrcAddr.String(),
		"dst-addr" : pktMd.DstAddr.String(),
		"src-port" : pktMd.SrcPort,
		"dst-port" : pktMd.DstPort,
	}

	log.WithFields(packetLog).Debug("Applying INT watchlist for packet.")

	// apply for post-NAT 5-tuple
	for _, rule := range rh.watchlist {
		if pktMd.Protocol == rule.GetProtocol() &&
			rule.GetSrcAddr().Contains(pktMd.SrcAddr) &&
			rule.GetDstAddr().Contains(pktMd.DstAddr) {
				log.WithFields(log.Fields{
					"packet": packetLog,
					"rule-matched": rule.String(),
				}).Debug("Match for post-NAT tuple found")
				return true
			}
	}

	// apply for pre-NAT 5-tuple
	for _, rule := range rh.watchlist {
		if pktMd.Protocol == rule.GetProtocol() &&
			rule.GetSrcAddr().Contains(pktMd.DataPlaneReport.PreNATSourceIP) &&
			rule.GetDstAddr().Contains(pktMd.DataPlaneReport.PreNATDestinationIP) {
			log.WithFields(log.Fields{
				"packet": packetLog,
				"rule-matched": rule.String(),
			}).Debug("Match for pre-NAT tuple found")
			return true
		}
	}

	log.WithFields(packetLog).Debug("No INT watchlist match found for packet.")

	return false
}

func (rh *ReportHandler) rxFn(id int) {
	hwID := uint8(id)
	seqNo := uint32(0)
	for pktMd := range rh.reportsChannel {
		if !rh.applyWatchlist(pktMd) {
			continue
		}

		fields := log.WithFields(log.Fields{
			"DataPlaneReport": pktMd.DataPlaneReport,
			"SrcAddr":         pktMd.SrcAddr,
			"DstAddr":         pktMd.DstAddr,
			"IPProtocol":      pktMd.Protocol,
			"SrcPort":         pktMd.SrcPort,
			"DstPort":         pktMd.DstPort,
			"Encapsulation":   pktMd.EncapMode,
		})
		fields.Debugf("RX worker %d parsed data plane event.", id)

		if seqNo >= math.MaxUint32 {
			seqNo = 0
		} else {
			seqNo++
		}

		data, err := packet.BuildINTReport(pktMd, rh.switchID, hwID, seqNo)
		if err != nil {
			fields.Errorf("failed to build INT report: %v", err)
			continue
		}

		n, err := rh.udpConn.Write(data)
		if err != nil {
			fields.Errorf("failed to sent UDP packet: %v", err)
			continue
		}
		fields.Tracef("RX worker %d sent %d bytes to %v", id, n, rh.udpConn.RemoteAddr())
	}
}