package inthostreporter

import (
	"encoding/binary"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"math"
	"net"
	"strconv"
)

const (
	// TODO (tomasz): make it configurable
	rxChannelSize = 100
	rxWorkers     = 2

	// DummyHopLatency
	// FIXME: PoC-only: we use DummyHopLatency to provide dummy hop latency for the INT collector.
	//  EgressTimestamp should be used to calculate hop latency.
	DummyHopLatency = 10000
)

var (
	INTCollectorServer = flag.String("collector", "", "Address (IP:Port) of the INT collector server.")
	// FIXME: we provide Switch ID as a command line argument for now; it should be probably configured via ConfigMap.
	INTSwitchID = flag.String("switch-id", "", "Switch ID used by INT Host Reporter to identify the end host")
)

type ReportHandler struct {
	switchID uint32

	// thread-safe
	udpConn *net.UDPConn

	reportsChannel     chan dataPlaneEvent
	dataPlaneInterface *dataPlaneInterface
}

func NewReportHandler(dpi *dataPlaneInterface) *ReportHandler {
	rh := &ReportHandler{}
	rh.dataPlaneInterface = dpi
	rh.reportsChannel = make(chan dataPlaneEvent, rxChannelSize)
	return rh
}

func getSwitchID() (uint32, error) {
	swID, err := strconv.ParseUint(*INTSwitchID, 10, 32)
	if err == nil {
		return uint32(swID), nil
	}

	// try IP format
	ip := net.ParseIP(*INTSwitchID).To4()
	if ip != nil {
		return binary.LittleEndian.Uint32(ip), nil
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

func (rh *ReportHandler) rxFn(id int) {
	hwID := uint8(id)
	seqNo := uint32(0)
	for event := range rh.reportsChannel {
		pktMd := event.Parse()
		log.WithFields(log.Fields{
			"DataPlaneReport": pktMd.DataPlaneReport,
			"SrcAddr":         pktMd.SrcAddr,
			"DstAddr":         pktMd.DstAddr,
			"IPProtocol":      pktMd.Protocol,
			"SrcPort":         pktMd.SrcPort,
			"DstPort":         pktMd.DstPort,
			"Encapsulation":   pktMd.EncapMode,
		}).Debugf("RX worker %d parsed data plane event.", id)

		if seqNo >= math.MaxUint32 {
			seqNo = 0
		} else {
			seqNo++
		}

		data, err := buildINTReport(pktMd, rh.switchID, hwID, seqNo)
		if err != nil {
			log.Errorf("failed to build INT report: %v", err)
			continue
		}

		n, err := rh.udpConn.Write(data)
		if err != nil {
			log.Errorf("failed to sent UDP packet: %v", err)
			continue
		}
		log.Tracef("RX worker %d sent %d bytes to %v", id, n, rh.udpConn.RemoteAddr())
	}
}