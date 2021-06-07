package inthostreporter

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"

	log "github.com/sirupsen/logrus"
	"net"
	"strconv"
)

const (
	// TODO (tomasz): make it configurable
	rxChannelSize = 100
	rxWorkers     = 1

	// DummyHopLatency
	// FIXME: PoC-only: we use DummyHopLatency to provide dummy hop latency for the INT collector.
	//  EgressTimestamp should be used to calculate hop latency.
	DummyHopLatency = 10000
)

var (
	intCollectorServer = flag.String("collector", "", "Address (IP:Port) of the INT collector server.")
	// FIXME: we provide Switch ID as a command line argument for now; it should be probably configured via ConfigMap.
	intSwitchID = flag.String("switch-id", "", "Switch ID used by INT Host Reporter to identify the end host")
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

func (rh *ReportHandler) Start() error {
	// TODO: use github.com/jessevdk/go-flags to configure mandatory flags.
	if *intCollectorServer == "" || *intSwitchID == "" {
		log.Fatal("The required flags are not provided")
	}

	switchID, err := strconv.ParseUint(*intSwitchID, 10, 32)
	if err != nil {
		log.Fatal("The 'switch-id' parameter has incorrect format. Use unsigned integer.")
	}
	rh.switchID = uint32(switchID)

	remoteAddr, err := net.ResolveUDPAddr("udp", *intCollectorServer)
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

		data, err := rh.buildINTReport(pktMd)
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

// TODO: we should probably move it to a separate file
func (rh *ReportHandler) buildINTFlowReport(pktMd *PacketMetadata) ([]byte, error) {
	fixedReport := INTReportFixedHeader{
		Version:                   0,
		NProto:                    NProtoTelemetrySwitchLocal,
		Dropped:                   false,
		CongestedQueueAssociation: false,
		TrackedFlowAssociation:    true,
		HwID:                      99, // FIXME: dummy value
		SeqNo:                     0,  // FIXME: calculate sequence number
		IngressTimestamp:          uint32(pktMd.DataPlaneReport.IngressTimestamp),
	}

	commonHeader := INTCommonReportHeader{
		SwitchID:    rh.switchID,
		IngressPort: uint16(pktMd.DataPlaneReport.IngressPort),
		EgressPort:  uint16(pktMd.DataPlaneReport.EgressPort),
		QueueID:     0,
	}

	localReport := INTLocalReportHeader{
		INTCommonReportHeader: commonHeader,
		QueueOccupancy:        0,
		EgressTimestamp:       uint32(pktMd.DataPlaneReport.IngressTimestamp) + DummyHopLatency,
	}
	payload := gopacket.Payload(pktMd.DataPlaneReport.LayerPayload())

	log.WithFields(log.Fields{
		"flow-report": localReport,
		"payload":     payload,
	}).Debug("INT Flow Report built")

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	err := gopacket.SerializeLayers(buf, opts,
		&fixedReport,
		&localReport,
		payload)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to serialize INT Flow Report: %v", err)
	}

	return buf.Bytes(), nil
}

func (rh *ReportHandler) buildINTReport(pktMd *PacketMetadata) (data []byte, err error) {
	switch pktMd.DataPlaneReport.Type {
	case TraceReport:
		data, err = rh.buildINTFlowReport(pktMd)
	// TODO: handle drop reports
	//  case DropReport:
	default:
		return []byte{}, fmt.Errorf("unknown report type")
	}

	return data, err
}
