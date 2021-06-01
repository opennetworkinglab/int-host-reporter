package inthostreporter

import (
	"flag"
	log "github.com/sirupsen/logrus"
	"net"
)

const (
	// TODO (tomasz): make it configurable
	rxChannelSize = 100
	rxWorkers     = 2
)

var (
	intCollectorServer = flag.String("collector", "", "Address (IP:Port) of the INT collector server.")
)

type ReportHandler struct {
	// thread-safe
	udpConn         *net.UDPConn

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
	if *intCollectorServer == "" {
		log.Fatal("The address of the INT collector is not provided.")
	}
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
			"SrcAddr": pktMd.SrcAddr,
			"DstAddr": pktMd.DstAddr,
			"IPProtocol": pktMd.Protocol,
			"SrcPort": pktMd.SrcPort,
			"DstPort": pktMd.DstPort,
			"Encapsulation": pktMd.EncapMode,
		}).Debugf("RX worker %d parsed data plane event.", id)


		// FIXME: only a stub to be used in future
		n, err := rh.udpConn.Write([]byte{0xff, 0xff})
		if err != nil {
			log.Errorf("failed to sent UDP packet: %v", err)
			continue
		}
		log.Tracef("RX worker %d sent %d bytes to %v", id, n, rh.udpConn.RemoteAddr())
	}
}

// TODO: implement
func (rh *ReportHandler) buildINTReport(pktMd PacketMetadata) ([]byte, error) {
	return []byte{}, nil
}
