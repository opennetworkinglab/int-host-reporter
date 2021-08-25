package dataplane

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"net"
)

type DataPlaneReportType uint8

// DataPlaneReportSize
// IMPORTANT!
// Keep in sync with DataPlaneReport.
const (
	DataPlaneReportSize = 40
)

// IMPORTANT!
// Keep in sync with data plane.
const (
	TraceReport DataPlaneReportType = 1
	DropReport  DataPlaneReportType = 2
)

var (
	LayerTypeDataPlaneReport = gopacket.RegisterLayerType(1000, gopacket.LayerTypeMetadata{
		Name:    "DataPlaneReport",
		Decoder: gopacket.DecodeFunc(decodeDataPlaneReport),
	})
)

type Event struct {
	Data []byte
	CPU  int
}

// DataPlaneReport
// IMPORTANT!
// This struct must be kept in sync with 'struct dp_event` from bpf-gpl/fib.h (calico-felix).
type DataPlaneReport struct {
	layers.BaseLayer
	Type                  DataPlaneReportType
	Reason                uint8
	PreNATDestinationIP   net.IP
	PreNATDestinationPort uint16
	IngressPort           uint32
	EgressPort            uint32
	IngressTimestamp      uint64
	EgressTimestamp       uint64
}

func (dpr *DataPlaneReport) String() string {
	return fmt.Sprintf("DataPlaneReport(type=%d, reason=%d, "+
		"PreNATDestinationIP=%s, "+
		"PreNATDestinationPort=%d, "+
		"IngressPort=%d, "+
		"EgressPort=%d, "+
		"IngressTimestamp=%v, "+
		"EgressTimeStamp=%v)",
		dpr.Type, dpr.Reason, dpr.PreNATDestinationIP.String(),
		dpr.PreNATDestinationPort, dpr.IngressPort, dpr.EgressPort,
		dpr.IngressTimestamp, dpr.EgressTimestamp)
}

func (dpr *DataPlaneReport) LayerType() gopacket.LayerType {
	return LayerTypeDataPlaneReport
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (dpr *DataPlaneReport) CanDecode() gopacket.LayerClass {
	return LayerTypeDataPlaneReport
}

func (dpr *DataPlaneReport) NextLayerType() gopacket.LayerType {
	return layers.LayerTypeEthernet
}

func (dpr *DataPlaneReport) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < DataPlaneReportSize {
		return fmt.Errorf("invalid data plane report. Length %d less than %d",
			len(data), DataPlaneReportSize)
	}
	dpr.Type = DataPlaneReportType(data[0])
	dpr.Reason = uint8(data[1])
	// 2 bytes of padding
	ipv4 := binary.LittleEndian.Uint32(data[4:8])
	dpr.PreNATDestinationIP = make(net.IP, 4)
	binary.LittleEndian.PutUint32(dpr.PreNATDestinationIP, ipv4)
	dpr.PreNATDestinationPort = binary.BigEndian.Uint16(data[8:12])
	dpr.IngressPort = binary.LittleEndian.Uint32(data[12:16])
	dpr.EgressPort = binary.LittleEndian.Uint32(data[16:20])
	// 4 bytes of padding
	dpr.IngressTimestamp = binary.LittleEndian.Uint64(data[24:32])
	dpr.EgressTimestamp = binary.LittleEndian.Uint64(data[32:40])

	dpr.BaseLayer = layers.BaseLayer{Contents: data}
	dpr.Contents = data[:DataPlaneReportSize]
	dpr.Payload = data[DataPlaneReportSize:]
	return nil
}

func decodeDataPlaneReport(data []byte, p gopacket.PacketBuilder) error {
	dpr := &DataPlaneReport{}
	err := dpr.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(dpr)
	next := dpr.NextLayerType()
	if next == gopacket.LayerTypeZero {
		return nil
	}
	return p.NextDecoder(next)
}

type PacketMetadata struct {
	DataPlaneReport *DataPlaneReport
	EncapMode		string
	DstAddr 		net.IP
	SrcAddr			net.IP
	Protocol 		uint8
	DstPort			uint16
	SrcPort			uint16

	// raw data of the data plane packet. DataPlaneReport is excluded.
	RawData []byte

	// IP layer
	IPLayer			*layers.IPv4
}

func (dpe Event) Parse() *PacketMetadata {
	pktMd := &PacketMetadata{
		EncapMode: "none",
	}
	pktMd.RawData = dpe.Data[DataPlaneReportSize:]
	parsedPacket := gopacket.NewPacket(dpe.Data, LayerTypeDataPlaneReport, gopacket.Default)
	log.Trace(parsedPacket.Dump())
	if dataPlaneReportLayer := parsedPacket.Layer(LayerTypeDataPlaneReport); dataPlaneReportLayer != nil {
		pktMd.DataPlaneReport = dataPlaneReportLayer.(*DataPlaneReport)
		if vxlanLayer := parsedPacket.Layer(layers.LayerTypeVXLAN); vxlanLayer != nil {
			// TODO: we support only VXLAN in the PoC
			pktMd.EncapMode = "vxlan"
			// if VXLAN exists it means we received reports from the "relay" node and we need to look deeper.
			parsedPacket = gopacket.NewPacket(vxlanLayer.LayerPayload(), layers.LayerTypeEthernet, gopacket.Default)
		}
		if ipv4Layer := parsedPacket.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ipv4, _ := ipv4Layer.(*layers.IPv4)
			pktMd.IPLayer = ipv4
			pktMd.DstAddr = ipv4.DstIP.To4()
			pktMd.SrcAddr = ipv4.SrcIP.To4()
			pktMd.Protocol = uint8(ipv4.Protocol)
			if l4Layer := parsedPacket.Layer(ipv4.NextLayerType()); l4Layer != nil {
				switch ipv4.Protocol {
				case layers.IPProtocolTCP:
					tcp, _ := l4Layer.(*layers.TCP)
					pktMd.SrcPort = uint16(tcp.SrcPort)
					pktMd.DstPort = uint16(tcp.DstPort)
				case layers.IPProtocolUDP:
					udp, _ := l4Layer.(*layers.UDP)
					pktMd.SrcPort = uint16(udp.SrcPort)
					pktMd.DstPort = uint16(udp.DstPort)
				}
			}
		}
	}

	if pktMd.DataPlaneReport.PreNATDestinationPort != 0 && !pktMd.DataPlaneReport.PreNATDestinationIP.IsUnspecified() {
		pktMd.DstPort = pktMd.DataPlaneReport.PreNATDestinationPort
		copy(pktMd.DstAddr, pktMd.DataPlaneReport.PreNATDestinationIP)
	}

	return pktMd
}
