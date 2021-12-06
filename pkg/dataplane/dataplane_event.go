// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"net"
)

type DatapathReportType uint8

// DataPlaneReportSize
// IMPORTANT!
// Keep in sync with DatapathReport.
const (
	DataPlaneReportSize = 40
)

// IMPORTANT!
// Keep in sync with data plane.
const (
	TraceReport DatapathReportType = 1
	DropReport  DatapathReportType = 2
)

var (
	LayerTypeDataPlaneReport = gopacket.RegisterLayerType(1000, gopacket.LayerTypeMetadata{
		Name:    "DatapathReport",
		Decoder: gopacket.DecodeFunc(decodeDataPlaneReport),
	})
)

type Event struct {
	Data []byte
	CPU  int
}

// DatapathReport
// IMPORTANT!
// This struct must be kept in sync with 'struct dp_event` from bpf-gpl/fib.h (calico-felix).
type DatapathReport struct {
	layers.BaseLayer
	Type                  DatapathReportType
	Reason                uint8
	PreNATSourceIP        net.IP
	PreNATDestinationIP   net.IP
	PreNATSourcePort      uint16
	PreNATDestinationPort uint16
	IngressPort           uint32
	EgressPort            uint32
	IngressTimestamp      uint64
	EgressTimestamp       uint64
}

func (dpr *DatapathReport) String() string {
	return fmt.Sprintf("DatapathReport(type=%d, reason=%d, "+
		"PreNATSourceIP=%s, "+
		"PreNATDestinationIP=%s, "+
		"PreNATSourcePort=%d, "+
		"PreNATDestinationPort=%d, "+
		"IngressPort=%d, "+
		"EgressPort=%d, "+
		"IngressTimestamp=%v, "+
		"EgressTimeStamp=%v)",
		dpr.Type, dpr.Reason, dpr.PreNATSourceIP.String(),
		dpr.PreNATDestinationIP.String(), dpr.PreNATSourcePort,
		dpr.PreNATDestinationPort, dpr.IngressPort, dpr.EgressPort,
		dpr.IngressTimestamp, dpr.EgressTimestamp)
}

func (dpr *DatapathReport) LayerType() gopacket.LayerType {
	return LayerTypeDataPlaneReport
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (dpr *DatapathReport) CanDecode() gopacket.LayerClass {
	return LayerTypeDataPlaneReport
}

func (dpr *DatapathReport) NextLayerType() gopacket.LayerType {
	return layers.LayerTypeEthernet
}

func (dpr *DatapathReport) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < DataPlaneReportSize {
		return fmt.Errorf("invalid data plane report. Length %d less than %d",
			len(data), DataPlaneReportSize)
	}
	dpr.Type = DatapathReportType(data[0])
	dpr.Reason = uint8(data[1])
	// 2 bytes of padding
	srcIPv4 := binary.LittleEndian.Uint32(data[4:8])
	dpr.PreNATSourceIP = make(net.IP, 4)
	binary.LittleEndian.PutUint32(dpr.PreNATSourceIP, srcIPv4)
	dstIPv4 := binary.LittleEndian.Uint32(data[8:12])
	dpr.PreNATDestinationIP = make(net.IP, 4)
	binary.LittleEndian.PutUint32(dpr.PreNATDestinationIP, dstIPv4)
	dpr.PreNATSourcePort = binary.BigEndian.Uint16(data[12:14])
	dpr.PreNATDestinationPort = binary.BigEndian.Uint16(data[14:16])
	dpr.IngressPort = binary.LittleEndian.Uint32(data[16:20])
	dpr.EgressPort = binary.LittleEndian.Uint32(data[20:24])
	dpr.IngressTimestamp = binary.LittleEndian.Uint64(data[24:32])
	dpr.EgressTimestamp = binary.LittleEndian.Uint64(data[32:40])

	dpr.BaseLayer = layers.BaseLayer{Contents: data}
	dpr.Contents = data[:DataPlaneReportSize]
	dpr.Payload = data[DataPlaneReportSize:]
	return nil
}

func decodeDataPlaneReport(data []byte, p gopacket.PacketBuilder) error {
	dpr := &DatapathReport{}
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
	DataPlaneReport *DatapathReport
	EncapMode       string
	DstAddr         net.IP
	SrcAddr         net.IP
	Protocol        uint8
	DstPort         uint16
	SrcPort         uint16

	MatchedPostNAT bool

	// raw data of the data plane packet. DataPlaneReport is excluded.
	RawData []byte

	// IP layer
	IPLayer *layers.IPv4
}

func (dpe Event) Parse() *PacketMetadata {
	pktMd := &PacketMetadata{
		EncapMode:      "none",
		MatchedPostNAT: false,
	}
	pktMd.RawData = dpe.Data[DataPlaneReportSize:]
	parsedPacket := gopacket.NewPacket(dpe.Data, LayerTypeDataPlaneReport, gopacket.Default)
	log.Trace(parsedPacket.Dump())
	if dataPlaneReportLayer := parsedPacket.Layer(LayerTypeDataPlaneReport); dataPlaneReportLayer != nil {
		pktMd.DataPlaneReport = dataPlaneReportLayer.(*DatapathReport)
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

	// FIXME: commented out at least for now; as it's not decided yet whether to report pre- or post-NAT'ed tuple to INT collector
	//if pktMd.DatapathReport.PreNATDestinationPort != 0 && !pktMd.DatapathReport.PreNATDestinationIP.IsUnspecified() {
	//	pktMd.DstPort = pktMd.DatapathReport.PreNATDestinationPort
	//	copy(pktMd.DstAddr, pktMd.DatapathReport.PreNATDestinationIP)
	//}

	return pktMd
}
