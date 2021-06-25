package watchlist

import (
	"github.com/opennetworkinglab/int-host-reporter/pkg/dataplane"
	"net"
)

type INTWatchlistRule struct {
	// matchFields contains a subset of 5-tuple fields we are matching on
	matchFields map[string]interface{}

	priority uint8
	//protocol uint8
	//srcAddr  net.IP
	//dstAddr  net.IP
	// TODO: currently we don't match on L4 ports
	//srcPort  uint16
	//dstPort  uint16
}

type INTWatchlist struct {
	rules []INTWatchlistRule
}

func NewINTWatchlist() *INTWatchlist {
	w := &INTWatchlist{}
	w.rules = make([]INTWatchlistRule, 0)
	return w
}

func (w *INTWatchlist) InsertRule(rule INTWatchlistRule) {
	// TODO: potential data race if we will enable runtime changes to the watchlist
	w.rules = append(w.rules, rule)
}

func (w *INTWatchlist) Classify(pktMd *dataplane.PacketMetadata) bool {
	// we use very naive approach (linear search); should be optimized in future
	for _, rule := range w.rules {
		// "protocol" should always exist in match fields map
		if rule.matchFields["protocol"].(uint8) != pktMd.Protocol {
			return false
		}

		if srcAddr, ok := rule.matchFields["src-addr"]; ok {
			saddr := srcAddr.(*net.IPNet)
			if !saddr.Contains(pktMd.SrcAddr) {
				return false
			}
		}

		if dstAddr, ok := rule.matchFields["dst-addr"]; ok {
			daddr := dstAddr.(*net.IPNet)
			if !daddr.Contains(pktMd.DstAddr) {
				return false
			}
		}

		// if at least one matching rule is found, we accept a packet to be reported
		return true
	}

	return false
}
