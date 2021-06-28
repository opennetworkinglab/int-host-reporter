package watchlist

import (
	"fmt"
	"github.com/opennetworkinglab/int-host-reporter/pkg/dataplane"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"net"
	"strings"
)

type WatchlistRuleYAML struct {
	DstAddr  string `yaml:"dst-addr,omitempty"`
	Protocol string `yaml:"protocol"`
	SrcAddr  string `yaml:"src-addr,omitempty"`
	DstPort  string `yaml:"dst-port,omitempty"`
	SrcPort  string `yaml:"src-port"`
}

type WatchlistYAML struct {
	Rules []WatchlistRuleYAML `yaml:"rules"`
}

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

func NewINTWatchlistRule() INTWatchlistRule {
	rule := INTWatchlistRule{}
	rule.matchFields = make(map[string]interface{})
	return rule
}

func NewINTWatchlist() *INTWatchlist {
	w := &INTWatchlist{}
	w.rules = make([]INTWatchlistRule, 0)
	return w
}

func ReadFromFile(filename string) (*INTWatchlist, error) {
	w := NewINTWatchlist()

	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	watchlist := &WatchlistYAML{}
	err = yaml.Unmarshal(buf, watchlist)
	if err != nil {
		return nil, fmt.Errorf("in file %q: %v", filename, err)
	}

	for _, r := range watchlist.Rules {
		rule, err := parseINTWatchlistRule(r)
		if err != nil {
			return nil, err
		}
		w.InsertRule(rule)
	}
	return w, nil
}

func protocolTextToDecimal(proto string) (uint8, error) {
	if proto == "" {
		return 0, fmt.Errorf("protocol field is mandatory, but not provided")
	}

	switch proto {
	case "UDP":
		return 17, nil
	case "TCP":
		return 6, nil
	default:
		return 0, fmt.Errorf("unknown protocol type")
	}
}

func parseINTWatchlistRule(rule WatchlistRuleYAML) (INTWatchlistRule, error) {
	r := NewINTWatchlistRule()
	proto, err := protocolTextToDecimal(rule.Protocol)
	if err != nil {
		return INTWatchlistRule{}, fmt.Errorf("failed to parse Protocol: %v", err)
	}
	r.matchFields["protocol"] = proto
	if rule.SrcAddr != "" {
		_, ip, err := parseIPv4Addr(rule.SrcAddr)
		if err != nil {
			return INTWatchlistRule{}, fmt.Errorf("failed to parse SrcAddr: %v", err)
		}
		r.matchFields["src-addr"] = ip
	}
	if rule.DstAddr != "" {
		_, ip, err := parseIPv4Addr(rule.DstAddr)
		if err != nil {
			return INTWatchlistRule{}, fmt.Errorf("failed to parse DstAddr: %v", err)
		}
		r.matchFields["dst-addr"] = ip
	}

	return r, nil
}

func parseL4Port(port string) ([]string, error) {
	s := strings.Split(port, ":")
	if len(s) != 2 {
		return []string{}, fmt.Errorf("wrong format of port field")
	}
	return s, nil
}

func parseIPv4Addr(addr string) (net.IP, *net.IPNet, error) {
	return net.ParseCIDR(addr)
}

func (w *INTWatchlist) Dump() {
	for idx, rule := range w.rules {
		log.Debugf("#%v: protocol=%v, srcAddr=%v, dstAddr=%v", idx, rule.matchFields["protocol"],
			rule.matchFields["src-addr"], rule.matchFields["dst-addr"])
	}
}

func (w *INTWatchlist) InsertRule(rule INTWatchlistRule) {
	// TODO: potential data race if we will enable runtime changes to the watchlist
	w.rules = append(w.rules, rule)
}

func (w *INTWatchlist) Classify(pktMd *dataplane.PacketMetadata) bool {
	// we use very naive approach (linear search); should be optimized in future
	for idx, rule := range w.rules {
		// "protocol" should always exist in match fields map
		if rule.matchFields["protocol"].(uint8) != pktMd.Protocol {
			continue
		}

		if srcAddr, ok := rule.matchFields["src-addr"]; ok {
			saddr := srcAddr.(*net.IPNet)
			if !saddr.Contains(pktMd.SrcAddr) {
				continue
			}
		}

		if dstAddr, ok := rule.matchFields["dst-addr"]; ok {
			daddr := dstAddr.(*net.IPNet)
			if !daddr.Contains(pktMd.DstAddr) {
				continue
			}
		}

		// if at least one matching rule is found, we accept a packet to be reported
		log.WithFields(log.Fields{
			"packet": pktMd,
			"rule": rule.matchFields,
		}).Debugf("Found match for rule #%v", idx)
		return true
	}

	return false
}
