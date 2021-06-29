package watchlist

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"net"
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
	protocol uint8
	srcAddr  net.IP
	dstAddr  net.IP
	// TODO: currently we don't match on L4 ports
	//srcPort  uint16
	//dstPort  uint16
}

func (rule INTWatchlistRule) String() string {
	return fmt.Sprintf("rule=[protocol=%v, srcAddr=%v, dstAddr=%v]", rule.protocol,
		rule.srcAddr, rule.dstAddr)
}

func (rule INTWatchlistRule) GetProtocol() uint8 {
	return rule.protocol
}

func (rule INTWatchlistRule) GetSrcAddr() net.IP {
	return rule.srcAddr
}

func (rule INTWatchlistRule) GetDstAddr() net.IP {
	return rule.dstAddr
}

type INTWatchlist struct {
	rules []INTWatchlistRule
}

func NewINTWatchlistRule() INTWatchlistRule {
	return INTWatchlistRule{}
}

func NewINTWatchlist() *INTWatchlist {
	w := &INTWatchlist{}
	w.rules = make([]INTWatchlistRule, 0)
	return w
}

func FillFromFile(w *INTWatchlist, filename string) error {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	watchlist := &WatchlistYAML{}
	err = yaml.Unmarshal(buf, watchlist)
	if err != nil {
		return fmt.Errorf("in file %q: %v", filename, err)
	}

	for _, r := range watchlist.Rules {
		rule, err := parseINTWatchlistRule(r)
		if err != nil {
			return err
		}
		w.InsertRule(rule)
	}
	return nil
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
	r.protocol = proto
	if rule.SrcAddr != "" {
		ip := net.ParseIP(rule.SrcAddr)
		if ip == nil {
			return INTWatchlistRule{}, fmt.Errorf("failed to parse SrcAddr")
		}
		r.srcAddr = ip
	}
	if rule.DstAddr != "" {
		ip := net.ParseIP(rule.DstAddr)
		if ip == nil {
			return INTWatchlistRule{}, fmt.Errorf("failed to parse DstAddr")
		}
		r.dstAddr = ip
	}

	return r, nil
}

func (w *INTWatchlist) GetRules() []INTWatchlistRule {
	return w.rules
}

func (w *INTWatchlist) InsertRule(rule INTWatchlistRule) {
	// TODO: potential data race if we will enable runtime changes to the watchlist
	w.rules = append(w.rules, rule)
}
