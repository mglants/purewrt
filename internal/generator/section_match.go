package generator

import "github.com/purewrt/purewrt/internal/config"

func sectionPortExpr(s config.Section, protocol string) string {
	if s.Action != "proxy" && s.Action != "zapret" {
		return ""
	}
	ports, _ := config.NormalizeDestinationPorts(s.DestinationPorts)
	return nftPortExpr(protocol, "dport", ports)
}

// sectionMatchExpr is used where the action does not already constrain the
// transport. Port restrictions imply TCP/UDP, never arbitrary transport headers.
func sectionMatchExpr(s config.Section) string {
	if s.Action != "proxy" && s.Action != "zapret" {
		return ""
	}
	ports, _ := config.NormalizeDestinationPorts(s.DestinationPorts)
	switch s.MatchProtocol {
	case "tcp", "udp":
		return " meta l4proto " + s.MatchProtocol + nftPortExpr(s.MatchProtocol, "dport", ports)
	case "tcp_udp":
		return " meta l4proto { tcp, udp }" + nftPortExpr("th", "dport", ports)
	default:
		if ports != "" {
			return " meta l4proto { tcp, udp }" + nftPortExpr("th", "dport", ports)
		}
		return ""
	}
}

// The queue and the earlier terminal claim must use precisely the same scope.
func sectionZapretStrategy(s config.Section, zs config.ZapretStrategy) config.ZapretStrategy {
	protocols := []string{}
	if protocolEnabled(zs, "tcp") && s.MatchesProtocol("tcp") {
		if ports, ok := config.IntersectDestinationPorts(zs.TCPPorts, s.DestinationPorts); ok {
			zs.TCPPorts = ports
			protocols = append(protocols, "tcp")
		}
	}
	if protocolEnabled(zs, "udp") && s.MatchesProtocol("udp") {
		if ports, ok := config.IntersectDestinationPorts(zs.UDPPorts, s.DestinationPorts); ok {
			zs.UDPPorts = ports
			protocols = append(protocols, "udp")
		}
	}
	zs.Protocols = protocols
	return zs
}
