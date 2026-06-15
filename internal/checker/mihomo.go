package checker

type MihomoPath struct {
	Inbound, Group, SelectedNode, NodeStatus string
	LatencyMS                                int
}

func MihomoForSection(sec string) MihomoPath {
	group := map[string]string{"ai": "AI", "media": "Media", "common": "Common"}[sec]
	if group == "" {
		group = "Common"
	}
	return MihomoPath{Inbound: "tproxy-" + sec, Group: group, SelectedNode: "unknown", NodeStatus: "unknown"}
}
