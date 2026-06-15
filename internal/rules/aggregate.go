package rules

func SplitOpenWrt(rs []Rule) (openwrt []Rule, mihomoOnly []Rule) {
	for _, r := range rs {
		if r.SupportedOpenWrt {
			openwrt = append(openwrt, r)
		} else if r.SupportedMihomo {
			mihomoOnly = append(mihomoOnly, r)
		}
	}
	return
}
