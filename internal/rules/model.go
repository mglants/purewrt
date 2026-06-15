package rules

type Type string

const (
	Domain        Type = "domain"
	DomainSuffix  Type = "domain_suffix"
	DomainKeyword Type = "domain_keyword"
	IPCIDR        Type = "ip_cidr"
	IPCIDR6       Type = "ip_cidr6"
	Classical     Type = "classical"
	DstPort       Type = "dst_port"
	Logical       Type = "logical"
	Native        Type = "native"
	GeoSite       Type = "geosite"
	GeoIP         Type = "geoip"
)

type Rule struct {
	Type             Type
	Value            string
	NoResolve        bool
	SourceProvider   string
	SourceLine       int
	SupportedOpenWrt bool
	SupportedMihomo  bool
}
type Provider struct {
	Name, Behavior, Format, Section, Action string
	Rules                                   []Rule
	Warnings                                []string
}
