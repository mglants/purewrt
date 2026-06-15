package generator

import (
	"io"

	"github.com/purewrt/purewrt/internal/config"
)

func WriteDNSMasqHeader(w io.Writer) error {
	_, err := io.WriteString(w, "# PureWRT generated file; do not edit.\n")
	return err
}

func WriteDNSMasqDomain(w io.Writer, c config.Config, s config.Section, d string) error {
	pfx := DNSMasqDomainPrefixes(c, s)
	return WriteDNSMasqDomainPrefixed(w, pfx, d)
}

// DNSMasqDomainPrefixes is the constant per-section prefix/suffix pair used by
// WriteDNSMasqDomainPrefixed. It's split this way so callers emitting many
// domains for the same section (the big MRS providers) can pre-compute the
// strings once instead of paying ~4 allocations per domain inside the inner
// loop. For the 80 k-entry providers this cuts the per-emit cost
// dramatically — the bottleneck in the streamMRSData hot path was the
// per-call `dnsSetName(s.NFTSet4())` + big concat into `io.WriteString`.
type domainPrefixes struct {
	// v4Prefix/v4Suffix: complete the line as `v4Prefix + domain + v4Suffix`.
	v4Prefix, v4Suffix string
	// v6Prefix/v6Suffix: same for IPv6; empty when IPv6 disabled for the
	// section so callers can check `v6Prefix == ""` to skip the v6 write
	// without re-evaluating the IPv6/LowResource flags per domain.
	v6Prefix, v6Suffix string
}

func DNSMasqDomainPrefixes(c config.Config, s config.Section) domainPrefixes {
	var p domainPrefixes
	if s.IPv4Enabled {
		set := dnsSetName(s.NFTSet4())
		p.v4Prefix = "nftset=/"
		p.v4Suffix = "/4#inet#purewrt#" + set + "\n"
	}
	if s.IPv6Enabled && c.Settings.IPv6 && !c.LowResource() {
		set := dnsSetName(s.NFTSet6())
		p.v6Prefix = "nftset=/"
		p.v6Suffix = "/6#inet#purewrt#" + set + "\n"
	}
	return p
}

func WriteDNSMasqDomainPrefixed(w io.Writer, pfx domainPrefixes, d string) error {
	if pfx.v4Prefix != "" {
		if _, err := io.WriteString(w, pfx.v4Prefix); err != nil {
			return err
		}
		if _, err := io.WriteString(w, d); err != nil {
			return err
		}
		if _, err := io.WriteString(w, pfx.v4Suffix); err != nil {
			return err
		}
	}
	if pfx.v6Prefix != "" {
		if _, err := io.WriteString(w, pfx.v6Prefix); err != nil {
			return err
		}
		if _, err := io.WriteString(w, d); err != nil {
			return err
		}
		if _, err := io.WriteString(w, pfx.v6Suffix); err != nil {
			return err
		}
	}
	return nil
}

// WriteDNSMasqDomainPrefixedBytes is the []byte-flavored sibling of
// WriteDNSMasqDomainPrefixed used by the MRS streaming hot path. Avoids
// the string conversion that would otherwise force a per-emit allocation
// when the caller already has the domain as bytes — `w.Write(d)` accepts
// the slice directly, while `io.WriteString(w, string(d))` would copy.
func WriteDNSMasqDomainPrefixedBytes(w io.Writer, pfx domainPrefixes, d []byte) error {
	if pfx.v4Prefix != "" {
		if _, err := io.WriteString(w, pfx.v4Prefix); err != nil {
			return err
		}
		if _, err := w.Write(d); err != nil {
			return err
		}
		if _, err := io.WriteString(w, pfx.v4Suffix); err != nil {
			return err
		}
	}
	if pfx.v6Prefix != "" {
		if _, err := io.WriteString(w, pfx.v6Prefix); err != nil {
			return err
		}
		if _, err := w.Write(d); err != nil {
			return err
		}
		if _, err := io.WriteString(w, pfx.v6Suffix); err != nil {
			return err
		}
	}
	return nil
}
