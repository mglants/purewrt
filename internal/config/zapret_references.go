package config

import "fmt"

// ResolveZapretReferences expands library references in memory only. UCI retains
// only the candidate identity and runtime settings; edits take effect on apply.
func (c *Config) ResolveZapretReferences(list ZapretCandidateList) error {
	byName := map[string]ZapretCandidate{}
	for _, v := range list.Candidates {
		byName[v.Name] = v
	}
	for i := range c.ZapretStrategies {
		s := &c.ZapretStrategies[i]
		if s.Candidate == "" {
			continue
		}
		v, ok := byName[s.Candidate]
		if !ok {
			return fmt.Errorf("zapret strategy %s references missing library entry %s", s.Name, s.Candidate)
		}
		s.Params, s.Protocols = v.Params, append([]string(nil), v.Protocols...)
		s.TCPPorts, s.UDPPorts = v.TCPPorts, v.UDPPorts
		s.TCPPktOut, s.TCPPktIn, s.UDPPktOut, s.UDPPktIn = v.TCPPktOut, v.TCPPktIn, v.UDPPktOut, v.UDPPktIn
		s.LibraryBlobs = nil
		for _, b := range v.Blobs {
			value := b.Hex
			if value == "" {
				value = "@" + CanonicalBlobPath(b.File)
			}
			s.LibraryBlobs = append(s.LibraryBlobs, b.Name+":"+value)
		}
	}
	return nil
}
