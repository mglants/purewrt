package manager

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/system"
)

// ZapretCandidates exposes catalog and user library entries only. Configured
// routing strategies remain in the routing table rather than appearing twice.
func (m Manager) ZapretCandidates() config.ZapretCandidateList {
	return config.LoadZapretCandidates()
}

type ZapretLibraryRequest struct {
	Action       string                 `json:"action"`
	Candidate    config.ZapretCandidate `json:"candidate"`
	OriginalName string                 `json:"original_name"`
	Name         string                 `json:"name"`
	Data         string                 `json:"data"`
}

var libraryBlobRefRE = regexp.MustCompile(`(?:^|:)(?:blob|seqovl_pattern|pattern)=([^:\s]+)`)

func libraryBlobNames(params string) []string {
	var out []string
	for _, tok := range strings.Fields(params) {
		for _, m := range libraryBlobRefRE.FindAllStringSubmatch(tok, -1) {
			out = append(out, m[1])
		}
	}
	return out
}

var libraryFileRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,159}\.bin$`)

func validateLibraryCandidate(c config.ZapretCandidate) error {
	if !safeIdentRE.MatchString(c.Name) || !strings.HasPrefix(c.Name, "user_") {
		return fmt.Errorf("user strategy name must start with user_ and use at most 64 letters, digits, underscores or hyphens")
	}
	if len(c.Params) == 0 || len(c.Params) > 16384 || strings.ContainsAny(c.Params, ";&|`$()<>\"'\\\x00") {
		return fmt.Errorf("invalid or oversized strategy parameters")
	}
	if len(c.Protocols) < 1 || len(c.Protocols) > 2 {
		return fmt.Errorf("select TCP, UDP, or both")
	}
	protocols := map[string]bool{}
	for _, p := range c.Protocols {
		if p != "tcp" && p != "udp" || protocols[p] {
			return fmt.Errorf("invalid protocols")
		}
		protocols[p] = true
	}
	for _, ports := range []string{c.TCPPorts, c.UDPPorts} {
		if ports != "" && !validLibraryPorts(ports) {
			return fmt.Errorf("invalid port list %q", ports)
		}
	}
	allowed := map[string]bool{"--new": true, "--name": true, "--filter-tcp": true, "--filter-udp": true, "--filter-l7": true, "--filter-l3": true, "--payload": true, "--in-range": true, "--out-range": true, "--lua-desync": true}
	filters := map[string]bool{}
	for _, arg := range strings.Fields(c.Params) {
		key, value, _ := strings.Cut(arg, "=")
		if !allowed[key] {
			return fmt.Errorf("unsupported strategy option %s; declare blobs separately", key)
		}
		if key == "--filter-tcp" || key == "--filter-udp" {
			p := strings.TrimPrefix(key, "--filter-")
			filters[p] = true
			if !protocols[p] {
				return fmt.Errorf("%s filter does not match selected protocols", p)
			}
			if !validLibraryPorts(value) {
				return fmt.Errorf("invalid filter ports %q", value)
			}
		}
	}
	for p := range protocols {
		if !filters[p] {
			return fmt.Errorf("include --filter-%s in parameters", p)
		}
	}
	aliases := map[string]bool{"fake_default_tls": true, "fake_default_http": true, "fake_default_quic": true}
	for _, b := range c.Blobs {
		if !safeIdentRE.MatchString(b.Name) || aliases[b.Name] {
			return fmt.Errorf("invalid or duplicate blob alias %q", b.Name)
		}
		if b.Hex != "" {
			if b.File != "" || !strings.HasPrefix(b.Hex, "0x") {
				return fmt.Errorf("blob must have a file or hex data")
			}
			d, e := hex.DecodeString(strings.TrimPrefix(b.Hex, "0x"))
			if e != nil || len(d) == 0 || len(d) > 65536 {
				return fmt.Errorf("invalid hex blob")
			}
		} else if !libraryFileRE.MatchString(b.File) || strings.Contains(b.File, "..") {
			return fmt.Errorf("invalid blob filename %q", b.File)
		}
		if b.SHA256 != "" {
			d, e := hex.DecodeString(b.SHA256)
			if e != nil || len(d) != 32 {
				return fmt.Errorf("invalid blob SHA256")
			}
		}
		aliases[b.Name] = true
	}
	for _, name := range libraryBlobNames(c.Params) {
		if strings.HasPrefix(name, "0x") {
			continue
		}
		if !aliases[name] {
			return fmt.Errorf("blob %q is not declared; select its file", name)
		}
	}
	return nil
}
func validLibraryPorts(v string) bool {
	for _, part := range strings.Split(v, ",") {
		var start, end int
		if strings.Contains(part, "-") {
			if _, e := fmt.Sscanf(part, "%d-%d", &start, &end); e != nil {
				return false
			}
		} else {
			if _, e := fmt.Sscanf(part, "%d", &start); e != nil {
				return false
			}
			end = start
		}
		if !regexp.MustCompile(`^[0-9]+(-[0-9]+)?$`).MatchString(part) || start < 1 || end > 65535 || end < start {
			return false
		}
	}
	return true
}

func (m Manager) ZapretLibrary(req ZapretLibraryRequest) (any, error) {
	lock, err := system.TryAcquire("/tmp/purewrt-zapret-library.lock")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if req.Action == "upload_blob" {
		if !safeIdentRE.MatchString(req.Name) {
			return nil, fmt.Errorf("invalid blob alias")
		}
		data, e := base64.StdEncoding.DecodeString(req.Data)
		if e != nil || len(data) == 0 || len(data) > 65536 {
			return nil, fmt.Errorf("upload a nonempty .bin file of at most 64 KiB")
		}
		file := "user_" + req.Name + "_" + blobSum(data)[:16] + ".bin"
		if e = os.MkdirAll(config.ZapretBlobCacheDir, 0755); e != nil {
			return nil, e
		}
		if e = system.AtomicWrite(filepath.Join(config.ZapretBlobCacheDir, file), data, 0644); e != nil {
			return nil, e
		}
		return config.ZapretBlobRef{Name: req.Name, File: file, SHA256: blobSum(data)}, nil
	}
	var list config.ZapretCandidateList
	data, err := os.ReadFile(config.ZapretUserCandidatesPath)
	if err == nil {
		if len(data) > 1<<20 {
			return nil, fmt.Errorf("user library too large")
		}
		if err = json.Unmarshal(data, &list); err != nil {
			return nil, fmt.Errorf("user library invalid: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if req.Action != "save" && req.Action != "delete" {
		return nil, fmt.Errorf("unknown library action")
	}
	if req.OriginalName != "" && (req.Action == "delete" || req.Candidate.Name != req.OriginalName) {
		c, e := m.Load()
		if e != nil {
			return nil, e
		}
		for _, app := range c.ZapretApplications {
			for _, assignment := range app.Assignments {
				_, candidate, _ := strings.Cut(assignment, "=")
				if candidate == req.OriginalName {
					return nil, fmt.Errorf("library entry is referenced by application %s; remove that assignment before deleting or renaming", app.Name)
				}
			}
		}
	}
	if req.Action == "save" {
		if err = validateLibraryCandidate(req.Candidate); err != nil {
			return nil, err
		}
		if len(list.Candidates) >= 128 && req.OriginalName == "" {
			return nil, fmt.Errorf("user library is limited to 128 strategies")
		}
		for _, c := range config.LoadZapretCatalog().Candidates {
			if c.Name == req.Candidate.Name {
				return nil, fmt.Errorf("name belongs to the downloaded catalog")
			}
		}
		// Duplicate aliases across candidates may resolve implicitly in production.
		for _, c := range config.LoadZapretCandidates().Candidates {
			if c.Name == req.OriginalName {
				continue
			}
			for _, b := range c.Blobs {
				for _, n := range req.Candidate.Blobs {
					if b.Name == n.Name && (b.File != n.File || b.Hex != n.Hex) {
						return nil, fmt.Errorf("blob alias %s already refers to different data; choose another alias", b.Name)
					}
				}
			}
		}
		args, e := m.clientTestArgs([]config.ZapretCandidate{req.Candidate}, "9910")
		if e != nil {
			return nil, e
		}
		bin := m.zapretNFQWSBin()
		if bin == "" {
			return nil, fmt.Errorf("nfqws2 is not installed")
		}
		args = append([]string{"--dry-run"}, args...)
		if out, e := (system.Runner{Timeout: 15 * time.Second}).Run(bin, args...); e != nil {
			return nil, fmt.Errorf("nfqws validation failed: %s: %w", out, e)
		}
	}
	updated, err := updateUserLibrary(list, req)
	if err != nil {
		return nil, err
	}
	data, err = json.MarshalIndent(updated, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("user library exceeds 1 MiB")
	}
	if err = os.MkdirAll(filepath.Dir(config.ZapretUserCandidatesPath), 0755); err != nil {
		return nil, err
	}
	if err = system.AtomicWrite(config.ZapretUserCandidatesPath, data, 0644); err != nil {
		return nil, err
	}
	return map[string]string{"result": "ok", "name": req.Candidate.Name}, nil
}
func updateUserLibrary(list config.ZapretCandidateList, req ZapretLibraryRequest) (config.ZapretCandidateList, error) {
	index := -1
	for i, c := range list.Candidates {
		if c.Name == req.OriginalName {
			index = i
		}
		if req.Action == "save" && c.Name == req.Candidate.Name && c.Name != req.OriginalName {
			return list, fmt.Errorf("strategy name already exists")
		}
	}
	if req.OriginalName != "" && index < 0 {
		return list, fmt.Errorf("user strategy no longer exists")
	}
	if req.Action == "delete" {
		if index < 0 {
			return list, fmt.Errorf("select a user strategy")
		}
		list.Candidates = append(list.Candidates[:index], list.Candidates[index+1:]...)
	} else {
		req.Candidate.Origin = "user"
		if index < 0 {
			list.Candidates = append(list.Candidates, req.Candidate)
		} else {
			list.Candidates[index] = req.Candidate
		}
	}
	return list, nil
}

func (m Manager) zapretBlobValue(b config.ZapretBlobRef) (string, error) {
	if b.Hex != "" {
		d, e := hex.DecodeString(strings.TrimPrefix(b.Hex, "0x"))
		if e != nil || len(d) == 0 || len(d) > 65536 || !strings.HasPrefix(b.Hex, "0x") {
			return "", fmt.Errorf("invalid hex blob %s", b.Name)
		}
		return b.Hex, nil
	}
	path, e := m.ResolveBlob(b.File, b.SHA256)
	return "@" + path, e
}
