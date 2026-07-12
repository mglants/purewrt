package manager

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/mesh"
	"github.com/purewrt/purewrt/internal/system"
)

// meshPeerNameRE mirrors the generator's friend-name guard: peer names
// arrive over the network, so anything outside the safe set is rejected
// before it can land in UCI or generated YAML.
var meshPeerNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// meshHWIDRE guards advertised hardware ids: the provider.AutomaticHWID
// format, "purewrt-" + 24 lowercase hex.
var meshHWIDRE = regexp.MustCompile(`^purewrt-[0-9a-f]{24}$`)

const meshProbeTimeout = 5 * time.Second

// MeshSyncReport is the mesh-sync outcome. Errors are per-peer and
// soft-continued: one unreachable friend must not stop discovery of the
// rest, but any error yields a non-zero CLI exit so the cron retry logic
// (and the LuCI job banner) notice.
type MeshSyncReport struct {
	Probed  int      `json:"probed"`
	Updated int      `json:"updated"`
	Added   int      `json:"added"`
	Removed int      `json:"removed"`
	Applied bool     `json:"applied"`
	Errors  []string `json:"errors,omitempty"`
}

// meshRuntimeStatus is the liveness side-channel (Q3): LastSeen/LastError
// per peer live in a tmpfs JSON file, NOT in UCI — flash writes every sync
// tick would wear the overlay and dirty nothing the generator cares about.
type meshRuntimeStatus struct {
	SyncedAt string                          `json:"synced_at"`
	Peers    map[string]meshRuntimePeerState `json:"peers"`
}

type meshRuntimePeerState struct {
	LastSeen  string `json:"last_seen,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

func meshStatusPath(c config.Config) string {
	return filepath.Join(c.RuntimeDir(), "mesh-status.json")
}

// MeshSync reconciles persisted mesh_peer sections against the live
// overlay: list easytier peers, probe each one's mesh API, persist material
// changes, Apply when anything material moved. Peers that are persisted but
// currently unreachable are KEPT — mihomo health checks park their proxies;
// pruning is a future GC concern, not a sync concern.
func (m Manager) MeshSync() (MeshSyncReport, error) {
	rep := MeshSyncReport{}
	c, err := m.Load()
	if err != nil {
		return rep, err
	}
	if !c.MeshActive() {
		return rep, fmt.Errorf("mesh not active")
	}
	psk, err := hex.DecodeString(c.Mesh.PSK)
	if err != nil || len(psk) == 0 {
		return rep, fmt.Errorf("mesh: stored PSK malformed")
	}
	key := mesh.DeriveAPIKey(psk)
	cli := m.meshCLI(c)
	overlay, err := cli.Peers()
	if err != nil {
		return rep, fmt.Errorf("mesh: overlay peer list: %w", err)
	}

	now := time.Now().UTC()
	status := meshRuntimeStatus{SyncedAt: now.Format(time.RFC3339), Peers: map[string]meshRuntimePeerState{}}
	changed := false
	// The stored hwid is write-once: computed at init/join, never rewritten.
	// The computed value has drift edge cases (interface renames, bridge MAC
	// overrides change the hash seed) and mesh identity must survive them —
	// friends key credentials on this id. Backfill only when a pre-hwid
	// config left it empty. A config restored onto replacement hardware
	// deliberately KEEPS its identity.
	if c.Mesh.HWID == "" {
		if hw, err := m.meshHWID(); err == nil {
			c.Mesh.HWID = hw
			changed = true
		}
	}
	byHWID := map[string]int{}
	for i, p := range c.MeshPeers {
		byHWID[p.HWID] = i
	}
	// aliveIPs marks overlay-level presence: a peer whose API probe fails is
	// still alive on the overlay and must not be stamped absent for GC.
	aliveIPs := map[string]bool{}
	seenHWID := map[string]bool{}
	for _, op := range overlay {
		if op.IPv4 == "" {
			continue
		}
		aliveIPs[op.IPv4] = true
		rep.Probed++
		info, err := m.meshProbe(c, key, op.IPv4)
		if err != nil {
			rep.Errors = append(rep.Errors, op.IPv4+": "+err.Error())
			if op.Hostname != "" {
				status.Peers[op.Hostname] = meshRuntimePeerState{LastError: err.Error()}
			}
			continue
		}
		if info.HWID == c.Mesh.HWID {
			continue // self via a hairpin route
		}
		if !meshHWIDRE.MatchString(info.HWID) {
			rep.Errors = append(rep.Errors, op.IPv4+": missing or malformed hwid")
			continue
		}
		if !meshPeerNameRE.MatchString(info.NodeName) {
			rep.Errors = append(rep.Errors, op.IPv4+": hostile node name")
			continue
		}
		status.Peers[info.NodeName] = meshRuntimePeerState{LastSeen: now.Format(time.RFC3339)}
		seenHWID[info.HWID] = true
		if i, ok := byHWID[info.HWID]; ok {
			p := &c.MeshPeers[i]
			if p.Name != info.NodeName || p.OverlayIP != op.IPv4 || p.ListenPort != info.ListenPort || p.ExitOffered != info.ExitOffered {
				p.Name, p.OverlayIP, p.ListenPort, p.ExitOffered = info.NodeName, op.IPv4, info.ListenPort, info.ExitOffered
				rep.Updated++
				changed = true
			}
			continue
		}
		c.MeshPeers = append(c.MeshPeers, config.MeshPeer{HWID: info.HWID, Name: info.NodeName, Enabled: true, OverlayIP: op.IPv4, ListenPort: info.ListenPort, ExitOffered: info.ExitOffered})
		byHWID[info.HWID] = len(c.MeshPeers) - 1
		rep.Added++
		changed = true
	}

	if meshGCPeers(&c, &rep, seenHWID, aliveIPs, now) {
		changed = true
	}

	if b, err := json.Marshal(status); err == nil {
		_ = os.MkdirAll(filepath.Dir(meshStatusPath(c)), 0755)
		_, _ = system.WriteIfChanged(meshStatusPath(c), b, 0644)
	}
	if changed {
		if err := m.meshSaveApply(c); err != nil {
			return rep, err
		}
		rep.Applied = true
	}
	return rep, nil
}

// meshDay is the UCI last_seen granularity: one calendar day, so the stamp
// costs at most one flash write per day per peer while still giving GC a
// reboot-proof absence clock (the tmpfs liveness file resets on reboot and
// can't drive deletion decisions).
const meshDay = "2006-01-02"

// meshGCPeers stamps day-granular last_seen on present peers and drops peers
// unseen for more than Mesh.PeerTTLDays days (0 disables GC). "Present"
// means either a successful API probe (hwid match) or bare overlay presence
// (its IP answers easytier even if the purewrt API is down) — only full
// absence ages a peer. Peers without a stamp yet are stamped now, so the TTL
// clock always starts from a recorded day, never from a guess.
func meshGCPeers(c *config.Config, rep *MeshSyncReport, seenHWID map[string]bool, aliveIPs map[string]bool, now time.Time) bool {
	today := now.Format(meshDay)
	changed := false
	kept := c.MeshPeers[:0]
	for _, p := range c.MeshPeers {
		present := seenHWID[p.HWID] || (p.OverlayIP != "" && aliveIPs[p.OverlayIP])
		if present || p.LastSeen == "" {
			if stampDay(p.LastSeen) != today {
				p.LastSeen = today
				changed = true
			}
			kept = append(kept, p)
			continue
		}
		if ttl := c.Mesh.PeerTTLDays; ttl > 0 {
			if last, err := time.Parse(meshDay, stampDay(p.LastSeen)); err == nil && now.Sub(last) > time.Duration(ttl)*24*time.Hour {
				rep.Removed++
				changed = true
				continue // dropped; rediscovery re-adds it if it ever returns
			}
		}
		kept = append(kept, p)
	}
	c.MeshPeers = kept
	return changed
}

// stampDay normalizes a stored last_seen to day granularity, accepting the
// RFC3339 stamps older builds wrote.
func stampDay(s string) string {
	if len(s) >= len(meshDay) {
		return s[:len(meshDay)]
	}
	return s
}

// meshProbe fetches and authenticates one peer's /mesh/v1/info.
func (m Manager) meshProbe(c config.Config, key []byte, ip string) (MeshInfo, error) {
	base := "http://" + ip + ":" + strconv.Itoa(c.Mesh.APIMeshPort)
	if m.meshProbeBase != nil {
		base = m.meshProbeBase(ip, c.Mesh.APIMeshPort)
	}
	nb := make([]byte, 8)
	if _, err := rand.Read(nb); err != nil {
		return MeshInfo{}, err
	}
	nonce := hex.EncodeToString(nb)
	ts := time.Now().Unix()
	req, err := http.NewRequest(http.MethodGet, base+"/mesh/v1/info", nil)
	if err != nil {
		return MeshInfo{}, err
	}
	req.Header.Set(mesh.HeaderTime, strconv.FormatInt(ts, 10))
	req.Header.Set(mesh.HeaderNonce, nonce)
	req.Header.Set(mesh.HeaderMAC, mesh.SignRequest(key, ts, nonce, http.MethodGet, "/mesh/v1/info"))
	client := &http.Client{Timeout: meshProbeTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return MeshInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return MeshInfo{}, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return MeshInfo{}, err
	}
	if err := mesh.VerifyResponse(key, ts, nonce, body, resp.Header.Get(mesh.HeaderMAC)); err != nil {
		return MeshInfo{}, err
	}
	var info MeshInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return MeshInfo{}, err
	}
	if info.V != 1 {
		return MeshInfo{}, fmt.Errorf("unsupported info version %d", info.V)
	}
	return info, nil
}
