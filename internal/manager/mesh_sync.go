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

const meshProbeTimeout = 5 * time.Second

// MeshSyncReport is the mesh-sync outcome. Errors are per-peer and
// soft-continued: one unreachable friend must not stop discovery of the
// rest, but any error yields a non-zero CLI exit so the cron retry logic
// (and the LuCI job banner) notice.
type MeshSyncReport struct {
	Probed  int      `json:"probed"`
	Updated int      `json:"updated"`
	Added   int      `json:"added"`
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
	byName := map[string]int{}
	for i, p := range c.MeshPeers {
		byName[p.Name] = i
	}
	changed := false
	for _, op := range overlay {
		if op.IPv4 == "" {
			continue
		}
		rep.Probed++
		info, err := m.meshProbe(c, key, op.IPv4)
		if err != nil {
			rep.Errors = append(rep.Errors, op.IPv4+": "+err.Error())
			if op.Hostname != "" {
				status.Peers[op.Hostname] = meshRuntimePeerState{LastError: err.Error()}
			}
			continue
		}
		if info.NodeName == c.Mesh.NodeName {
			continue // self via a hairpin route
		}
		if !meshPeerNameRE.MatchString(info.NodeName) {
			rep.Errors = append(rep.Errors, op.IPv4+": hostile node name")
			continue
		}
		if _, err := hex.DecodeString(info.CredSalt); err != nil || info.CredSalt == "" {
			rep.Errors = append(rep.Errors, info.NodeName+": malformed cred salt")
			continue
		}
		status.Peers[info.NodeName] = meshRuntimePeerState{LastSeen: now.Format(time.RFC3339)}
		if i, ok := byName[info.NodeName]; ok {
			p := &c.MeshPeers[i]
			if p.OverlayIP != op.IPv4 || p.ListenPort != info.ListenPort || p.CredSalt != info.CredSalt || p.ExitOffered != info.ExitOffered {
				p.OverlayIP, p.ListenPort, p.CredSalt, p.ExitOffered = op.IPv4, info.ListenPort, info.CredSalt, info.ExitOffered
				rep.Updated++
				changed = true
			}
			continue
		}
		c.MeshPeers = append(c.MeshPeers, config.MeshPeer{Name: info.NodeName, Enabled: true, OverlayIP: op.IPv4, ListenPort: info.ListenPort, CredSalt: info.CredSalt, ExitOffered: info.ExitOffered})
		byName[info.NodeName] = len(c.MeshPeers) - 1
		rep.Added++
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
