package manager

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/mesh"
)

// MeshInitResult is what mesh-init / mesh-join / mesh-rotate print: the
// pasteable sync-code plus the derived network name for display.
type MeshInitResult struct {
	Code        string `json:"code"`
	NetworkName string `json:"network_name"`
}

// MeshInstalled reports whether the easytier companion package is present —
// the zapret_installed twin that gates the LuCI mesh page.
func (m Manager) MeshInstalled() bool {
	bin := config.DefaultMesh().EasytierBin
	if c, err := m.Load(); err == nil && c.Mesh.EasytierBin != "" {
		bin = c.Mesh.EasytierBin
	}
	fi, err := os.Stat(bin)
	return err == nil && !fi.IsDir()
}

// meshNodeName picks the mesh identity: explicit flag, else the router's
// hostname, else a fixed fallback.
func meshNodeName(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "purewrt"
}

// fillMeshFromCode populates the Mesh section from a decoded sync-code,
// preserving plumbing fields (ports, device, bin) the code doesn't carry.
// The credential salt is derived from (PSK, node name) — nothing is minted.
func fillMeshFromCode(c *config.Config, code mesh.Code, nodeName string) error {
	d := config.DefaultMesh()
	mc := c.Mesh
	if mc.ListenPort <= 0 {
		mc.ListenPort = d.ListenPort
	}
	if mc.APIMeshPort <= 0 {
		mc.APIMeshPort = d.APIMeshPort
	}
	if mc.DeviceName == "" {
		mc.DeviceName = d.DeviceName
	}
	if mc.EasytierBin == "" {
		mc.EasytierBin = d.EasytierBin
	}
	if mc.RPCPortal == "" {
		mc.RPCPortal = d.RPCPortal
	}
	if mc.SyncCron == "" {
		mc.SyncCron = d.SyncCron
	}
	mc.Enabled = true
	mc.Code = code.Encode()
	mc.NetworkName = code.NetworkName()
	mc.NetworkSecret = base64.StdEncoding.EncodeToString(code.NetworkSecret[:])
	mc.PSK = hex.EncodeToString(code.PSK[:])
	mc.NodeName = nodeName
	// Offering the exit is the point of the mesh, and it never exposes the
	// router's home IP (MeshExit routes via own proxies only) — default on,
	// LuCI/CLI can toggle it off.
	mc.ExitEnabled = true
	mc.ExtraPeers = append([]string{}, code.ExtraPeers...)
	c.Mesh = mc
	return nil
}

func (m Manager) meshSaveApply(c config.Config) error {
	if m.ConfigPath == "" {
		m.ConfigPath = uciPurewrtPath
	}
	_, _ = config.Backup(m.ConfigPath)
	if err := config.Save(m.ConfigPath, c); err != nil {
		return err
	}
	return m.Apply()
}

// MeshInit mints a fresh group and joins it as the first member.
func (m Manager) MeshInit(nodeName string) (MeshInitResult, error) {
	c, err := m.Load()
	if err != nil {
		return MeshInitResult{}, err
	}
	if c.MeshActive() {
		return MeshInitResult{}, fmt.Errorf("mesh already active (network %s) — mesh-leave first, or mesh-code to reprint the code", c.Mesh.NetworkName)
	}
	code, err := mesh.GenerateCode()
	if err != nil {
		return MeshInitResult{}, err
	}
	if err := fillMeshFromCode(&c, code, meshNodeName(nodeName)); err != nil {
		return MeshInitResult{}, err
	}
	if err := m.meshSaveApply(c); err != nil {
		return MeshInitResult{}, err
	}
	return MeshInitResult{Code: code.Encode(), NetworkName: c.Mesh.NetworkName}, nil
}

// MeshJoin joins an existing group from a pasted sync-code.
func (m Manager) MeshJoin(codeStr, nodeName string) (MeshInitResult, error) {
	c, err := m.Load()
	if err != nil {
		return MeshInitResult{}, err
	}
	if c.MeshActive() {
		return MeshInitResult{}, fmt.Errorf("mesh already active (network %s) — mesh-leave first", c.Mesh.NetworkName)
	}
	code, err := mesh.DecodeCode(codeStr)
	if err != nil {
		return MeshInitResult{}, err
	}
	if err := fillMeshFromCode(&c, code, meshNodeName(nodeName)); err != nil {
		return MeshInitResult{}, err
	}
	if err := m.meshSaveApply(c); err != nil {
		return MeshInitResult{}, err
	}
	return MeshInitResult{Code: code.Encode(), NetworkName: c.Mesh.NetworkName}, nil
}

// MeshLeave clears the mesh membership and all persisted peers; Apply tears
// the listener/zone/daemon down.
func (m Manager) MeshLeave() error {
	c, err := m.Load()
	if err != nil {
		return err
	}
	if !c.MeshActive() && len(c.MeshPeers) == 0 {
		return fmt.Errorf("mesh not active")
	}
	c.Mesh = config.DefaultMesh()
	c.MeshPeers = nil
	return m.meshSaveApply(c)
}

// meshCodeFromConfig decodes the stored sync-code.
func meshCodeFromConfig(mc config.Mesh) (mesh.Code, error) {
	if mc.Code == "" {
		return mesh.Code{}, fmt.Errorf("mesh: no sync-code stored")
	}
	return mesh.DecodeCode(mc.Code)
}

// MeshCode re-encodes the stored group material as a pasteable sync-code.
// Write-ACL on the rpcd side: the code contains the group secrets.
func (m Manager) MeshCode() (MeshInitResult, error) {
	c, err := m.Load()
	if err != nil {
		return MeshInitResult{}, err
	}
	if !c.MeshActive() {
		return MeshInitResult{}, fmt.Errorf("mesh not active")
	}
	code, err := meshCodeFromConfig(c.Mesh)
	if err != nil {
		return MeshInitResult{}, err
	}
	return MeshInitResult{Code: code.Encode(), NetworkName: c.Mesh.NetworkName}, nil
}

// MeshRotate mints a new network secret + PSK + own cred salt while keeping
// the network name and persisted peers. Remaining friends re-paste the new
// code; a kicked router can no longer join the overlay and every credential
// derived from the old PSK dies with it.
func (m Manager) MeshRotate() (MeshInitResult, error) {
	c, err := m.Load()
	if err != nil {
		return MeshInitResult{}, err
	}
	if !c.MeshActive() {
		return MeshInitResult{}, fmt.Errorf("mesh not active")
	}
	old, err := meshCodeFromConfig(c.Mesh)
	if err != nil {
		return MeshInitResult{}, err
	}
	fresh, err := mesh.GenerateCode()
	if err != nil {
		return MeshInitResult{}, err
	}
	fresh.NameEntropy = old.NameEntropy // keep the network name
	fresh.ExtraPeers = old.ExtraPeers
	nodeName := c.Mesh.NodeName
	if err := fillMeshFromCode(&c, fresh, nodeName); err != nil {
		return MeshInitResult{}, err
	}
	if err := m.meshSaveApply(c); err != nil {
		return MeshInitResult{}, err
	}
	return MeshInitResult{Code: fresh.Encode(), NetworkName: c.Mesh.NetworkName}, nil
}

// MeshPeerSet toggles consumption of one persisted peer's exit.
func (m Manager) MeshPeerSet(name string, enabled bool) error {
	c, err := m.Load()
	if err != nil {
		return err
	}
	for i := range c.MeshPeers {
		if c.MeshPeers[i].Name == name {
			c.MeshPeers[i].Enabled = enabled
			return m.meshSaveApply(c)
		}
	}
	return fmt.Errorf("mesh peer %q not found", name)
}

// MeshStatusReport merges config state with live easytier daemon state.
// Liveness is best-effort: a dead daemon yields DaemonRunning=false and
// config-only peer rows, never an error — the LuCI page must render either
// way.
type MeshStatusReport struct {
	Active        bool             `json:"active"`
	Installed     bool             `json:"installed"`
	NetworkName   string           `json:"network_name,omitempty"`
	NodeName      string           `json:"node_name,omitempty"`
	ExitEnabled   bool             `json:"exit_enabled"`
	DaemonRunning bool             `json:"daemon_running"`
	OverlayIP     string           `json:"overlay_ip,omitempty"`
	Peers         []MeshPeerStatus `json:"peers"`
}

type MeshPeerStatus struct {
	Name        string  `json:"name"`
	Enabled     bool    `json:"enabled"`
	OverlayIP   string  `json:"overlay_ip,omitempty"`
	ExitOffered bool    `json:"exit_offered"`
	Live        bool    `json:"live"`
	Relay       bool    `json:"relay,omitempty"`
	LatencyMs   float64 `json:"latency_ms,omitempty"`
	LastSeen    string  `json:"last_seen,omitempty"`
	LastError   string  `json:"last_error,omitempty"`
}

// MeshDiagnosticsReport is the overlay-formation debugging view: per-
// rendezvous dial status plus the STUN NAT classification. Everything is
// best-effort — a dead daemon yields empty sections, never an error, so the
// LuCI card renders in every state.
type MeshDiagnosticsReport struct {
	Active        bool                `json:"active"`
	DaemonRunning bool                `json:"daemon_running"`
	OverlayIP     string              `json:"overlay_ip,omitempty"`
	Connectors    []MeshConnectorInfo `json:"connectors"`
	NatUDP        string              `json:"nat_udp,omitempty"`
	NatTCP        string              `json:"nat_tcp,omitempty"`
	PublicIPs     []string            `json:"public_ips,omitempty"`
}

type MeshConnectorInfo struct {
	URL    string `json:"url"`
	Status string `json:"status"`
}

// MeshDiagnostics reports why the overlay is (not) forming: which rendezvous
// peers connect and what NAT the node sits behind. Symmetric NAT means
// punching usually fails and friends fall back to relay through the
// rendezvous.
func (m Manager) MeshDiagnostics() MeshDiagnosticsReport {
	rep := MeshDiagnosticsReport{Connectors: []MeshConnectorInfo{}}
	c, err := m.Load()
	if err != nil {
		return rep
	}
	rep.Active = c.MeshActive()
	if !rep.Active || !m.MeshInstalled() {
		return rep
	}
	cli := m.meshCLI(c)
	if ip, err := cli.NodeIP(); err == nil {
		rep.DaemonRunning = true
		rep.OverlayIP = ip
	}
	if conns, err := cli.Connectors(); err == nil {
		rep.DaemonRunning = true
		for _, cn := range conns {
			rep.Connectors = append(rep.Connectors, MeshConnectorInfo{URL: cn.URL, Status: cn.Status})
		}
	}
	if nat, err := cli.NAT(); err == nil {
		rep.NatUDP = nat.UDPNatType
		rep.NatTCP = nat.TCPNatType
		rep.PublicIPs = nat.PublicIPs
	}
	return rep
}

func (m Manager) meshCLI(c config.Config) mesh.CLI {
	bin := c.Mesh.EasytierBin
	if bin == "" {
		bin = config.DefaultMesh().EasytierBin
	}
	// easytier ships easytier-core + easytier-cli side by side.
	cli := strings.TrimSuffix(bin, "-core") + "-cli"
	if cli == bin {
		cli = filepath.Join(filepath.Dir(bin), "easytier-cli")
	}
	portal := c.Mesh.RPCPortal
	if portal == "" {
		portal = config.DefaultMesh().RPCPortal
	}
	return mesh.CLI{Bin: cli, Portal: portal, Run: m.meshRunner}
}

func (m Manager) MeshStatus() MeshStatusReport {
	rep := MeshStatusReport{Installed: m.MeshInstalled(), Peers: []MeshPeerStatus{}}
	c, err := m.Load()
	if err != nil {
		return rep
	}
	rep.Active = c.MeshActive()
	rep.NetworkName = c.Mesh.NetworkName
	rep.NodeName = c.Mesh.NodeName
	rep.ExitEnabled = c.Mesh.ExitEnabled
	live := map[string]mesh.OverlayPeer{}
	if rep.Active && rep.Installed {
		cli := m.meshCLI(c)
		if ip, err := cli.NodeIP(); err == nil {
			rep.DaemonRunning = true
			rep.OverlayIP = ip
		}
		if peers, err := cli.Peers(); err == nil {
			for _, p := range peers {
				live[p.IPv4] = p
			}
		}
	}
	for _, p := range c.MeshPeers {
		st := MeshPeerStatus{Name: p.Name, Enabled: p.Enabled, OverlayIP: p.OverlayIP, ExitOffered: p.ExitOffered, LastSeen: p.LastSeen, LastError: p.LastError}
		if lp, ok := live[p.OverlayIP]; ok && p.OverlayIP != "" {
			st.Live = true
			st.Relay = lp.Relay
			st.LatencyMs = lp.LatencyMs
		}
		rep.Peers = append(rep.Peers, st)
	}
	return rep
}
