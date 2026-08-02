package proxyguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/system"
)

const (
	StateVersion = 1

	Healthy     = "healthy"
	Suspect     = "suspect"
	Quarantined = "quarantined"
)

var ErrStateVersion = errors.New("unsupported proxy-guard state version")

// State is the tmpfs-backed input to the mihomo runtime overlay. It contains
// measurements as well as the small routing decision: quarantined names and
// each group's forced last-resort member. User UCI filters never live here.
type State struct {
	Version   int                    `json:"version"`
	UpdatedAt time.Time              `json:"updated_at,omitempty"`
	LastRun   time.Time              `json:"last_run,omitempty"`
	Nodes     map[string]*NodeState  `json:"nodes,omitempty"`
	Groups    map[string]*GroupState `json:"groups,omitempty"`
}

type NodeState struct {
	Name           string    `json:"name"`
	Provider       string    `json:"provider,omitempty"`
	Kind           string    `json:"kind,omitempty"`
	State          string    `json:"state"`
	Reason         string    `json:"reason,omitempty"`
	LatenciesMS    []int     `json:"latencies_ms,omitempty"`
	LastDelayMS    int       `json:"last_delay_ms,omitempty"`
	JitterMS       int       `json:"jitter_ms,omitempty"`
	LastDownKbps   float64   `json:"last_down_kbps,omitempty"`
	LastProbe      time.Time `json:"last_probe,omitempty"`
	BadStreak      int       `json:"bad_streak,omitempty"`
	RecoveryStreak int       `json:"recovery_streak,omitempty"`
	QuarantinedAt  time.Time `json:"quarantined_at,omitempty"`
	RetryAfter     time.Time `json:"retry_after,omitempty"`
	LastSeen       time.Time `json:"last_seen,omitempty"`
}

type GroupState struct {
	Name        string   `json:"name"`
	Members     []string `json:"members,omitempty"`
	LastResorts []string `json:"last_resorts,omitempty"`
}

func NewState() State {
	return State{Version: StateVersion, Nodes: map[string]*NodeState{}, Groups: map[string]*GroupState{}}
}

func Path(c config.Config) string {
	return filepath.Join(c.RuntimeDir(), "proxy-guard.json")
}

func ProbeLockPath(c config.Config) string {
	return filepath.Join(c.RuntimeDir(), "proxy-guard-probe.lock")
}

func Load(c config.Config) (State, error) {
	data, err := os.ReadFile(Path(c))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewState(), nil
		}
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, err
	}
	if s.Version != StateVersion {
		return NewState(), fmt.Errorf("%w: got %d, want %d", ErrStateVersion, s.Version, StateVersion)
	}
	ensureMaps(&s)
	return s, nil
}

func Save(c config.Config, s State) error {
	ensureMaps(&s)
	s.Version = StateVersion
	s.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return system.AtomicWrite(Path(c), append(data, '\n'), 0600)
}

func Remove(c config.Config) error {
	err := os.Remove(Path(c))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func ensureMaps(s *State) {
	if s.Nodes == nil {
		s.Nodes = map[string]*NodeState{}
	}
	if s.Groups == nil {
		s.Groups = map[string]*GroupState{}
	}
}

func (s State) QuarantinedNames() []string {
	var out []string
	for name, node := range s.Nodes {
		if node != nil && node.State == Quarantined {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// RoutingSignature excludes measurements and timestamps. It changes only
// when the generated mihomo membership should change.
func (s State) RoutingSignature() string {
	type groupSig struct {
		Name        string
		LastResorts []string
	}
	var nodes []string
	for name, n := range s.Nodes {
		if n != nil && n.State == Quarantined {
			nodes = append(nodes, name)
		}
	}
	sort.Strings(nodes)
	var groups []groupSig
	for name, g := range s.Groups {
		if g != nil && len(g.LastResorts) > 0 {
			retained := append([]string(nil), g.LastResorts...)
			sort.Strings(retained)
			groups = append(groups, groupSig{Name: name, LastResorts: retained})
		}
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	b, _ := json.Marshal(struct {
		Nodes  []string
		Groups []groupSig
	}{nodes, groups})
	return string(b)
}
