package manager

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"path/filepath"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/generator"
	"github.com/purewrt/purewrt/internal/system"
)

// ApplyAttempt is bounded runtime status, not a cache of rule contents.
type ApplyAttempt struct {
	Time    time.Time `json:"time"`
	Success bool      `json:"success"`
	Stage   string    `json:"stage"`
	Error   string    `json:"error,omitempty"`
}
type ApplyHealthReport struct {
	Last   *ApplyAttempt `json:"last,omitempty"`
	Issues []string      `json:"issues"`
}
type applyStageFailure struct {
	stage string
	err   error
}

func (e *applyStageFailure) Error() string       { return e.stage + ": " + e.err.Error() }
func (e *applyStageFailure) Unwrap() error       { return e.err }
func applyFailure(stage string, err error) error { return &applyStageFailure{stage, err} }

func applyHealthPath(c config.Config) string {
	return filepath.Join(c.RuntimeDir(), "apply-health.json")
}
func recordApplyAttempt(c config.Config, started time.Time, err error) error {
	a := ApplyAttempt{Time: started.UTC(), Success: err == nil, Stage: "complete"}
	if err != nil {
		a.Stage = "prepare"
		var staged *applyStageFailure
		if errors.As(err, &staged) {
			a.Stage = staged.stage
		}
		a.Error = err.Error()
		if len(a.Error) > 2048 {
			a.Error = a.Error[:2048] + "…"
		}
	}
	b, e := json.Marshal(a)
	if e != nil {
		return e
	}
	return system.AtomicWrite(applyHealthPath(c), b, 0600)
}

// Only metadata is read. An empty generated nft payload is not a legitimate
// empty rule list: the generator always emits a header and set flush commands.
func checkApplyFiles(p generator.GeneratedPaths, g generator.GenerationGroups) error {
	var paths []string
	if g.Mihomo {
		paths = append(paths, p.MihomoConfig)
	}
	if g.OpenWrtBundle {
		paths = append(paths, p.NFTFile, p.NFTSetsFile)
	}
	for _, path := range paths {
		if err := checkGeneratedFile(path); err != nil {
			return err
		}
	}
	return nil
}

func checkGeneratedFile(path string) error {
	if path == "" {
		return fmt.Errorf("generated output path is missing")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("generated output %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Errorf("generated output %s is empty or not a regular file", path)
	}
	return nil
}

func (m Manager) ApplyHealth() ApplyHealthReport {
	r := ApplyHealthReport{Issues: []string{}}
	c, err := m.Load()
	if err != nil {
		r.Issues = append(r.Issues, "load configuration: "+err.Error())
		c = config.Default()
	}
	f, err := os.Open(applyHealthPath(c))
	if err == nil {
		var a ApplyAttempt
		err = json.NewDecoder(io.LimitReader(f, 16*1024)).Decode(&a)
		f.Close()
		if err == nil {
			r.Last = &a
		} else {
			r.Issues = append(r.Issues, "read apply status: "+err.Error())
		}
	} else if !os.IsNotExist(err) {
		r.Issues = append(r.Issues, "read apply status: "+err.Error())
	}
	if c.Settings.Enabled {
		p := generator.DefaultGeneratedPaths(c)
		for _, path := range []string{p.MihomoConfig, p.NFTFile, p.NFTSetsFile} {
			if e := checkGeneratedFile(path); e != nil {
				r.Issues = append(r.Issues, e.Error())
			}
		}
	}
	return r
}

// Best-effort socket logging remains available when filesystem writes fail.
func logApplyFailure(message string) {
	if len(message) > 2048 {
		message = message[:2048]
	}
	if w, err := syslog.New(syslog.LOG_ERR|syslog.LOG_DAEMON, "purewrt"); err == nil {
		_ = w.Err(message)
		_ = w.Close()
	}
}
