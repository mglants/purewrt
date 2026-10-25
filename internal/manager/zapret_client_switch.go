package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/purewrt/purewrt/internal/system"
)

type clientSwitchRequest struct {
	ID                       string
	Expires                  int64
	Candidate, Extra, Manual string
}
type clientSwitchResult struct{ ID, Error string }

// ZapretClientSwitch changes only strategy selection in an existing session.
// Its client, WAN, routing state and original expiry remain unchanged.
func (m Manager) ZapretClientSwitch(candidate, extra string, manualInput ...string) error {
	manual := ""
	if len(manualInput) > 0 {
		manual = manualInput[0]
	}
	lock, err := system.TryAcquire(clientTestPath(".switch-lock"))
	if err != nil {
		return fmt.Errorf("another strategy switch is pending: %w", err)
	}
	defer lock.Close()
	s := m.ZapretClientStatus()
	if !s.Running || s.Phase != "testing" {
		return fmt.Errorf("no active client test")
	}
	if time.Until(time.Unix(s.Expires, 0)) < 10*time.Second {
		return fmt.Errorf("test is about to expire; start a new session")
	}
	if _, err = clientTestCandidates(ZapretClientOptions{Candidate: candidate, Extra: extra, Manual: manual}, m.ZapretCandidates()); err != nil {
		return err
	}
	req := clientSwitchRequest{ID: strconv.FormatInt(time.Now().UnixNano(), 10), Expires: s.Expires, Candidate: candidate, Extra: extra, Manual: manual}
	data, _ := json.Marshal(req)
	if err = system.AtomicWrite(clientTestPath(".switch"), data, 0600); err != nil {
		return err
	}
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		var result clientSwitchResult
		if b, e := os.ReadFile(clientTestPath(".switch-result")); e == nil && json.Unmarshal(b, &result) == nil && result.ID == req.ID {
			if result.Error != "" {
				return fmt.Errorf("%s", result.Error)
			}
			return nil
		}
	}
	return fmt.Errorf("switch acknowledgment timed out; check current test status")
}

func readClientSwitch() (clientSwitchRequest, error) {
	var req clientSwitchRequest
	data, err := os.ReadFile(clientTestPath(".switch"))
	if err != nil {
		return req, err
	}
	_ = os.Remove(clientTestPath(".switch"))
	err = json.Unmarshal(data, &req)
	return req, err
}

type clientNFQ struct {
	cmd  *exec.Cmd
	done chan error
}

func (p *clientNFQ) stop() {
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	_ = p.cmd.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(time.Second):
	}
}
func startClientNFQ(ctx context.Context, bin string, args []string, queue string, seconds int) (*clientNFQ, error) {
	if seconds < 1 {
		return nil, fmt.Errorf("test expired")
	}
	// Independent watchdog survives a crashed worker, including after setuid.
	wrapper := `seconds="$1"; shift
"$@" &
child=$!
(sleep "$seconds"; kill -TERM "$child" 2>/dev/null; sleep 2; kill -KILL "$child" 2>/dev/null) </dev/null >/dev/null 2>&1 &
timer=$!
trap 'kill "$child" "$timer" 2>/dev/null || true' EXIT
trap 'exit 0' TERM INT
wait "$child"
exit $?
`
	argv := append([]string{"-c", wrapper, "purewrt-client-nfq", strconv.Itoa(seconds), bin}, args...)
	cmd := exec.CommandContext(ctx, "sh", argv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	log := &limitedBuffer{limit: 8192}
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &clientNFQ{cmd: cmd, done: make(chan error, 1)}
	go func() { p.done <- cmd.Wait() }()
	select {
	case err := <-p.done:
		p.stop()
		return nil, fmt.Errorf("nfqws startup failed: %v: %s", err, log.String())
	case <-time.After(300 * time.Millisecond):
	}
	q, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if err == nil {
		for _, line := range strings.Split(string(q), "\n") {
			f := strings.Fields(line)
			if len(f) > 0 && f[0] == queue {
				return p, nil
			}
		}
	}
	p.stop()
	return nil, fmt.Errorf("nfqws did not attach queue %s", queue)
}

// Replace only queue destinations in one nft transaction. Existing client
// bypass, marks, WAN routes, offload guard, counters and timeout sets stay intact.
func clientSwitchNFT(post, incoming, queue string) (string, error) {
	if queue != clientTestQueue && queue != "9910" {
		return "", fmt.Errorf("invalid client queue %q", queue)
	}
	var b strings.Builder
	count := 0
	for _, chain := range []struct{ name, body string }{{"post", post}, {"incoming", incoming}} {
		for _, line := range strings.Split(chain.body, "\n") {
			expr, handle, ok := strings.Cut(strings.TrimSpace(line), " # handle ")
			if !ok || !strings.Contains(expr, "queue flags bypass to ") {
				continue
			}
			if _, err := strconv.ParseUint(strings.TrimSpace(handle), 10, 64); err != nil {
				return "", err
			}
			fields := strings.Fields(expr)
			for i := 0; i+4 < len(fields); i++ {
				if fields[i] == "queue" && fields[i+1] == "flags" && fields[i+2] == "bypass" && fields[i+3] == "to" {
					if fields[i+4] != "9908" && fields[i+4] != "9910" {
						return "", fmt.Errorf("unexpected client queue %s", fields[i+4])
					}
					fields[i+4] = queue
					count++
				}
			}
			fmt.Fprintf(&b, "replace rule inet %s %s handle %s %s\n", clientTestName, chain.name, strings.TrimSpace(handle), strings.Join(fields, " "))
		}
	}
	if count != 3 {
		return "", fmt.Errorf("expected three client queue rules, found %d", count)
	}
	return b.String(), nil
}
func (m Manager) switchClientNFQ(ctx context.Context, r commandRunner, bin, queue string, req clientSwitchRequest, expires int64) (*clientNFQ, error) {
	candidates, err := clientTestCandidates(ZapretClientOptions{Candidate: req.Candidate, Extra: req.Extra, Manual: req.Manual}, m.ZapretCandidates())
	if err != nil {
		return nil, err
	}
	args, err := m.clientTestArgs(candidates, queue)
	if err != nil {
		return nil, err
	}
	// Refuse an occupied spare queue before touching any live rules.
	if q, e := os.ReadFile("/proc/net/netfilter/nfnetlink_queue"); e == nil {
		for _, line := range strings.Split(string(q), "\n") {
			f := strings.Fields(line)
			if len(f) > 0 && f[0] == queue {
				return nil, fmt.Errorf("spare queue %s is busy", queue)
			}
		}
	}
	next, err := startClientNFQ(ctx, bin, args, queue, int(time.Until(time.Unix(expires, 0)).Seconds()))
	if err != nil {
		return nil, err
	}
	installed := false
	defer func() {
		if !installed {
			next.stop()
		}
	}()
	post, err := r.Run("nft", "-a", "list", "chain", "inet", clientTestName, "post")
	if err != nil {
		return nil, err
	}
	incoming, err := r.Run("nft", "-a", "list", "chain", "inet", clientTestName, "incoming")
	if err != nil {
		return nil, err
	}
	script, err := clientSwitchNFT(post, incoming, queue)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if _, err = os.Stat(clientTestPath(".stop")); err == nil {
		return nil, fmt.Errorf("test is stopping")
	}
	path := clientTestPath(".switch-nft")
	if err = system.AtomicWrite(path, []byte(script), 0600); err != nil {
		return nil, err
	}
	defer os.Remove(path)
	select {
	case err := <-next.done:
		return nil, fmt.Errorf("replacement nfqws exited before switch: %v", err)
	default:
	}
	if out, err := r.Run("nft", "-f", path); err != nil {
		return nil, fmt.Errorf("switch queue: %s: %w", out, err)
	}
	installed = true
	return next, nil
}
