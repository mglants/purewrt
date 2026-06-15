package system

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

const DefaultOutputLimit = 256 * 1024

type Runner struct {
	DryRun  bool
	Timeout time.Duration
	MaxOut  int64
}

func (r Runner) Run(name string, args ...string) (string, error) {
	return r.RunContext(context.Background(), name, args...)
}

func (r Runner) RunContext(parent context.Context, name string, args ...string) (string, error) {
	if r.DryRun {
		return name + " " + join(args), nil
	}
	t := r.Timeout
	if t == 0 {
		t = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, t)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	limit := r.MaxOut
	if limit == 0 {
		limit = DefaultOutputLimit
	}
	out := &limitedBuffer{limit: limit}
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	text := out.String()
	if ctx.Err() == context.DeadlineExceeded {
		return text, fmt.Errorf("command timed out after %s", t)
	}
	if out.Truncated() {
		text += "\n[output truncated]"
	}
	return text, err
}

type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int64
	written   int64
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.written += int64(len(p))
	remaining := b.limit - int64(b.buf.Len())
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.truncated = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) String() string { return b.buf.String() }
func (b *limitedBuffer) Truncated() bool {
	return b.truncated || b.written > b.limit
}

var _ io.Writer = (*limitedBuffer)(nil)

func join(a []string) string {
	return strings.Join(a, " ")
}
