package checker

import (
	"context"
	"io"
	"net/http"
	"time"
)

// ThroughputResult is one real data-transfer measurement. Unlike a mihomo
// url-test (which GETs an empty 204 body and so measures only RTT/TTFB), this
// drives N bytes through the supplied http.Client and reports the achieved
// rate — the signal that distinguishes "node answers a probe" from "node
// actually carries data". Bytes/Seconds are populated even when the transfer
// times out mid-stream, so a stalled link reports its real (near-zero) rate
// rather than a bare error.
type ThroughputResult struct {
	OK         bool    `json:"ok"`
	HTTPStatus int     `json:"http_status,omitempty"`
	Bytes      int64   `json:"bytes"`
	Seconds    float64 `json:"seconds"`
	Kbps       float64 `json:"kbps"` // kilobits per second (bytes*8/1000/seconds)
	Error      string  `json:"error,omitempty"`
}

// ThroughputProbe drives a real transfer through client and measures the rate.
//   - download (isUpload=false): GET url, read+count the full body.
//   - upload   (isUpload=true):  POST nbytes of zeroes to url.
//
// The caller supplies the client — pass a proxied client (provider.NewClient
// with ProxyURL=mihomo mixed-port) to probe the proxy path, or a plain client
// for the direct baseline. ctx bounds the whole transfer; on deadline the
// partial byte count + elapsed time still yield a meaningful rate.
func ThroughputProbe(ctx context.Context, client *http.Client, url string, isUpload bool, nbytes int64) ThroughputResult {
	if isUpload {
		return uploadProbe(ctx, client, url, nbytes)
	}
	return downloadProbe(ctx, client, url)
}

func downloadProbe(ctx context.Context, client *http.Client, url string) ThroughputResult {
	var res ThroughputResult
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	resp, err := client.Do(req)
	if err != nil {
		res.Seconds = time.Since(start).Seconds()
		res.Error = err.Error()
		return res
	}
	defer func() { _ = resp.Body.Close() }()
	res.HTTPStatus = resp.StatusCode
	n, cerr := io.Copy(io.Discard, resp.Body)
	res.Seconds = time.Since(start).Seconds()
	res.Bytes = n
	res.Kbps = kbps(n, res.Seconds)
	if cerr != nil {
		res.Error = cerr.Error()
	}
	res.OK = resp.StatusCode >= 200 && resp.StatusCode < 300 && cerr == nil && n > 0
	return res
}

func uploadProbe(ctx context.Context, client *http.Client, url string, nbytes int64) ThroughputResult {
	var res ThroughputResult
	start := time.Now()
	body := &countingReader{r: io.LimitReader(zeroReader{}, nbytes)}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.ContentLength = nbytes
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	// body.n counts bytes the transport actually read from us = bytes sent,
	// valid even when Do errors out on a mid-upload timeout.
	res.Bytes = body.n
	res.Seconds = time.Since(start).Seconds()
	res.Kbps = kbps(res.Bytes, res.Seconds)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	res.HTTPStatus = resp.StatusCode
	res.OK = resp.StatusCode >= 200 && resp.StatusCode < 300 && body.n > 0
	return res
}

func kbps(bytes int64, seconds float64) float64 {
	if seconds <= 0 {
		return 0
	}
	return float64(bytes) * 8 / 1000 / seconds
}

// zeroReader yields an endless stream of NUL bytes (capped by io.LimitReader).
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// countingReader tallies bytes read through it — used to measure how many
// upload bytes actually left the box even if the request is cut short.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
