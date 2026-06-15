package manager

import (
	"context"
	"time"

	"github.com/purewrt/purewrt/internal/ipdb"
)

// IPDBUpdate refreshes the ip2asn dataset with the same download tactics
// as provider fetches: bootstrap DoH client (+ optional update-via-proxy)
// first, one retry through the local mihomo proxy on failure.
func (m Manager) IPDBUpdate(ctx context.Context) (ipdb.UpdateResult, error) {
	c, err := m.Load()
	if err != nil {
		return ipdb.UpdateResult{}, err
	}
	path := ipdb.DownloadPath(c.Settings.Workdir)
	primary, fallback := updaterClients(c, 5*time.Minute)
	res, err := ipdb.Update(ctx, path, primary)
	if err != nil && fallback != nil {
		res, err = ipdb.Update(ctx, path, fallback)
	}
	return res, err
}
