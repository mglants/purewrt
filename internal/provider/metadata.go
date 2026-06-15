package provider

import (
	"encoding/json"
	"os"
	"time"

	"github.com/purewrt/purewrt/internal/system"
)

type Metadata struct {
	URLRedacted  string    `json:"url_redacted"`
	LastUpdate   time.Time `json:"last_update"`
	LastSuccess  time.Time `json:"last_success"`
	EntryCount   int       `json:"entry_count"`
	Checksum     string    `json:"checksum"`
	ErrorMessage string    `json:"error_message,omitempty"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	// Subscription-userinfo data, parsed from the RFC-ish header many proxy
	// panels emit (`upload=NNN; download=NNN; total=NNN; expire=unix_ts`).
	// Zero values mean the header was absent. SubExpire being non-zero and
	// within 7 days is what triggers the LuCI banner / doctor warning.
	SubExpire    time.Time `json:"sub_expire,omitempty"`
	SubUsedBytes int64     `json:"sub_used_bytes,omitempty"`
	SubTotalBytes int64    `json:"sub_total_bytes,omitempty"`
}

func WriteMetadata(path string, meta Metadata) error {
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return system.AtomicWrite(path+".meta.json", append(b, '\n'), 0600)
}

func ReadMetadata(path string) (Metadata, error) {
	b, err := os.ReadFile(path + ".meta.json")
	if err != nil {
		return Metadata{}, err
	}
	var meta Metadata
	if err := json.Unmarshal(b, &meta); err != nil {
		return Metadata{}, err
	}
	return meta, nil
}
