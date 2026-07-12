package manager

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/purewrt/purewrt/internal/mesh"
)

// MeshInfo is the /mesh/v1/info payload: the material fields a friend needs
// to consume this router's exit. No credential material travels — the ss
// password derives from (group PSK, hwid), both of which the peer already
// holds after this exchange. hwid is the immutable identity; node_name is a
// display label that may change.
type MeshInfo struct {
	V           int    `json:"v"`
	HWID        string `json:"hwid"`
	NodeName    string `json:"node_name"`
	ExitOffered bool   `json:"exit_offered"`
	ListenPort  int    `json:"listen_port"`
}

// MeshInfoHandler serves the overlay-only mesh API (mounted on its own
// listener at APIMeshPort; the fw4 mesh zone limits reachability to
// pwmesh0). Every request must carry a fresh HMAC (group-PSK-derived key,
// 120s window, nonce replay cache); every response body is signed so a
// spoofed responder without the PSK can't inject peers.
func (m Manager) MeshInfoHandler() http.Handler {
	nonces := mesh.NewNonceCache(4096, mesh.MaxClockSkew)
	mux := http.NewServeMux()
	mux.HandleFunc("/mesh/v1/info", func(w http.ResponseWriter, r *http.Request) {
		c, err := m.Load()
		if err != nil || !c.MeshActive() {
			http.Error(w, "mesh inactive", http.StatusServiceUnavailable)
			return
		}
		psk, err := hex.DecodeString(c.Mesh.PSK)
		if err != nil || len(psk) == 0 {
			http.Error(w, "mesh inactive", http.StatusServiceUnavailable)
			return
		}
		key := mesh.DeriveAPIKey(psk)
		ts, err := strconv.ParseInt(r.Header.Get(mesh.HeaderTime), 10, 64)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		nonce := r.Header.Get(mesh.HeaderNonce)
		mac := r.Header.Get(mesh.HeaderMAC)
		if err := mesh.VerifyRequest(key, time.Now(), ts, nonce, r.Method, r.URL.Path, mac, nonces); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := json.Marshal(MeshInfo{V: 1, HWID: c.Mesh.HWID, NodeName: c.Mesh.NodeName, ExitOffered: c.Mesh.ExitEnabled, ListenPort: c.Mesh.ListenPort})
		if err != nil {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Response MAC binds to the request's ts+nonce: a captured response
		// can't be replayed against a different probe.
		w.Header().Set(mesh.HeaderMAC, mesh.SignResponse(key, ts, nonce, body))
		_, _ = w.Write(body)
	})
	return mux
}
