'use strict';
'require view';
'require rpc';
'require ui';
'require purewrt.manual_rule_modal as manualModal';
'require purewrt.styles';

// Client Traffic — observe a LAN client's blocked flows in real time.
//
// The backend (`purewrt client-traffic --live --json`) writes one NDJSON
// event per line to /tmp/purewrt-client-traffic.log. This view polls
// `client_traffic_status` every 2 s with an offset cursor, advances the
// cursor by `next_offset`, and dispatches each parsed event to the
// matching panel renderer. Six event types:
//   - conntrack-snapshot: replace the flow table
//   - dns-query / dns-reply: append to the DNS panel
//   - icmp-unreachable / tcp-rst / quic-retry: append to Rejection panel
//   - tls-sni / quic-sni: enrich hostnames in any existing flow rows
//   - warning: surface inline at the top
//
// Sessions are bounded by the backend's --max-seconds (default 300, cap 600).
// beforeunload calls _stop best-effort so closing the tab terminates the
// tcpdump processes; the time cap is the safety net.

var callStart  = rpc.declare({ object: 'purewrt', method: 'client_traffic_start',
                               params: [ 'ip', 'max_seconds', 'live' ] });
var callStatus = rpc.declare({ object: 'purewrt', method: 'client_traffic_status',
                               params: [ 'offset' ] });
var callStop   = rpc.declare({ object: 'purewrt', method: 'client_traffic_stop' });
var callLeases = rpc.declare({ object: 'luci-rpc', method: 'getDHCPLeases' });
// tcpdump is an optional dependency: the live capture shells out to it. When
// absent we show a yellow "not installed" banner (mirrors the zapret pattern)
// and disable the capture button. expect:{installed:false} so an ACL/permission
// hiccup degrades to "assume missing" (banner shown) rather than throwing.
var callTcpdumpInstalled = rpc.declare({ object: 'purewrt', method: 'tcpdump_installed', expect: { installed: false } });
var callIpdbStatus       = rpc.declare({ object: 'purewrt', method: 'ipdb_status' });
var callIpdbUpdateStart  = rpc.declare({ object: 'purewrt', method: 'ipdb_update_start' });
var callIpdbUpdateStatus = rpc.declare({ object: 'purewrt', method: 'ipdb_update_status' });
// Shared "what does PureWRT think of this host?" lookup — the same backend
// the Diagnostics → Site check section uses. Reused verbatim here so users
// can probe arbitrary hostnames/IPs (e.g. one they just saw in a flow row)
// without leaving the Client Traffic page.
var callRuleCheck = rpc.declare({ object: 'purewrt', method: 'check', params: [ 'domain' ] });

// Mutable session state — set by the start handler, cleared by stop / unload.
var state = {
  ip: '',
  offset: 0,
  running: false,
  pollHandle: null,
  // flowsByKey is the cumulative view of every flow we've seen during the
  // session, keyed by (proto, dst_ip, dst_port, src_port). The backend emits
  // delta snapshots (only flows that changed in the last tick), so a
  // tick-replace would make low-traffic clients flicker between empty and
  // populated. The cumulative map gives a stable, growing table — like a
  // packet-capture view, not a CPU monitor.
  flowsByKey: {},
  // selectedKeys tracks which flowKeys the user has checked for batch add.
  // Persists across ticks so the selection stays stable while new data
  // arrives — re-rendering preserves it because checkbox state is computed
  // from this map, not from the DOM.
  selectedKeys: {},
  dnsQueries: [],
  rejections: [],
  hostnames: {},  // map[ip] -> hostname (last-seen wins; learned from dns-reply + SNI)
  startedAt: 0,
  maxSeconds: 0,
  // showBogons toggles whether private/loopback/multicast/broadcast/CGNAT/
  // test-net destinations are listed. Off by default — those are noise for
  // the "what's blocked externally" question (KDE Connect broadcasts, mDNS,
  // self-traffic). User flips it on to debug LAN-side issues.
  showBogons: false,
};

function flowKey(f) {
  return f.proto + '|' + f.dest_ip + ':' + f.dest_port + '|' + (f.src_port || 0);
}

// flowList returns the rows the user should see right now, sorted with the
// most-interesting first (UNREPLIED → LOPSIDED → high traffic). Honours the
// showBogons toggle: when off, drops bogon-destination flows entirely (they
// won't be the answer to "what's blocked externally").
function flowList() {
  var arr = [];
  Object.keys(state.flowsByKey).forEach(function(k) {
    var f = state.flowsByKey[k];
    if (!state.showBogons && f.bogon) return;
    arr.push(f);
  });
  arr.sort(function(a, b) {
    if ((a.unreplied ? 1 : 0) !== (b.unreplied ? 1 : 0)) return b.unreplied ? 1 : -1;
    if ((a.stalled ? 1 : 0) !== (b.stalled ? 1 : 0))     return b.stalled ? 1 : -1;
    if ((a.frozen ? 1 : 0) !== (b.frozen ? 1 : 0))       return b.frozen ? 1 : -1;
    if ((a.lopsided ? 1 : 0) !== (b.lopsided ? 1 : 0))   return b.lopsided ? 1 : -1;
    return (b.orig_packets || 0) - (a.orig_packets || 0);
  });
  return arr;
}

// hiddenBogonCount tells the user how many flows + rejection signals are
// currently filtered out, so the toggle has a clear "what am I losing?"
// signal next to it. Combines both panels into one number — they share
// the same toggle.
function hiddenBogonCount() {
  if (state.showBogons) return 0;
  var n = 0;
  Object.keys(state.flowsByKey).forEach(function(k) {
    if (state.flowsByKey[k].bogon) n++;
  });
  state.rejections.forEach(function(r) { if (r.bogon) n++; });
  return n;
}

function leaseOption(lease) {
  var label = lease.hostname ? lease.hostname + ' (' + lease.ipaddr + ')' : lease.ipaddr;
  return E('option', { 'value': lease.ipaddr }, [ label ]);
}

function isIPv4(s) {
  var m = String(s).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  for (var i = 1; i <= 4; i++) if (parseInt(m[i], 10) > 255) return false;
  return true;
}

// quicBlockedDests collects the destination IPs that fired a QUIC-retry
// rejection (client re-sent QUIC Initials with no usable reply). The tracker
// only emits once it crosses its retry threshold within the window, so a
// presence here = HTTP/3 / QUIC being DPI-blocked. Used to mark the matching
// UDP flow row BLOCKED even when the conntrack snapshot alone looks ambiguous
// (the flow-stalled heuristic and the QUIC-retry tracker run in separate
// goroutines and only converge here in the view).
function quicBlockedDests() {
  var set = {};
  state.rejections.forEach(function(r) {
    if (r.kind === 'QUIC retry' && r.dest_ip) set[r.dest_ip] = true;
  });
  return set;
}

// pillFor maps a flow status to a coloured pill. quicBlocked is the map from
// quicBlockedDests() so a UDP flow to a QUIC-blocked dest reads as BLOCKED.
function pillFor(flow, quicBlocked) {
  var danger = function(label, title) {
    return E('span', { 'class': 'purewrt-pill purewrt-pill-danger', 'title': title || '' }, label);
  };
  if (flow.unreplied) return danger('BLOCKED', _('No reply at all — the destination is silently dropping this client’s packets.'));
  if (flow.proto === 'udp' && quicBlocked && quicBlocked[flow.dest_ip])
    return danger('BLOCKED·QUIC', _('QUIC Initials were re-sent with no usable reply — HTTP/3 is being DPI-blocked. Route this destination through a proxy section instead of direct.'));
  if (flow.stalled)   return danger('BLOCKED·DPI', _('Handshake completed but no data came back — DPI/SNI drop after the handshake. Route this destination through a proxy section instead of direct.'));
  if (flow.frozen) {
    var kb = Math.round((flow.reply_bytes || 0) / 1024);
    return E('span', { 'class': 'purewrt-pill purewrt-pill-warn', 'title':
      _('Transfer received %d KB then stopped while the connection stayed open — possibly a DPI mid-stream cut if this destination is on your direct list. (Can also be a normal idle keep-alive connection.)').format(kb) }, 'STALLED');
  }
  if (flow.lopsided)  return E('span', { 'class': 'purewrt-pill purewrt-pill-warn' },   'LOPSIDED');
  if (flow.offload)   return E('span', { 'class': 'purewrt-pill purewrt-pill-info' },   'OFFLOAD');
  return E('span', { 'class': 'purewrt-pill purewrt-pill-ok' }, 'OK');
}

// renderLookupSection builds the free-form "give me a hostname or IP, tell
// me how PureWRT classifies it" probe. Reuses the same `check` backend the
// Diagnostics page uses — the output is the same text dump, rendered in a
// monospace block. Exposed here on Client Traffic so the user can probe a
// destination they just spotted in a flow row without page-hopping.
function renderLookupSection() {
  var input = E('input', {
    'type': 'text',
    'class': 'cbi-input-text',
    'placeholder': _('hostname or IPv4 (e.g. accounts.ea.com or 149.154.167.41)'),
    'style': 'width:32em',
    'data-role': 'lookup-input'
  });
  var out = E('pre', {
    'data-role': 'lookup-output',
    'style': 'margin-top:.5em;padding:.5em;background:#1a1a1a;color:#cfe;font-size:.85em;white-space:pre-wrap;max-height:24em;overflow-y:auto;display:none'
  });
  var btn = E('button', { 'class': 'btn cbi-button cbi-button-action' }, _('Check'));
  function run(query) {
    var q = (query == null ? input.value : query).trim();
    if (!q) {
      ui.addNotification(null, E('p', _('Enter a hostname or IPv4.')), 'warning');
      return;
    }
    input.value = q;
    out.textContent = _('Looking up %s…').format(q);
    out.style.display = '';
    btn.disabled = true;
    callRuleCheck(q).then(function(r) {
      out.textContent = (r && r.output) || JSON.stringify(r, null, 2);
    }, function(err) {
      out.textContent = _('Lookup failed: %s').format(String(err));
    }).finally(function() { btn.disabled = false; });
  }
  btn.addEventListener('click', function(ev) { ev.preventDefault(); run(); });
  input.addEventListener('keydown', function(ev) {
    if (ev.key === 'Enter') { ev.preventDefault(); run(); }
  });
  // Expose the run function on the container so per-row "lookup" buttons
  // can drive the same panel — avoids opening a modal per click and keeps
  // the user's existing query/output visible.
  var section = E('div', { 'data-role': 'lookup-section', 'class': 'cbi-section', 'style': 'margin-top:1em' }, [
    E('h3', {}, _('Lookup in rule providers')),
    E('p', { 'class': 'cbi-section-note' }, _(
      'Probe a hostname or IPv4 against the configured rule providers — same backend as Diagnostics → Site check. \
      Tells you which provider/section would route the destination, plus DNS resolution, nftset membership, and mihomo node.')),
    E('div', { 'style': 'display:flex;gap:.5em;align-items:center;flex-wrap:wrap' }, [ input, btn ]),
    out
  ]);
  section.__runLookup = run;
  return section;
}

// triggerLookup is what the per-row "check" buttons call. Routes the click
// to the page's single lookup section, which keeps the output panel
// stateful instead of spawning a modal per check.
function triggerLookup(query) {
  var section = document.querySelector('[data-role="lookup-section"]');
  if (section && typeof section.__runLookup === 'function') {
    section.__runLookup(query);
    section.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

function lookupButton(query) {
  if (!query) return E([]);
  var btn = E('button', {
    'class': 'btn cbi-button',
    'style': 'font-size:.85em;padding:.2em .5em;margin-right:.3em',
    'title': _('Check this destination in rule providers (same as Lookup section above).')
  }, [ '🔍' ]);
  btn.addEventListener('click', function(ev) { ev.preventDefault(); triggerLookup(query); });
  return btn;
}

// addToManualButton — per-row "+ manual" affordance. When the row carries
// an ASN (set by backend enrichment), the modal grows a "whole-AS" radio
// option that fans out to every CIDR the ipdb attributes to that AS. The
// caller passes opts.asn + opts.asOrg so the modal can label the choice;
// the modal itself is responsible for the ipdb_asn RPC lookup.
function addToManualButton(host, asn, asOrg, country) {
  if (!host) return E([]);
  var btn = E('button', {
    'class': 'btn cbi-button cbi-button-action',
    'style': 'font-size:.85em;padding:.2em .5em',
    'title': asn
      ? _('Route this hostname (or its entire AS) through a PureWRT section.')
      : _('Route this hostname through a PureWRT section via a manual rule provider.')
  }, [ '+ ', _('manual') ]);
  btn.addEventListener('click', function(ev) {
    ev.preventDefault();
    manualModal.openManualPicker({ entry: host, asn: asn, asOrg: asOrg, country: country });
  });
  return btn;
}

function renderFlowsPanel(container) {
  var rows = flowList();
  container.innerHTML = '';
  // Always render the batch toolbar — even with zero rows — so the user
  // sees the affordance up-front and we don't reflow the layout when the
  // first flow arrives.
  container.appendChild(renderBatchToolbar());
  if (!rows.length) {
    container.appendChild(E('p', { 'class': 'cbi-section-note' }, _('Waiting for traffic …')));
    return;
  }
  // Header row: leading checkbox column for "select all", then the data cols.
  var hdrAll = E('input', { 'type': 'checkbox', 'title': _('Select all visible') });
  hdrAll.addEventListener('change', function() {
    rows.forEach(function(f) {
      if (hdrAll.checked) state.selectedKeys[flowKey(f)] = true;
      else delete state.selectedKeys[flowKey(f)];
    });
    renderFlowsPanel(container);
  });
  // Reflect the "all selected" state visually so the indeterminate case
  // doesn't show a stale checkmark after the user manually toggles one row.
  var allSelected = rows.length > 0 && rows.every(function(f) { return state.selectedKeys[flowKey(f)]; });
  hdrAll.checked = allSelected;
  var tbl = E('table', { 'class': 'table cbi-section-table', 'style': 'margin-top:.5em' }, [
    E('tr', { 'class': 'tr table-titles' }, [
      E('th', { 'class': 'th', 'style': 'width:2em' }, [ hdrAll ]),
      E('th', { 'class': 'th' }, _('Status')),
      E('th', { 'class': 'th' }, _('Proto')),
      E('th', { 'class': 'th' }, _('Destination')),
      E('th', { 'class': 'th' }, _('Hostname')),
      E('th', { 'class': 'th' }, _('Nftset')),
      E('th', { 'class': 'th' }, _('Pkts out/in')),
      E('th', { 'class': 'th' }, _('Bytes out/in')),
      E('th', { 'class': 'th' }, _('State')),
      E('th', { 'class': 'th' }, '')
    ])
  ]);
  var quicBlocked = quicBlockedDests();
  rows.forEach(function(f) {
    var host = f.hostname || state.hostnames[f.dest_ip] || '';
    var dest = f.dest_ip + ':' + f.dest_port;
    var key = flowKey(f);
    var cb = E('input', { 'type': 'checkbox', 'data-key': key });
    if (state.selectedKeys[key]) cb.checked = true;
    cb.addEventListener('change', function() {
      if (cb.checked) state.selectedKeys[key] = true;
      else delete state.selectedKeys[key];
      // Re-render only the toolbar so the count updates without scroll loss.
      var newToolbar = renderBatchToolbar();
      var oldToolbar = container.querySelector('[data-role="batch-toolbar"]');
      if (oldToolbar) container.replaceChild(newToolbar, oldToolbar);
    });
    tbl.appendChild(E('tr', { 'class': 'tr' }, [
      E('td', { 'class': 'td' }, [ cb ]),
      E('td', { 'class': 'td' }, [ pillFor(f, quicBlocked) ]),
      E('td', { 'class': 'td' }, f.proto.toUpperCase()),
      E('td', { 'class': 'td' }, [ renderDestCell(dest, f) ]),
      E('td', { 'class': 'td' }, host || '—'),
      E('td', { 'class': 'td' }, [ renderNftsetBadges(f.nftsets) ]),
      E('td', { 'class': 'td' }, (f.orig_packets || 0) + ' / ' + (f.reply_packets || 0)),
      E('td', { 'class': 'td' }, (f.orig_bytes || 0) + ' / ' + (f.reply_bytes || 0)),
      E('td', { 'class': 'td' }, f.state || (f.proto === 'udp' ? 'udp' : '')),
      E('td', { 'class': 'td' }, [
        lookupButton(host || f.dest_ip),
        // Manual-add button is always shown — users may want to route a
        // healthy flow proactively (e.g. force a working but slow CDN
        // through a specific section, or just bookmark a destination they
        // saw working today before it starts failing). Passes ASN context
        // through so the modal can offer whole-AS expansion when ipdb is
        // installed and the flow has been enriched.
        addToManualButton(host || f.dest_ip, f.asn, f.as_org, f.country)
      ])
    ]));
  });
  container.appendChild(tbl);
}

// renderBatchToolbar produces the "Add N selected" + "Clear selection"
// pair shown above the flow table. Lives in its own function because we
// re-render JUST this strip when a row's checkbox changes (cheap, keeps
// table scroll position stable on large captures).
function renderBatchToolbar() {
  var count = Object.keys(state.selectedKeys).length;
  var addBtn = E('button', {
    'class': 'btn cbi-button cbi-button-action',
    'disabled': count === 0 ? 'disabled' : null,
    'title': _('Open the batch picker pre-filled with all selected entries (hostname when known, otherwise IP).')
  }, [ '+ ', _('Add %d selected to manual').format(count) ]);
  addBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    var entries = [];
    var seen = {};
    flowList().forEach(function(f) {
      var k = flowKey(f);
      if (!state.selectedKeys[k]) return;
      var e = entryFor(f);
      if (!e || seen[e]) return;
      seen[e] = 1;
      entries.push(e);
    });
    if (!entries.length) return;
    manualModal.openManualBatchPicker({ entries: entries }).then(function(res) {
      if (res) {
        // Successful add — clear the selection so the user sees a clean slate.
        state.selectedKeys = {};
        var container = document.querySelector('[data-role="flows-panel"]');
        if (container) renderFlowsPanel(container);
      }
    });
  });
  var clearBtn = E('button', {
    'class': 'btn',
    'style': 'margin-left:.5em',
    'disabled': count === 0 ? 'disabled' : null
  }, _('Clear selection'));
  clearBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    state.selectedKeys = {};
    var container = document.querySelector('[data-role="flows-panel"]');
    if (container) renderFlowsPanel(container);
  });
  // Bogon visibility toggle. Default off because the common "Apex / game /
  // streaming is blocked" use case wants external destinations only — and
  // KDE-Connect / mDNS / SSDP broadcasts inside RFC1918 would just pad the
  // table with answers that aren't the question.
  var bogonCb = E('input', {
    'type': 'checkbox',
    'id': 'show-bogons-toggle',
    'style': 'margin-right:.3em'
  });
  if (state.showBogons) bogonCb.checked = true;
  bogonCb.addEventListener('change', function() {
    state.showBogons = bogonCb.checked;
    var flowsC = document.querySelector('[data-role="flows-panel"]');
    if (flowsC) renderFlowsPanel(flowsC);
    var rejC = document.querySelector('[data-role="rejections-panel"]');
    if (rejC) renderRejectionsPanel(rejC);
  });
  var hidden = hiddenBogonCount();
  var bogonLabel = E('label', {
    'for': 'show-bogons-toggle',
    'style': 'margin-left:1.5em;color:#888;cursor:pointer;user-select:none'
  }, [ bogonCb, hidden > 0
        ? _('Show local / broadcast traffic (%d hidden)').format(hidden)
        : _('Show local / broadcast traffic') ]);
  return E('div', {
    'data-role': 'batch-toolbar',
    'style': 'margin:.3em 0;display:flex;align-items:center'
  }, [ addBtn, clearBtn, bogonLabel ]);
}

function renderRejectionsPanel(container) {
  // Apply the same showBogons toggle as the Flows panel: router-rejecting-
  // self-traffic and LAN broadcast RSTs aren't "external blocking" answers.
  var visible = state.rejections.filter(function(r) {
    return state.showBogons || !r.bogon;
  });
  if (!visible.length) {
    container.innerHTML = '';
    var note = state.rejections.length
      ? _('No external rejection signals — %d local/bogon signals hidden. Toggle "Show local / broadcast traffic" above to see them.').format(state.rejections.length)
      : _('No rejection signals so far. ICMP unreachable / TCP RST / QUIC retry will surface here as they happen.');
    container.appendChild(E('p', { 'class': 'cbi-section-note' }, note));
    return;
  }
  // Group identical signals so a burst of packets to the same destination
  // collapses into one row with a count.
  var grouped = {};
  visible.forEach(function(r) {
    var k = r.kind + '|' + (r.dest || '');
    if (!grouped[k]) { grouped[k] = { sample: r, count: 0 }; }
    grouped[k].count++;
  });
  var keys = Object.keys(grouped).sort();
  var tbl = E('table', { 'class': 'table cbi-section-table' }, [
    E('tr', { 'class': 'tr table-titles' }, [
      E('th', { 'class': 'th' }, _('Kind')),
      E('th', { 'class': 'th' }, _('Destination')),
      E('th', { 'class': 'th' }, _('Hostname')),
      E('th', { 'class': 'th' }, _('Nftset')),
      E('th', { 'class': 'th' }, _('Detail')),
      E('th', { 'class': 'th' }, _('Count')),
      E('th', { 'class': 'th' }, '')
    ])
  ]);
  keys.forEach(function(k) {
    var g = grouped[k]; var r = g.sample;
    var host = r.hostname || state.hostnames[r.dest_ip] || '';
    // Build the Destination cell with the ASN/CC subline same as flow rows
    // — same enrichment shape, same renderer.
    var destFake = { dest_ip: r.dest_ip, asn: r.asn, as_org: r.as_org, country: r.country };
    tbl.appendChild(E('tr', { 'class': 'tr' }, [
      E('td', { 'class': 'td' }, E('span', { 'class': 'purewrt-pill purewrt-pill-danger' }, r.kind)),
      E('td', { 'class': 'td' }, [ renderDestCell(r.dest || '—', destFake) ]),
      E('td', { 'class': 'td' }, host || '—'),
      E('td', { 'class': 'td' }, [ renderNftsetBadges(r.nftsets) ]),
      E('td', { 'class': 'td' }, r.detail || ''),
      E('td', { 'class': 'td' }, String(g.count)),
      E('td', { 'class': 'td' }, [
        lookupButton(host || (r.dest_ip || '')),
        addToManualButton(host || (r.dest_ip || ''), r.asn, r.as_org, r.country)
      ])
    ]));
  });
  container.innerHTML = '';
  container.appendChild(tbl);
}

function renderDNSPanel(container) {
  if (!state.dnsQueries.length) {
    container.innerHTML = '';
    container.appendChild(E('p', { 'class': 'cbi-section-note' }, _('No DNS queries yet. If the client uses DoH/DoT, queries won’t appear here — hostnames still recover via TLS/QUIC SNI extraction.')));
    return;
  }
  var last = state.dnsQueries.slice(-30);
  var tbl = E('table', { 'class': 'table cbi-section-table' }, [
    E('tr', { 'class': 'tr table-titles' }, [
      E('th', { 'class': 'th' }, _('Type')),
      E('th', { 'class': 'th' }, _('Hostname')),
      E('th', { 'class': 'th' }, _('Answers'))
    ])
  ]);
  last.forEach(function(q) {
    tbl.appendChild(E('tr', { 'class': 'tr' }, [
      E('td', { 'class': 'td' }, q.qtype + (q.source === 'mdns' ? ' (mdns)' : '')),
      E('td', { 'class': 'td' }, q.hostname),
      E('td', { 'class': 'td' }, (q.answers || []).join(', '))
    ]));
  });
  container.innerHTML = '';
  container.appendChild(tbl);
}

// Event dispatch — applies one parsed NDJSON event to the in-memory state
// and re-renders only the affected panel. Called from the poll loop with
// each tick's freshly-arrived events.
function applyEvent(ev, doms) {
  var d = ev.data || {};
  switch (ev.type) {
    case 'conntrack-snapshot':
      // Merge: every flow in the snapshot updates / inserts its entry in the
      // cumulative map. Entries not present in this tick stay visible — they
      // may simply be idle, and there's no signal that they've ended.
      (d.flows || []).forEach(function(f) { state.flowsByKey[flowKey(f)] = f; });
      renderFlowsPanel(doms.flows);
      if (d.skipped_ipv6) {
        doms.warning.textContent = _('Heads up: %d IPv6 flows from this client are not shown (IPv4-only in v1).').format(d.skipped_ipv6);
        doms.warning.style.display = '';
      }
      break;
    case 'dns-query':
      state.dnsQueries.push({ qtype: d.qtype, hostname: d.hostname, source: d.source, answers: [] });
      renderDNSPanel(doms.dns);
      break;
    case 'dns-reply':
      // Backfill answers onto the most-recent query for the same hostname.
      for (var i = state.dnsQueries.length - 1; i >= 0; i--) {
        if (state.dnsQueries[i].hostname === d.hostname) {
          state.dnsQueries[i].answers = d.answers || [];
          break;
        }
      }
      (d.answers || []).forEach(function(a) { state.hostnames[a] = d.hostname; });
      renderDNSPanel(doms.dns);
      renderFlowsPanel(doms.flows);   // hostnames may have changed
      break;
    case 'tls-sni':
    case 'quic-sni':
      state.hostnames[d.dest] = d.sni;
      renderFlowsPanel(doms.flows);
      break;
    case 'icmp-unreachable':
      state.rejections.push({
        kind: 'ICMP ' + (d.code_text || ('code ' + d.code)) + (d.source ? ' (' + d.source + ')' : ''),
        dest: d.original_dest ? (d.original_proto + '://' + d.original_dest + ':' + d.original_port) : d.from,
        dest_ip: d.original_dest || d.from,
        hostname: d.hostname || state.hostnames[d.original_dest || d.from] || '',
        detail: 'from ' + d.from,
        bogon: !!d.bogon,
        nftsets: d.nftsets || [],
        asn: d.asn || 0,
        as_org: d.as_org || '',
        country: d.country || '',
      });
      renderRejectionsPanel(doms.rejections);
      break;
    case 'tcp-rst':
      state.rejections.push({
        kind: 'TCP RST (' + d.source + ')',
        dest: d.from + ':' + d.from_port,
        dest_ip: d.from,
        hostname: d.hostname || state.hostnames[d.from] || '',
        detail: '→ ' + d.to + ':' + d.to_port,
        bogon: !!d.bogon,
        nftsets: d.nftsets || [],
        asn: d.asn || 0,
        as_org: d.as_org || '',
        country: d.country || '',
      });
      renderRejectionsPanel(doms.rejections);
      break;
    case 'quic-retry':
      state.rejections.push({
        kind: 'QUIC retry',
        dest: d.dest + ':' + d.dest_port,
        dest_ip: d.dest,
        hostname: d.hostname || state.hostnames[d.dest] || '',
        detail: d.initial_count + ' initials in ' + d.window_seconds + 's, no reply',
        bogon: !!d.bogon,
        nftsets: d.nftsets || [],
        asn: d.asn || 0,
        as_org: d.as_org || '',
        country: d.country || '',
      });
      renderRejectionsPanel(doms.rejections);
      break;
    case 'warning':
      doms.warning.textContent = d.message || '';
      doms.warning.style.display = '';
      break;
    case 'error':
      ui.addNotification(null, E('p', d.message || _('client-traffic error')), 'danger');
      break;
  }
}

function clearState() {
  state.flowsByKey = {};
  state.selectedKeys = {};
  state.dnsQueries = [];
  state.rejections = [];
  state.hostnames = {};
  state.offset = 0;
}

// entryFor returns the string to write into the manual rule provider for a
// flow: hostname when we recovered one (via DNS reply or TLS SNI), else the
// destination IP. Matches the user's intent: "if dns found we should add it
// via dns, if not via ip address."
function entryFor(f) {
  return f.hostname || state.hostnames[f.dest_ip] || f.dest_ip;
}

// renderDestCell stacks the dest IP:port on top of a tiny grey ASN/country
// subline. Empty subline when no IPDB enrichment — the line is hidden
// rather than showing "AS 0", to keep the table compact for users who
// haven't installed the database.
function renderDestCell(dest, f) {
  var children = [ E('div', {}, dest) ];
  if (f.asn || f.country) {
    var label = '';
    if (f.asn) label += 'AS' + f.asn;
    if (f.country) label += (label ? ' · ' : '') + f.country;
    if (f.as_org) label += ' · ' + f.as_org;
    children.push(E('div', {
      'style': 'font-size:.75em;color:#999;margin-top:.1em',
      'title': f.as_org || ''
    }, label));
  }
  return E('div', {}, children);
}

// renderNftsetBadges shows the section memberships for a destination as
// small pills. Two flavours are visually distinguishable:
//   - "proxy_X"     — static IP/CIDR match from a rule provider
//   - "dns_proxy_X" — dnsmasq-resolved domain hit (the "user actually
//                     typed this hostname" signal; rendered with reduced
//                     opacity so the static membership pops first)
// Empty means "default route" — useful negative signal.
function renderNftsetBadges(sets) {
  if (!sets || !sets.length) return E('span', { 'style': 'color:#888' }, '—');
  return E('span', {}, sets.map(function(s) {
    var cls = 'purewrt-pill purewrt-pill-muted';
    var style = 'margin-right:.2em;font-size:.8em';
    var isDNS = s.indexOf('dns_') === 0;
    var base = isDNS ? s.slice(4) : s;
    if (base === 'direct')      cls = 'purewrt-pill purewrt-pill-info';
    else if (base === 'reject') cls = 'purewrt-pill purewrt-pill-danger';
    else if (base.indexOf('proxy_') === 0) cls = 'purewrt-pill purewrt-pill-ok';
    if (isDNS) style += ';opacity:.7;font-style:italic';
    return E('span', { 'class': cls, 'style': style, 'title': isDNS
      ? _('Dynamic — dnsmasq resolved a domain to this IP. Expires with the DNS TTL.')
      : _('Static — this IP matched a CIDR/IP rule in a rule provider.')
    }, s);
  }));
}

function stopPolling() {
  if (state.pollHandle) {
    window.clearTimeout(state.pollHandle);
    state.pollHandle = null;
  }
  state.running = false;
}

function pollOnce(doms) {
  return callStatus(String(state.offset)).then(function(resp) {
    var events = (resp && resp.events) || [];
    events.forEach(function(ev) { applyEvent(ev, doms); });
    var nextOff = parseInt((resp && resp.next_offset) || '0', 10);
    if (!isNaN(nextOff)) state.offset = nextOff;
    var running = Number(resp && resp.running);
    if (running !== 0) return true;
    // Backend exited — stop polling.
    return false;
  });
}

function pollLoop(doms) {
  if (!state.running) return;
  pollOnce(doms).then(function(stillRunning) {
    updateCountdown(doms);
    if (stillRunning && state.running) {
      state.pollHandle = window.setTimeout(function() { pollLoop(doms); }, 2000);
    } else {
      finishSession(doms, _('Capture finished.'));
    }
  }, function(err) {
    ui.addNotification(null, E('p', String(err)), 'danger');
    finishSession(doms, _('Polling error.'));
  });
}

function updateCountdown(doms) {
  if (!state.maxSeconds || !state.startedAt) {
    doms.countdown.textContent = '';
    return;
  }
  var rem = Math.max(0, Math.round(state.maxSeconds - (Date.now() - state.startedAt) / 1000));
  doms.countdown.textContent = _('Auto-stop in %ds').format(rem);
}

function finishSession(doms, label) {
  stopPolling();
  doms.startBtn.disabled = false;
  doms.stopBtn.disabled = true;
  doms.status.textContent = label;
  doms.countdown.textContent = '';
}

function startSession(doms) {
  var ip = doms.ipSelect.value || doms.ipInput.value;
  if (!isIPv4(ip)) {
    ui.addNotification(null, E('p', _('Please pick or enter a valid IPv4 address.')), 'warning');
    return;
  }
  var maxSeconds = parseInt(doms.durationInput.value, 10) || 60;
  if (maxSeconds < 10) maxSeconds = 10;
  if (maxSeconds > 600) maxSeconds = 600;
  clearState();
  state.ip = ip;
  state.maxSeconds = maxSeconds;
  state.startedAt = Date.now();
  state.running = true;
  doms.startBtn.disabled = true;
  doms.stopBtn.disabled = false;
  doms.status.textContent = _('Capturing from %s …').format(ip);
  doms.warning.style.display = 'none';
  renderFlowsPanel(doms.flows);
  renderDNSPanel(doms.dns);
  renderRejectionsPanel(doms.rejections);
  callStart(ip, String(maxSeconds), '1').then(function() {
    state.pollHandle = window.setTimeout(function() { pollLoop(doms); }, 500);
  }, function(err) {
    finishSession(doms, _('Start failed: %s').format(String(err)));
  });
}

function stopSession(doms) {
  if (!state.running) return;
  callStop().then(function() { /* polling loop will see running=0 next tick */ },
                  function() { /* best effort */ });
  finishSession(doms, _('Stopped.'));
}

// renderIpdbBanner shows the offline IP database status as a thin strip
// near the page header. Three visual states:
//   - Not installed → "Install (~7 MB)" CTA
//   - Installed     → "ASN db: N ranges, refreshed X days ago | Refresh"
//   - Stale (>30 d) → same + amber tint to encourage refresh
//
// The download is async (one full body fetch, can take 10–30 s on slow
// uplinks) so the button kicks off ipdb_update_start and we poll
// ipdb_update_status every 2 s until rc lands. UI is replaced in-place
// once the update settles.
function renderIpdbBanner(initial) {
  var banner = E('div', {
    'data-role': 'ipdb-banner',
    'style': 'margin:.5em 0;padding:.5em .8em;border-radius:4px;font-size:.9em;display:flex;align-items:center;gap:.6em'
  });
  applyIpdbBanner(banner, initial);
  return banner;
}

function applyIpdbBanner(banner, status) {
  banner.innerHTML = '';
  banner.style.background = '#1f3a3a';
  banner.style.color = '#cfe';
  var installed = status && status.installed;
  var stale     = installed && (status.age_days || 0) > 30;
  if (stale) {
    banner.style.background = '#3a3220';
    banner.style.color      = '#fec';
  }
  var label;
  if (!installed) {
    banner.style.background = '#322';
    banner.style.color = '#f99';
    label = _('IP database not installed — without it, flow rows show no ASN / country / org. Source: iptoasn.com (public domain, ~7 MB).');
  } else {
    var size = Math.round((status.size_bytes || 0) / 1024 / 1024 * 10) / 10;
    label = _('IP database installed (%s MB, refreshed %d days ago).').format(size, status.age_days || 0);
  }
  banner.appendChild(E('span', { 'style': 'flex:1' }, label));

  var btn = E('button', {
    'class': 'btn cbi-button ' + (installed ? '' : 'cbi-button-action'),
  }, installed ? _('Refresh') : _('Install (~7 MB)'));
  btn.addEventListener('click', function(ev) {
    ev.preventDefault();
    btn.disabled = true;
    btn.textContent = _('Downloading…');
    callIpdbUpdateStart().then(function() {
      var started = Date.now();
      var deadline = Date.now() + 5 * 60 * 1000;
      function poll() {
        callIpdbUpdateStatus().then(function(s) {
          if (Date.now() > deadline) {
            ui.addNotification(null, E('p', _('ipdb-update timed out')), 'danger');
            applyIpdbBanner(banner, status);
            return;
          }
          if (Number(s && s.running) === 1) {
            btn.textContent = _('Downloading… %ds').format(Math.round((Date.now() - started) / 1000));
            window.setTimeout(poll, 2000);
            return;
          }
          // Done. Re-query status to refresh the banner with fresh stats.
          callIpdbStatus().then(function(fresh) { applyIpdbBanner(banner, fresh); });
          ui.addNotification(null, E('p', _('IP database refreshed. Restart any in-progress capture to pick up the new data.')), 'info');
        }, function(err) {
          ui.addNotification(null, E('p', _('ipdb-update poll failed: %s').format(String(err))), 'danger');
          applyIpdbBanner(banner, status);
        });
      }
      window.setTimeout(poll, 500);
    }, function(err) {
      ui.addNotification(null, E('p', _('ipdb-update start failed: %s').format(String(err))), 'danger');
      applyIpdbBanner(banner, status);
    });
  });
  banner.appendChild(btn);
}

return view.extend({
  render: function() {
    return Promise.all([
      callLeases(),
      callIpdbStatus().catch(function() { return null; }),
      callTcpdumpInstalled().catch(function() { return false; })
    ]).then(function(results) {
      var leases = results[0];
      var ipdbInitial = results[1];
      // expect:{installed:false} already unwraps the RPC to the bare boolean,
      // so results[2] IS the value (not an object — don't read .installed).
      var tcpdumpInstalled = !!results[2];
      var ipv4 = ((leases && leases.dhcp_leases) || []).slice().sort(function(a, b) {
        return (a.ipaddr || '').localeCompare(b.ipaddr || '');
      });

      var ipSelect = E('select', { 'class': 'cbi-input-select' }, [
        E('option', { 'value': '' }, [ _('-- choose a DHCP client --') ])
      ].concat(ipv4.map(leaseOption)));
      var ipInput = E('input', {
        'type': 'text', 'class': 'cbi-input-text',
        'placeholder': _('or type a static IPv4 (e.g. 192.168.1.50)'),
        'style': 'margin-left:.5em;width:18em'
      });
      var durationInput = E('input', {
        'type': 'number', 'class': 'cbi-input-text', 'min': '10', 'max': '600',
        'value': '60', 'style': 'width:6em'
      });
      var startBtn = E('button', { 'class': 'btn cbi-button cbi-button-action' }, _('Start live capture'));
      var stopBtn  = E('button', { 'class': 'btn cbi-button cbi-button-remove', 'disabled': 'disabled' }, _('Stop'));
      var status   = E('span', { 'style': 'margin-left:1em;font-style:italic' }, _('Idle.'));
      var countdown = E('span', { 'style': 'margin-left:1em;color:#666' });
      var warning  = E('div', { 'class': 'alert-message warning', 'style': 'display:none;margin:1em 0' });
      var ipdbBanner = renderIpdbBanner(ipdbInitial);

      // Optional-dependency warning (mirrors the Zapret "not installed" banner).
      // Live capture needs tcpdump; without it, disable the start button and
      // explain how to install. The rest of the page (lookup, IPDB) still works.
      var tcpdumpBanner = E('div', {});
      if (!tcpdumpInstalled) {
        startBtn.setAttribute('disabled', 'disabled');
        tcpdumpBanner = E('div', {
          'class': 'alert-message warning',
          'style': 'margin:1em 0;padding:1em 1.2em;display:flex;flex-direction:column;gap:.4em'
        }, [
          E('strong', {}, _('tcpdump is not installed on this router.')),
          E('p', { 'style': 'margin:.2em 0' }, _(
            'Live packet capture for a client needs the optional tcpdump package. \
            Without it this page can still resolve domains and show the IP-to-ASN database, \
            but the Start live capture button is disabled.')),
          E('p', { 'style': 'margin:.2em 0' }, [
            _('To install on OpenWrt 25.12 (apk-based): '),
            E('code', { 'style': 'background:#21262d;padding:.1em .4em;border-radius:3px' }, 'apk add tcpdump-mini'),
            _(' — then reload this page.')
          ])
        ]);
      }

      var flowsContainer  = E('div', { 'data-role': 'flows-panel', 'style': 'margin-top:.5em' });
      var rejectContainer = E('div', { 'data-role': 'rejections-panel', 'style': 'margin-top:.5em' });
      var dnsContainer    = E('div', { 'style': 'margin-top:.5em' });

      var doms = {
        ipSelect: ipSelect, ipInput: ipInput, durationInput: durationInput,
        startBtn: startBtn, stopBtn: stopBtn, status: status, countdown: countdown,
        warning: warning,
        flows: flowsContainer, rejections: rejectContainer, dns: dnsContainer,
      };
      startBtn.addEventListener('click', function(ev) { ev.preventDefault(); startSession(doms); });
      stopBtn.addEventListener('click',  function(ev) { ev.preventDefault(); stopSession(doms); });
      window.addEventListener('beforeunload', function() {
        // Best effort — closing the tab terminates tcpdump via the backend's
        // SIGTERM handler. The --max-seconds cap is the safety net if the
        // RPC doesn't arrive (network blip, etc.).
        if (state.running) callStop();
      });

      renderFlowsPanel(flowsContainer);
      renderRejectionsPanel(rejectContainer);
      renderDNSPanel(dnsContainer);

      return E('div', {}, [
        E('h2', {}, _('Client Traffic')),
        E('p', { 'class': 'cbi-section-note' }, _(
          'Live diagnostic for a single LAN client. Shows which destinations \
          its traffic is hitting, which flows are blocked or stalled, and the \
          rejection signals (ICMP unreachable, TCP RST, QUIC retry) that hint \
          at WHY. Works even for clients that don’t go through PureWRT — \
          the router sees every packet because it’s the default gateway.')),
        warning,
        tcpdumpBanner,
        ipdbBanner,
        E('div', { 'class': 'cbi-section', 'style': 'margin-top:1em' }, [
          E('div', { 'style': 'display:flex;align-items:center;gap:.5em;flex-wrap:wrap' }, [
            E('label', {}, _('Client:')), ipSelect, ipInput,
            E('label', { 'style': 'margin-left:1em' }, _('Duration (s):')), durationInput,
            startBtn, stopBtn, status, countdown
          ])
        ]),
        renderLookupSection(),
        E('h3', { 'style': 'margin-top:1.5em' }, _('Rejection signals (why)')),
        rejectContainer,
        E('h3', { 'style': 'margin-top:1.5em' }, _('Flows (what)')),
        flowsContainer,
        E('h3', { 'style': 'margin-top:1.5em' }, _('Recent DNS queries')),
        dnsContainer,
      ]);
    });
  },
  handleSave: null, handleSaveApply: null, handleReset: null
});
