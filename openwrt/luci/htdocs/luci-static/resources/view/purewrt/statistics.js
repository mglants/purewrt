'use strict';
'require view';
'require rpc';
'require uci';
'require purewrt.styles';
'require purewrt.format as fmt';

var callStatistics = rpc.declare({ object: 'purewrt', method: 'statistics' });
var callTrafficSample = rpc.declare({ object: 'purewrt', method: 'mihomo_traffic_sample' });
var callConfigState = rpc.declare({ object: 'purewrt', method: 'config_state' });

// humanAgo / humanUptime / pill live in purewrt.format — shared with
// general.js and subscriptions.js.
var humanAgo = fmt.humanAgo, humanUptime = fmt.humanUptime, pill = fmt.pill;

// formatBps renders mihomo's bytes-per-second traffic counter as a
// human-friendly rate. Mihomo's /traffic emits the up/down delta per
// sample window (currently 1s) so the raw value is already a rate.
function formatBps(bytes) {
  bytes = Number(bytes || 0);
  if (bytes < 1024) return bytes + ' B/s';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KiB/s';
  if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + ' MiB/s';
  return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GiB/s';
}

// formatBytes pretty-prints a raw byte count for static (non-rate) values
// — e.g. cache size, nftset payload bytes. Always picks the largest unit
// that keeps the number under 1024.
function formatBytes(bytes) {
  bytes = Number(bytes || 0);
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KiB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + ' MiB';
  return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GiB';
}

// formatCount adds thousands separators so an 81 k entry count is
// legible at a glance.
function formatCount(n) {
  n = Number(n || 0);
  return n.toLocaleString('en-US');
}

function yesNoPill(flag) {
  return flag ? pill(_('yes'), 'ok') : pill(_('no'), 'muted');
}

function actionPill(action) {
  if (!action) return pill('-', 'muted');
  switch (String(action).toLowerCase()) {
    case 'proxy':  return pill(_('proxy'), 'info');
    case 'direct': return pill(_('direct'), 'ok');
    case 'reject': return pill(_('reject'), 'danger');
    case 'zapret': return pill(_('zapret'), 'warn');
    case 'vpn':    return pill(_('vpn'), 'warn');
    default:       return pill(action, 'muted');
  }
}

// liveTrafficPanel builds a self-updating panel that polls
// mihomo_traffic_sample every 2 seconds, drawing the last N samples as a
// tiny inline sparkline plus a current-rate readout. Stops the timer
// when the user navigates away (the DOM node leaves the document).
function liveTrafficPanel() {
  var SAMPLES = 60; // ~2 minutes at 2s cadence
  var POLL_MS = 2000;
  var up = E('span', { 'class': 'purewrt-stat-value purewrt-stat-up' }, '0 B/s');
  var down = E('span', { 'class': 'purewrt-stat-value purewrt-stat-down' }, '0 B/s');
  var conns = E('span', { 'class': 'purewrt-stat-value' }, '0');
  var totalUp = E('span', { 'class': 'purewrt-stat-value purewrt-stat-up' }, '0 B');
  var totalDown = E('span', { 'class': 'purewrt-stat-value purewrt-stat-down' }, '0 B');
  var peak = E('div', { 'class': 'purewrt-text-dim', 'style': 'margin-top:.25em' }, '');
  var sparkline = E('canvas', { 'width': 480, 'height': 80, 'style': 'background:#1a1a1a;border-radius:4px;display:block' });
  var emptyHint = E('div', { 'class': 'purewrt-sparkline-empty' }, _('Collecting samples…'));
  var hist = [];
  var peakUp = 0, peakDown = 0;
  // Cumulative bytes since page open — mihomo's /traffic samples report
  // bytes-per-second, so each tick contributes `rate * POLL_seconds`.
  var cumUp = 0, cumDown = 0;

  function draw() {
    var ctx = sparkline.getContext('2d');
    if (!ctx) return;
    var w = sparkline.width, h = sparkline.height;
    ctx.clearRect(0, 0, w, h);
    // Baseline grid — quiet horizontal lines so the empty/idle state
    // doesn't render as just a black square.
    ctx.strokeStyle = 'rgba(255,255,255,0.05)';
    ctx.lineWidth = 1;
    [0.25, 0.5, 0.75].forEach(function(f) {
      ctx.beginPath();
      ctx.moveTo(0, h * f);
      ctx.lineTo(w, h * f);
      ctx.stroke();
    });
    if (!hist.length) return;
    var max = 1;
    hist.forEach(function(s) { if (s.up > max) max = s.up; if (s.down > max) max = s.down; });
    var step = w / SAMPLES;
    function plot(key, color) {
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      hist.forEach(function(s, i) {
        var x = (SAMPLES - hist.length + i) * step;
        var y = h - (s[key] / max) * (h - 4) - 2;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }
    plot('up', '#5cb85c');
    plot('down', '#5bc0de');
  }

  function tick() {
    if (!sparkline.isConnected) return; // user navigated away
    return callTrafficSample().then(function(s) {
      s = s || {};
      var u = Number(s.up || 0), d = Number(s.down || 0);
      up.innerText = formatBps(u);
      down.innerText = formatBps(d);
      conns.innerText = String(s.connections_total || 0);
      hist.push({ up: u, down: d });
      if (hist.length > SAMPLES) hist.shift();
      if (u > peakUp) peakUp = u;
      if (d > peakDown) peakDown = d;
      // /traffic emits bytes/sec; multiply by the poll window to integrate
      // a rough running total. Drops sub-poll bursts but is good enough to
      // show "we've moved a few hundred MiB this session".
      cumUp += u * (POLL_MS / 1000);
      cumDown += d * (POLL_MS / 1000);
      totalUp.innerText = formatBytes(cumUp);
      totalDown.innerText = formatBytes(cumDown);
      peak.innerText = _('peak ↑ %s · peak ↓ %s').format(formatBps(peakUp), formatBps(peakDown));
      if (hist.length >= 2) emptyHint.style.display = 'none';
      draw();
    }).catch(function() {
      // Mihomo not running yet, or metrics_enabled is off — fail silent.
    }).finally(function() {
      if (sparkline.isConnected) setTimeout(tick, POLL_MS);
    });
  }

  setTimeout(tick, 100); // kick first sample right after mount
  draw(); // paint the empty baseline immediately

  return E('div', { 'class': 'purewrt-card' }, [
    E('h3', {}, _('Live traffic (via mihomo /traffic)')),
    E('p', { 'class': 'purewrt-text-dim' }, _('Polled every 2 seconds. Requires <code>metrics_enabled</code> = 1 in /etc/config/purewrt for the underlying purewrt-api endpoints to be reachable.')),
    E('div', { 'class': 'purewrt-stat-grid' }, [
      E('div', {}, [ E('div', { 'class': 'purewrt-stat-label' }, _('↑ Upload')), up ]),
      E('div', {}, [ E('div', { 'class': 'purewrt-stat-label' }, _('↓ Download')), down ]),
      E('div', {}, [ E('div', { 'class': 'purewrt-stat-label' }, _('Active connections')), conns ]),
      E('div', {}, [ E('div', { 'class': 'purewrt-stat-label' }, _('↑ Total (session)')), totalUp ]),
      E('div', {}, [ E('div', { 'class': 'purewrt-stat-label' }, _('↓ Total (session)')), totalDown ])
    ]),
    E('div', { 'class': 'purewrt-sparkline-wrap' }, [ sparkline, emptyHint ]),
    peak
  ]);
}

function dataTable(headers, rows) {
  // headers: [ string | {label, numeric: true} ]
  var ths = headers.map(function(h) {
    var label = (h && h.label !== undefined) ? h.label : h;
    var cls = (h && h.numeric) ? 'num' : null;
    return E('th', cls ? { 'class': cls } : {}, label);
  });
  var body = rows.map(function(row) {
    return E('tr', {}, row.map(function(cell, i) {
      var spec = headers[i];
      var cls = (spec && spec.numeric) ? 'num' : (spec && spec.cls) ? spec.cls : null;
      var content = (cell && cell.nodeType) ? cell : (cell == null || cell === '') ? '' : String(cell);
      return E('td', cls ? { 'class': cls } : {}, content);
    }));
  });
  if (!rows.length) {
    body.push(E('tr', {}, [
      E('td', { 'colspan': String(headers.length), 'class': 'muted', 'style': 'text-align:center;font-style:italic' }, _('No entries'))
    ]));
  }
  return E('table', { 'class': 'purewrt-table' }, [
    E('thead', {}, [ E('tr', {}, ths) ]),
    E('tbody', {}, body)
  ]);
}

function secToTimeString(value) {
  value = Number(value || 0);
  if (!value)
    return '-';

  var hours = Math.floor(value / 3600);
  var mins = Math.floor((value % 3600) / 60);
  var sec = value % 60;
  var out = [];

  if (hours > 0)
    out.push(hours + _('h'));
  if (mins > 0)
    out.push(mins + _('m'));
  out.push(sec + _('s'));

  return out.join(' ');
}

function providerRows(items) {
  return (items || []).map(function(p) {
    var errCell = p.error ? E('span', { 'class': 'err' }, p.error) : E('span', { 'class': 'muted' }, '');
    return [
      p.name,
      yesNoPill(!!p.enabled),
      p.section || E('span', { 'class': 'muted' }, '-'),
      actionPill(p.action),
      formatCount(p.entry_count),
      p.last_success || p.last_update || E('span', { 'class': 'muted' }, '-'),
      errCell
    ];
  });
}

function vpnRows(items) {
  return (items || []).map(function(v) {
    return [
      v.name,
      yesNoPill(!!v.enabled),
      v.interface || E('span', { 'class': 'muted' }, '-'),
      v.route_table || E('span', { 'class': 'muted' }, '-'),
      yesNoPill(!!v.ok),
      v.error ? E('span', { 'class': 'err' }, v.error) : ''
    ];
  });
}

function nftRows(items) {
  // Match-set / Description / Packets / Traffic / Entries.
  // The legacy "Bytes" column (set memory footprint via `len(raw)`) was
  // dropped — it measured the JSON payload size, not anything operators
  // care about. Replaced by Packets+Traffic from named counters that
  // actually reflect matched traffic since last apply.
  return (items || []).map(function(n) {
    return [
      n.set,
      n.description || E('span', { 'class': 'muted' }, '-'),
      formatCount(n.hit_packets),
      formatBytes(n.hit_bytes),
      formatCount(n.entries)
    ];
  });
}

// counterWindowNote shows the user how long since the last apply, so the
// raw counter values have meaningful context. Counters reset on every
// `nft -f` apply (atomic table replace zeroes them), so this is essentially
// the "uptime" of the current rule generation.
function counterWindowNote(state) {
  state = state || {};
  var applied = Number(state.applied_unix || 0);
  if (!applied) return null;
  return E('p', { 'class': 'purewrt-text-dim' },
    _('Packets/Traffic are per-rule counters since last apply (%s ago). Atomic ruleset swap resets them on every apply.').format(humanAgo(applied)));
}

function dnsmasqSections(items) {
  items = items || [];
  if (!items.length)
    return E('p', { 'class': 'purewrt-text-muted' }, _('No DNSMasq sets reported'));

  return E('div', {}, items.map(function(d, idx) {
    var loaded = d.loaded && !d.error;
    var entries = Number(d.entries || 0);
    var hitPackets = Number(d.hit_packets || 0);
    var hitBytes = Number(d.hit_bytes || 0);
    // Auto-open the first 2 populated sets, plus any populated set with
    // fewer than 20 entries (fits on screen). Big sets stay collapsed to
    // avoid scrolling 100+ lines per set.
    var autoOpen = loaded && entries > 0 && (idx < 2 || entries < 20);
    var rows = loaded ? (d.items || []).map(function(i) {
      return [ i.ip || E('span', { 'class': 'muted' }, '-'), secToTimeString(i.timeout) ];
    }) : [];
    if (!rows.length && !loaded)
      rows = [[ E('span', { 'class': 'muted' }, _('not loaded')), E('span', { 'class': 'err' }, d.error || '-') ]];

    var summary = E('summary', {}, [
      d.set || '-',
      E('span', { 'class': 'purewrt-text-dim', 'style': 'margin-left:.6em;font-weight:normal' },
        '%s: %s%s · %s: %s · %s: %s'.format(
          _('entries'), formatCount(entries), d.limited ? '+' : '',
          _('packets'), formatCount(hitPackets),
          _('traffic'), formatBytes(hitBytes)))
    ]);
    var body = E('div', { 'class': 'purewrt-collapse-body' }, [
      dataTable([
        _('IP address'),
        { label: _('Timeout'), numeric: true }
      ], rows)
    ]);
    return E('details', autoOpen ? { 'class': 'purewrt-collapse', 'open': '' } : { 'class': 'purewrt-collapse' }, [ summary, body ]);
  }));
}

// applyBanner shows the last-applied timestamp, dirty flag, and auto-update
// cron schedule as a single status strip at the top of the page. Mirrors the
// banner on the Subscriptions page so operators see the same signal in both
// places. Hidden when there's literally nothing to report (fresh install).
function applyBanner(state, autoCron, autoEnabled) {
  state = state || {};
  var applied = Number(state.applied_unix || 0);
  var dirty = !!state.dirty;
  var hasCron = autoEnabled && autoCron;
  if (!applied && !dirty && !hasCron) return null;
  var parts = [];
  if (applied) parts.push(_('Last applied: %s ago').format(humanAgo(applied)));
  else parts.push(_('Never applied'));
  if (hasCron) parts.push(_('Auto-update: %s').format(autoCron));
  else if (autoCron) parts.push(_('Auto-update: %s (disabled)').format(autoCron));
  else parts.push(_('Auto-update: off'));
  if (dirty) parts.push(_('config has unapplied changes'));
  var variant = dirty ? 'warn' : 'ok';
  return E('div', { 'class': 'purewrt-banner purewrt-banner-' + variant }, parts.join(' · '));
}

// staleProviderBanner flags providers whose last_success is more than 24 h
// old. Returns null when everything's fresh so the strip doesn't render.
// Providers without a URL (inline manual lists, subscription-generated
// rule providers) have no remote source to download from, so the freshness
// check doesn't apply to them and they're skipped.
function staleProviderBanner(s) {
  var STALE_SEC = 24 * 3600;
  var nowSec = Math.floor(Date.now() / 1000);
  var stale = [];
  function check(items, kind) {
    (items || []).forEach(function(p) {
      if (!p.enabled) return;
      if (!p.url) return;
      var ts = parseProviderTime(p.last_success || p.last_update);
      if (!ts) {
        // URL is set but no success timestamp — never downloaded yet.
        stale.push({ kind: kind, name: p.name, ago: _('never') });
        return;
      }
      var age = nowSec - ts;
      if (age > STALE_SEC) stale.push({ kind: kind, name: p.name, ago: humanAgo(ts) });
    });
  }
  check(s.rule_providers, _('rule'));
  check(s.proxy_providers, _('proxy'));
  if (!stale.length) return null;
  var label = stale.map(function(x) { return x.name + ' (' + x.kind + ', ' + x.ago + ')'; }).join(', ');
  return E('div', { 'class': 'purewrt-banner purewrt-banner-warn' }, [
    E('strong', {}, _('Stale providers: ')),
    label,
    E('div', { 'class': 'purewrt-banner-sub' }, _('Last successful download more than 24h ago — check connectivity or run an update.'))
  ]);
}

// parseProviderTime parses the "02.01.2006-15:04" stamp emitted by
// formatTime() in internal/manager/statistics.go back into a unix timestamp.
// Returns 0 on failure so callers can treat that as "no data".
function parseProviderTime(s) {
  if (!s) return 0;
  var m = /^(\d{2})\.(\d{2})\.(\d{4})-(\d{2}):(\d{2})$/.exec(s);
  if (!m) return 0;
  // Constructor takes month as 0-indexed.
  var d = new Date(Number(m[3]), Number(m[2]) - 1, Number(m[1]), Number(m[4]), Number(m[5]));
  var t = Math.floor(d.getTime() / 1000);
  return isNaN(t) ? 0 : t;
}

function servicesCard(services) {
  var rows = (services || []).map(function(svc) {
    var running = svc.pid > 0;
    var statusCell = running ? pill(_('running'), 'ok') : pill(_('stopped'), 'danger');
    return [
      svc.name,
      statusCell,
      running ? String(svc.pid) : E('span', { 'class': 'muted' }, '-'),
      running ? humanUptime(svc.uptime_sec) : E('span', { 'class': 'muted' }, '-'),
      svc.started_unix ? new Date(svc.started_unix * 1000).toLocaleString() : E('span', { 'class': 'muted' }, '-')
    ];
  });
  return E('div', { 'class': 'purewrt-card' }, [
    E('h3', {}, _('Services')),
    dataTable([
      _('Name'),
      _('Status'),
      { label: _('PID'), numeric: true },
      _('Uptime'),
      _('Started')
    ], rows)
  ]);
}

function overviewCard(s) {
  var cache = s.cache || {};
  function kv(label, value) {
    return [ E('dt', {}, label), E('dd', {}, value) ];
  }
  return E('div', { 'class': 'purewrt-card' }, [
    E('h3', {}, _('Generation overview')),
    E('dl', { 'class': 'purewrt-kv' }, [].concat(
      kv(_('Last provider update'), s.last_update || E('span', { 'class': 'purewrt-text-muted' }, '-')),
      kv(_('Resource profile'), s.resource_profile || '-'),
      kv(_('Cache mode'), cache.mode || '-'),
      kv(_('Cache directory'), cache.dir || '-'),
      kv(_('Cache entries'), formatCount(cache.entries)),
      kv(_('Cache size'), formatBytes(cache.bytes)),
      kv(_('Skipped subscription rule imports'), formatCount(s.skipped_subscription_rule_imports))
    ))
  ]);
}

function providersCard(title, items) {
  return E('div', { 'class': 'purewrt-card' }, [
    E('h3', {}, title),
    dataTable([
      _('Name'),
      _('Enabled'),
      _('Section'),
      _('Action'),
      { label: _('Entries'), numeric: true },
      _('Last success'),
      _('Error')
    ], providerRows(items))
  ]);
}

return view.extend({
  // load resolves the three independent data sources in parallel: the big
  // statistics RPC, the cheap config_state RPC (last-applied + dirty), and
  // the UCI config (cron schedule + enable flag). LuCI calls load() before
  // render() and passes the result through.
  load: function() {
    return Promise.all([
      callStatistics().catch(function() { return {}; }),
      callConfigState().catch(function() { return {}; }),
      uci.load('purewrt').catch(function() { return null; })
    ]);
  },

  render: function(data) {
    var s = data && data[0] || {};
    var state = data && data[1] || {};
    var autoCron = uci.get('purewrt', 'settings', 'auto_update_cron') || '';
    var autoEnabled = uci.get('purewrt', 'settings', 'auto_update_enabled') !== '0';
    // LuCI's E() stringifies null children to the literal text "null", so
    // filter them out before composing the page.
    var children = [
      E('h2', {}, _('PureWRT Statistics')),
      applyBanner(state, autoCron, autoEnabled),
      staleProviderBanner(s),
      liveTrafficPanel(),
      overviewCard(s),
      servicesCard(s.services),
      providersCard(_('Rule providers'), s.rule_providers),
      providersCard(_('Proxy providers'), s.proxy_providers),
      E('div', { 'class': 'purewrt-card' }, [
        E('h3', {}, _('VPN routes')),
        dataTable([
          _('Name'),
          _('Enabled'),
          _('Interface'),
          _('Route table'),
          _('OK'),
          _('Error')
        ], vpnRows(s.vpn_routes))
      ]),
      E('div', { 'class': 'purewrt-card' }, [
        E('h3', {}, _('Nftables sets')),
        counterWindowNote(state),
        dataTable([
          _('Match-set'),
          _('Description'),
          { label: _('Packets'), numeric: true },
          { label: _('Traffic'), numeric: true },
          { label: _('Entries'), numeric: true }
        ], nftRows(s.nftables))
      ]),
      E('div', { 'class': 'purewrt-card' }, [
        E('h3', {}, _('Dnsmasq sets')),
        E('p', { 'class': 'purewrt-text-dim' }, _('Per-section dynamic IP sets populated by dnsmasq via nftset directives. Counter window resets on every apply. Large sets collapsed by default; click a row to expand.')),
        dnsmasqSections(s.dnsmasq)
      ])
    ];
    return E('div', { 'class': 'cbi-map' }, children.filter(function(c) { return c != null; }));
  }
});
