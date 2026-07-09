'use strict';
'require view';
'require rpc';
'require ui';
'require uci';
'require purewrt.dpi_check_async as dpiCheckAsync';
'require purewrt.manual_rule_modal as manualModal';
'require purewrt.styles';
'require purewrt.format as fmt';

// hostOf extracts just the FQDN from a probe target string. Targets are
// formatted as "host:port" (with optional path), so we split on the first
// colon and ignore everything after. Returns the raw string when no colon
// is present (already a bare host).
function hostOf(target) {
  if (!target) return '';
  var t = String(target).trim();
  var colon = t.indexOf(':');
  return colon >= 0 ? t.slice(0, colon) : t;
}

// addToManualButton returns a small inline button that opens the manual
// rule provider picker pre-filled with the row's hostname. Shared between
// the blocked / suggested-fix columns so a user can route around an issue
// with one click without leaving the page.
function addToManualButton(target) {
  var host = hostOf(target);
  if (!host) return E([]);
  var btn = E('button', {
    'class': 'btn cbi-button cbi-button-action',
    'style': 'font-size:.85em;padding:.2em .5em',
    'title': _('Open the manual rule provider picker prefilled with this hostname so you can route it through a proxy/direct/reject section.')
  }, [ '+ ', _('manual') ]);
  btn.addEventListener('click', function(ev) {
    ev.preventDefault();
    manualModal.openManualPicker({ entry: host });
  });
  return btn;
}

// "What's blocked right now" — bulk runs the same DNS→TCP→TLS→HTTP probe
// ladder that `purewrt doctor --canaries --report` exposes on the CLI.
// Two list semantics, modelled after rkn-block-checker:
//   - whitelist: control sites that should always work (gosuslugi, ya.ru,
//     sberbank). If most fail, the network itself is broken and the overall
//     verdict drops to "inconclusive".
//   - blacklist: suspected-blocked sites (instagram, twitter, protonvpn).
//     Failures here, weighted by confidence level, drive the verdict.
//
// The overall verdict banner combines the two so non-experts get a single
// "your network is in a blocked zone (high confidence)" line rather than
// having to interpret per-target details.

var callBlocking = rpc.declare({ object: 'purewrt', method: 'blocking_heuristics', params: [ 'blacklist', 'whitelist' ] });

// Default lists mirror checker.DefaultWhitelistCanaries / DefaultBlacklistCanaries
// in internal/checker/blocking.go so behaviour matches the CLI on first load.
var DEFAULT_WHITELIST = [
  'www.gosuslugi.ru:443',
  'ya.ru:443',
  'www.sberbank.ru:443',
  'vk.com:443',
  'www.ozon.ru:443',
  'www.avito.ru:443',
  'lenta.ru:443',
  'rutube.ru:443'
];

var DEFAULT_BLACKLIST = [
  'www.instagram.com:443',
  'www.facebook.com:443',
  'x.com:443',
  'www.linkedin.com:443',
  'discord.com:443',
  'rutracker.org:443',
  'www.torproject.org:443',
  'protonvpn.com:443',
  'www.deepl.com:443',
  'www.patreon.com:443',
  'meduza.io:443',
  'www.dw.com:443'
];

// verdictPillClass maps a verdict string to one of the .purewrt-pill-<flavour>
// CSS classes defined in purewrt.styles. Aligned with the Go-side
// confidence/verdict labelling so the UI's visual severity matches what
// the backend says.
function verdictPillClass(v) {
  if (!v) return 'purewrt-pill-muted';
  if (v === 'ok') return 'purewrt-pill-ok';
  // Red: hard, high-confidence censorship signals.
  if (v === 'http_stub' || v === 'http_451' ||
      v === 'dns' || v.indexOf('rst') >= 0 || v.indexOf('refused') >= 0)
    return 'purewrt-pill-danger';
  // Orange: ambiguous timeouts / generic failures.
  if (v.indexOf('timeout') >= 0 || v.indexOf('fail') >= 0 || v === 'no-answer')
    return 'purewrt-pill-warn';
  // Blue: HTTP non-stub errors (status 4xx/5xx that aren't 451).
  if (v.indexOf('http_') === 0) return 'purewrt-pill-info';
  return 'purewrt-pill-muted';
}

function verdictPill(verdict) {
  return E('span', { 'class': 'purewrt-pill ' + verdictPillClass(verdict) }, (verdict || '-').toUpperCase());
}

// confidenceBadge renders the high/medium/low qualifier as a smaller pill.
// High = green outline, medium = amber, low = grey. Empty when the result
// hasn't been classified (e.g. probe never ran).
function confidenceBadge(c) {
  if (!c) return E('span', {}, '');
  return E('span', { 'class': 'purewrt-confidence purewrt-confidence-' + c }, c.toUpperCase());
}

// verdictHint maps a verdict to a one-line "what to try next" suggestion.
// Used per-row so non-experts know the likely fix without reading the
// Reason column. Kept terse so it fits in a table cell.
function verdictHint(verdict) {
  if (!verdict || verdict === 'ok') return '';
  switch (verdict) {
    case 'dns':              return _('Domain doesn\'t resolve via system DNS (dnsmasq → mihomo) — NXDOMAIN, a downed authoritative, or a DNS-level block.');
    case 'tcp_rst':          return _('TCP reset mid-connection — IP-level filter. Route this host through a proxy section.');
    case 'tcp_refused':      return _('Connection refused — destination not listening. Confirm host:port is correct.');
    case 'tcp_timeout':      return _('TCP timeout — IP block or upstream congestion. Try traceroute, then route via proxy.');
    case 'tcp_no_route':     return _('No route to host — interface/route table issue, not censorship. Check default route.');
    case 'tcp_fail':         return _('TCP error — see Reason column for details.');
    case 'tls_rst':          return _('TLS handshake reset — classic SNI-based DPI signature. Enable zapret with TLS fragmentation.');
    case 'tls_remote_error': return _('TLS remote-error alert — server-side rejection, possibly SNI filter. Try zapret or proxy.');
    case 'tls_timeout':      return _('TLS handshake timeout — DPI stalling. Try zapret or route via proxy.');
    case 'tls_fail':         return _('TLS handshake failed — see Reason. May indicate cert issue or DPI.');
    case 'http_error':       return _('HTTP request dropped mid-flight — try again or route via proxy.');
    case 'http_451':         return _('HTTP 451 — operator-mandated block by the host itself; routing alone will not help (change region/identity).');
    case 'http_stub':        return _('ISP served a "blocked by RKN" stub page instead of the real site — route through a proxy or change DNS to bypass.');
    case 'config':           return _('Probe config error (bad target format).');
  }
  if (verdict.indexOf('http_') === 0) return _('HTTP error status — server-side issue, not censorship.');
  return '';
}

// renderResults builds a tbody for one list (whitelist or blacklist). The
// column set is fixed across both tables so a user comparing them sees the
// same columns in the same order.
function renderResults(results, listLabel) {
  var body = E('tbody', {});
  if (!results || !results.length) {
    body.appendChild(E('tr', {}, E('td', { 'colspan': 7, 'class': 'purewrt-text-muted' }, _('No results yet.'))));
    return body;
  }
  results.forEach(function(r) {
    body.appendChild(E('tr', {}, [
      E('td', { 'style': 'font-family:monospace' }, r.target || ''),
      E('td', {}, verdictPill(r.verdict || '-')),
      E('td', {}, confidenceBadge(r.confidence)),
      E('td', {}, (r.latency_ms || 0) + ' ms'),
      E('td', { 'class': 'purewrt-text-muted', 'style': 'font-size:0.85em' }, r.reason || (r.notes && r.notes[0]) || ''),
      E('td', { 'class': 'purewrt-text-dim' }, verdictHint(r.verdict || '')),
      E('td', { 'style': 'text-align:right' }, addToManualButton(r.target))
    ]));
  });
  return body;
}

function makeResultsTable() {
  var thead = E('thead', {}, E('tr', {}, [
    E('th', {}, _('Target')),
    E('th', {}, _('Verdict')),
    E('th', {}, _('Confidence')),
    E('th', {}, _('Latency')),
    E('th', {}, _('Reason / note')),
    E('th', {}, _('Suggested fix')),
    E('th', {}, _('Route via'))
  ]));
  var body = E('tbody', {}, E('tr', {}, E('td', { 'colspan': 7, 'class': 'purewrt-text-muted' }, _('No results yet.'))));
  var table = E('table', { 'class': 'table cbi-section-table', 'style': 'margin-top:0.5em' }, [ thead, body ]);
  return { table: table, body: body };
}

// verdictBanner paints the overall report verdict into a single coloured
// strip at the top of the page. The four-state palette mirrors the Go
// computeOverallVerdict logic.
function verdictBanner(verdict, reason) {
  var cls = 'purewrt-banner-muted';
  var label = _('No verdict yet — click "Probe now".');
  if (verdict === 'blocked_zone_high') {
    cls = 'purewrt-banner-danger';
    label = _('Likely in a blocked zone (HIGH confidence)');
  } else if (verdict === 'blocked_zone_medium') {
    cls = 'purewrt-banner-warn';
    label = _('Likely in a blocked zone (medium confidence)');
  } else if (verdict === 'no_blocking_detected') {
    cls = 'purewrt-banner-ok';
    label = _('No blocking detected');
  } else if (verdict === 'inconclusive') {
    cls = 'purewrt-banner-muted';
    label = _('Inconclusive — baseline whitelist failing');
  }
  return E('div', { 'class': 'purewrt-banner ' + cls }, [
    E('strong', {}, label),
    reason ? E('div', { 'class': 'purewrt-banner-sub' }, reason) : E([])
  ]);
}

return view.extend({
  load: function() {
    return uci.load('purewrt');
  },

  render: function() {
    // Migration: older deployments saved a single combined list to
    // `blocking_canaries`. Use that as the initial blacklist when no
    // dedicated blacklist UCI value exists.
    // TODO(sunset 2026-Q4): drop this fallback and the matching unset()
    // call further down once every active deployment has had at least
    // one save through the new dual-list UI.
    var savedBlack = uci.get('purewrt', 'main', 'blocking_blacklist')
      || uci.get('purewrt', 'main', 'blocking_canaries') || '';
    var savedWhite = uci.get('purewrt', 'main', 'blocking_whitelist') || '';
    var initBlack = savedBlack ? savedBlack.split(/[,\s]+/).filter(Boolean) : DEFAULT_BLACKLIST;
    var initWhite = savedWhite ? savedWhite.split(/[,\s]+/).filter(Boolean) : DEFAULT_WHITELIST;

    var blackArea = E('textarea', {
      'class': 'cbi-input-textarea',
      'rows': 6,
      'style': 'width:30em;font-family:monospace',
      'placeholder': DEFAULT_BLACKLIST.join('\n')
    });
    blackArea.value = initBlack.join('\n');

    var whiteArea = E('textarea', {
      'class': 'cbi-input-textarea',
      'rows': 6,
      'style': 'width:30em;font-family:monospace',
      'placeholder': DEFAULT_WHITELIST.join('\n')
    });
    whiteArea.value = initWhite.join('\n');

    var bannerHolder = E('div', {}, verdictBanner('', ''));
    var whiteTable = makeResultsTable();
    var blackTable = makeResultsTable();
    var whiteSummary = E('p', { 'class': 'purewrt-text-muted', 'style': 'margin:0' }, '');
    var blackSummary = E('p', { 'class': 'purewrt-text-muted', 'style': 'margin:0' }, '');
    var lastRunAt = E('span', { 'class': 'purewrt-text-muted', 'style': 'font-size:0.85em' }, '');

    function splitTargets(area) {
      return (area.value || '').split(/[,\s]+/).map(function(t) { return t.trim(); }).filter(Boolean);
    }

    function renderReport(report) {
      var wh = (report && report.whitelist) || [];
      var bl = (report && report.blacklist) || [];
      var verdict = (report && report.verdict) || '';
      var reason = (report && report.reason) || '';

      bannerHolder.innerHTML = '';
      bannerHolder.appendChild(verdictBanner(verdict, reason));

      var newWhite = renderResults(wh, 'whitelist');
      whiteTable.body.parentNode.replaceChild(newWhite, whiteTable.body);
      whiteTable.body = newWhite;

      var newBlack = renderResults(bl, 'blacklist');
      blackTable.body.parentNode.replaceChild(newBlack, blackTable.body);
      blackTable.body = newBlack;

      var wOK = wh.filter(function(r) { return r.verdict === 'ok'; }).length;
      var bOK = bl.filter(function(r) { return r.verdict === 'ok'; }).length;
      whiteSummary.innerText = _('%d/%d control sites reachable').format(wOK, wh.length);
      blackSummary.innerText = _('%d/%d suspected-blocked sites reachable').format(bOK, bl.length);

      lastRunAt.innerText = _('Last run: %s').format(new Date().toLocaleTimeString());
    }

    var refreshTimer = null;
    var autoRefresh = E('input', { 'type': 'checkbox' });
    if ((uci.get('purewrt', 'main', 'blocking_autorefresh') || '') === '1') {
      autoRefresh.checked = true;
      refreshTimer = setInterval(function() { runProbe(); }, 5 * 60 * 1000);
    }
    autoRefresh.addEventListener('change', function() {
      if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
      if (autoRefresh.checked) refreshTimer = setInterval(runProbe, 5 * 60 * 1000);
      uci.set('purewrt', 'main', 'blocking_autorefresh', autoRefresh.checked ? '1' : '0');
      uci.save();
    });

    function runProbe() {
      var bl = splitTargets(blackArea);
      var wh = splitTargets(whiteArea);
      uci.set('purewrt', 'main', 'blocking_blacklist', bl.join(','));
      uci.set('purewrt', 'main', 'blocking_whitelist', wh.join(','));
      // Migration cleanup: clear the legacy combined-list option so it
      // doesn't drift out of sync with the new split storage.
      uci.unset('purewrt', 'main', 'blocking_canaries');
      uci.save();
      lastRunAt.innerHTML = ''; lastRunAt.appendChild(fmt.spinner(_('Probing…')));
      return callBlocking(bl, wh).then(function(r) {
        // New shim shape: {report: {whitelist, blacklist, verdict, reason}, results: [...]}.
        // Old shape: {results: [...]} → no report data, render flat as blacklist.
        var report = (r && r.report) || null;
        if (!report && r && (r.results || Array.isArray(r))) {
          report = { whitelist: [], blacklist: r.results || r, verdict: '', reason: '' };
        }
        renderReport(report || { whitelist: [], blacklist: [], verdict: 'inconclusive', reason: 'probe returned no data' });
      }, function(err) {
        ui.addNotification(null, E('p', _('Probe failed: %s').format(err && err.message ? err.message : String(err))), 'danger');
      });
    }

    var root = E('div', { 'class': 'cbi-map' }, [
      E('h2', _('What’s blocked right now')),
      E('p', {}, _('Runs the DNS → TCP → TLS → HTTP probe ladder against two target lists and classifies each failure. Whitelist sites are controls that should always work; blacklist sites are commonly censored. The verdict combines both: if the whitelist itself is failing, the network is broken (not censored), and the report says so plainly.')),
      bannerHolder,
      E('div', { 'class': 'cbi-section' }, [
        E('h3', _('Target lists')),
        E('p', { 'class': 'purewrt-text-muted' }, _('One <code>host:port</code> per line. Saved to UCI for next visit. Leave empty to fall back to curated defaults.')),
        E('div', { 'style': 'display:flex;gap:2em;flex-wrap:wrap' }, [
          E('div', {}, [
            E('label', { 'style': 'font-weight:bold' }, _('Whitelist (control)')),
            E('br'),
            whiteArea
          ]),
          E('div', {}, [
            E('label', { 'style': 'font-weight:bold' }, _('Blacklist (suspected blocked)')),
            E('br'),
            blackArea
          ])
        ]),
        E('br'),
        E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': function() { return runProbe(); } }, _('Probe now')),
        ' ',
        E('label', { 'style': 'margin-left:1em' }, [ autoRefresh, ' ', _('Auto-refresh every 5 minutes') ]),
        ' ',
        lastRunAt
      ]),
      E('div', { 'class': 'cbi-section' }, [
        E('h3', _('Whitelist (control sites — should always work)')),
        whiteSummary,
        whiteTable.table
      ]),
      E('div', { 'class': 'cbi-section' }, [
        E('h3', _('Blacklist (suspected blocked)')),
        blackSummary,
        blackTable.table
      ]),
      tcp1620Section()
    ]);

    // SPA-navigation cleanup: when LuCI swaps this view out of the DOM,
    // tear down the auto-refresh interval so we don't stack one per visit.
    // The closure scope already holds refreshTimer; observe the parent so
    // a removeChild on root triggers the cleanup.
    var stopRefresh = function() {
      if (refreshTimer !== null) { clearInterval(refreshTimer); refreshTimer = null; }
    };
    setTimeout(function() {
      var anchor = root.parentNode || document.body;
      var mo = new MutationObserver(function() {
        if (!document.body.contains(root)) { stopRefresh(); mo.disconnect(); }
      });
      mo.observe(anchor, { childList: true, subtree: true });
    }, 0);

    return root;
  }
});

// ---- TCP-16-20 advanced DPI probe ------------------------------------

// renderTCP1620 builds the result table for one host's matrix. Cells are
// kept terse so the matrix fits ~6 columns even on phones.
function renderTCP1620(report) {
  if (!report || !report.results) return E('p', {}, _('No probe results.'));
  var rows = report.results.slice().sort(function(a, b) {
    if (a.port !== b.port) return a.port - b.port;
    if (a.proto !== b.proto) return a.proto < b.proto ? -1 : 1;
    if ((a.tls_version || '') !== (b.tls_version || '')) return (a.tls_version || '') < (b.tls_version || '') ? -1 : 1;
    return 0;
  });
  var thead = E('thead', {}, E('tr', {}, [
    E('th', {}, _('Port')),
    E('th', {}, _('Proto')),
    E('th', {}, _('TLS')),
    E('th', {}, _('SNI')),
    E('th', {}, _('Host hdr')),
    E('th', {}, _('Alive')),
    E('th', {}, _('Waits-for-body')),
    E('th', {}, _('DPI'))
  ]));
  var tbody = E('tbody', {});
  rows.forEach(function(r) {
    var alive = r.alive
      ? E('span', { 'class': 'purewrt-text-success' }, '✓')
      : E('span', { 'class': 'purewrt-text-danger' }, r.alive_error || '✗');
    var waits = r.alive
      ? (r.server_waits
        ? E('span', { 'class': 'purewrt-text-success' }, _('yes'))
        : E('span', { 'class': 'purewrt-text-muted' }, _('no')))
      : E('span', { 'class': 'purewrt-text-muted' }, '-');
    var dpi;
    if (!r.alive) dpi = E('span', { 'class': 'purewrt-text-muted' }, '-');
    else if (r.dpi_detected) dpi = E('span', { 'class': 'purewrt-text-danger', 'style': 'font-weight:bold' }, _('detected'));
    else if (r.dpi_error) dpi = E('span', { 'class': 'purewrt-text-warn' }, r.dpi_error);
    else dpi = E('span', { 'class': 'purewrt-text-success' }, _('not detected'));
    tbody.appendChild(E('tr', {}, [
      E('td', {}, String(r.port)),
      E('td', {}, r.proto),
      E('td', { 'style': 'font-family:monospace' }, r.tls_version || '-'),
      E('td', { 'style': 'font-family:monospace' }, r.sni || '-'),
      E('td', { 'style': 'font-family:monospace' }, r.http_host || '-'),
      E('td', {}, alive),
      E('td', {}, waits),
      E('td', {}, dpi)
    ]));
  });
  var summary = E('p', {}, _('IP %s · %d/%d alive · %d DPI-detected').format(
    report.ip, report.alive_count || 0, report.results.length, report.dpi_detected_count || 0));
  return E('div', {}, [ summary, E('table', { 'class': 'table cbi-section-table' }, [ thead, tbody ]) ]);
}

function tcp1620Section() {
  var hostInput = E('input', {
    'class': 'cbi-input-text',
    'style': 'font-family:monospace;min-width:18em',
    'placeholder': 'www.google.com'
  });
  hostInput.value = uci.get('purewrt', 'main', 'dpi_check_host') || 'www.google.com';
  var statusLine = E('p', { 'class': 'purewrt-text-muted' }, _('Idle.'));
  var resultBox = E('div', {});
  function setStatus(s) { statusLine.innerText = s; }

  function runProbe() {
    var host = (hostInput.value || '').trim();
    if (!host) {
      ui.addNotification(null, E('p', _('Host required.')), 'warning');
      return;
    }
    uci.set('purewrt', 'main', 'dpi_check_host', host);
    uci.save();
    setStatus(_('Probing %s… this takes 1-3 minutes.').format(host));
    resultBox.innerHTML = ''; resultBox.appendChild(fmt.spinner(_('Probing %s…').format(host)));
    return dpiCheckAsync.run({ host: host }).then(function(r) {
      if (!r.ok) {
        setStatus(_('Probe failed (rc=%s).').format(r.rc));
        return;
      }
      setStatus(_('Done.'));
      resultBox.innerHTML = '';
      resultBox.appendChild(renderTCP1620(r.report || {}));
    }, function(err) {
      setStatus(_('Probe timed out: %s').format(err && err.message ? err.message : String(err)));
    });
  }

  return E('div', { 'class': 'cbi-section' }, [
    E('h3', _('Advanced DPI probe (TCP 16-20)')),
    E('p', {}, _('Sweeps the SNI / Host-header / TLS-version matrix against one target to fingerprint which bytes the censor is matching. Russian-style TSPU equipment often inspects bytes 16-20 of the TCP payload; by varying TLS version and SNI we shift different bytes into that window. Cells where DPI is detected tell you which combinations to avoid (or which zapret strategy to enable).')),
    E('label', {}, [ _('Host: '), hostInput ]),
    ' ',
    E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': runProbe }, _('Run TCP-16-20 probe')),
    statusLine,
    resultBox
  ]);
}
