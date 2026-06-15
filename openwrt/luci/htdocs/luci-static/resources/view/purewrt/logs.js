'use strict';
'require view';
'require rpc';
'require ui';

// PureWRT Logs view. Pulls 5 backend log streams from rpcd (each is a
// `logread | grep <pattern>` server-side), renders each in its own panel
// with independent per-panel filter / pause / copy controls. Auto-refreshes
// every POLL_MS while at least one panel is unpaused.
//
// State lives in plain JS objects (panel descriptors), not on DOM nodes —
// makes lifecycle reasoning easier and survives DOM rewrites cleanly.
// The MutationObserver at the bottom is the only deliberate DOM-side
// hook, and it's just for tearing down the poll loop when LuCI navigates
// away (LuCI caches view modules and re-calls render() on revisit, so
// without explicit teardown we'd stack interval handlers).

var callLogs = rpc.declare({
  object: 'purewrt',
  method: 'logs',
  params: [ 'source' ],
  expect: { output: '' }
});

// zapret_installed gates the Zapret panel — the package is optional so
// installs without it shouldn't render a permanently-empty section. The
// expect+defer-style call returns `{installed: false}` instead of
// throwing when the user lacks rpcd permission, so the page degrades to
// "show Zapret" rather than "crash" on auth edge cases.
var callZapretInstalled = rpc.declare({
  object: 'purewrt',
  method: 'zapret_installed',
  expect: { installed: false }
});

// Each source is one logread-pattern on the backend. Title goes in the
// panel heading; hint is the cbi-section-note below it so the user knows
// what they're looking at without checking the rpcd file.
// Three panels by daemon. Previous incarnations had separate RPC / Manager
// / Update panels but every refresh/apply event in those streams is
// tagged purewrt-bg / purewrt-cron / purewrt-rpc — all matched by the
// bare `purewrt` keyword in the merged panel. Users who want just the
// update lines type "update" into the per-panel filter instead.
var SOURCES = [
  { key: 'rpc',     title: 'PureWRT',         hint: 'every purewrt action — rpcd-driven (LuCI clicks), background daemon, cron, boot, direct CLI, subscription refresh' },
  { key: 'mihomo',  title: 'Mihomo / Clash',  hint: 'proxy engine — node selection, routing decisions, DNS lookups' },
  // Zapret panel stays visible even when the package isn't installed —
  // mirrors the Zapret config page (also keeps its tab visible). The
  // panel body is replaced by a "not installed" notice at render time,
  // computed once from the rpcd check.
  { key: 'zapret',  title: 'Zapret',          hint: 'nfqws / tpws DPI-bypass daemon and its scripted runners', requiresZapret: true }
];

var DEFAULT_TAIL_LINES   = 200;
var MAX_RENDERED_LINES   = 1000;
var POLL_MS              = 3000;
var SCROLL_PIN_PX        = 24;  // px tolerance for "still at bottom" tail-follow

// Stylesheet injected once at first render. Lives here (not in a static
// .css file under resources/) so the logs page is self-contained — no
// extra deploy step when iterating on visual tweaks.
var STYLE_ID = 'purewrt-logs-style';
function ensureStyles() {
  if (document.getElementById(STYLE_ID)) return;
  var s = document.createElement('style');
  s.id = STYLE_ID;
  s.textContent = [
    '.purewrt-log-pre {',
    '  max-height: 30em; overflow-y: auto; overflow-x: hidden;',
    '  white-space: pre-wrap; word-break: break-word;',
    '  background: #0d1117; color: #c9d1d9;',
    '  padding: .6em .8em; margin: 0;',
    '  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;',
    '  font-size: .82em; line-height: 1.45;',
    '  border-radius: 6px; border: 1px solid #30363d;',
    '}',
    '.purewrt-log-line { display: block; padding: 0 .2em; border-left: 2px solid transparent; }',
    '.purewrt-log-line.err  { color: #ff7b72; border-left-color: #ff7b72; background: rgba(248,81,73,.05); }',
    '.purewrt-log-line.warn { color: #f0b06b; border-left-color: #f0b06b; }',
    '.purewrt-log-line.info { color: #7ee787; }',
    '.purewrt-log-line.dim  { color: #8b949e; }',
    '.purewrt-log-line mark { background: #f0b06b; color: #0d1117; border-radius: 2px; padding: 0 1px; }',
    '.purewrt-log-toolbar { display: flex; align-items: center; gap: .5em; flex-wrap: wrap; margin: .2em 0 .4em 0; }',
    '.purewrt-log-toolbar h3 { margin: 0; flex: 0 0 auto; }',
    '.purewrt-log-toolbar .filler { flex: 1; }',
    '.purewrt-log-toolbar .status { font-size: .78em; color: #8b949e; min-width: 7em; text-align: right; }',
    '.purewrt-log-toolbar input.cbi-input-text { width: 14em; }',
    '.purewrt-log-toolbar .ctrl { font-size: .85em; padding: .15em .55em; }',
    '.purewrt-log-toolbar .ctrl.paused { background: #f0b06b; color: #0d1117; }',
    '.purewrt-log-toolbar .pill { font-size: .72em; padding: .1em .5em; border-radius: 10px; background: #21262d; color: #8b949e; }',
    '.purewrt-log-toolbar .pill.live { background: #2ea043; color: #fff; }',
    ''
  ].join('\n');
  document.head.appendChild(s);
}

// classifyLine returns one of err/warn/info/dim by keyword heuristic.
// Tries to match common log-level prefixes first; falls back to keyword
// search; defaults to dim so the panel doesn't visually screams at the
// user for ordinary informational chatter.
var RX_ERR  = /\b(err(?:or)?|fatal|panic|fail(?:ed)?|denied|refused|unreachable|rejected)\b/i;
var RX_WARN = /\b(warn(?:ing)?|stall|retry|timeout|degraded|missing|stale)\b/i;
var RX_OK   = /\b(ok|success|started|applied|ready|connected|updated|reload(?:ed)?)\b/i;
function classifyLine(line) {
  if (RX_ERR.test(line))  return 'err';
  if (RX_WARN.test(line)) return 'warn';
  if (RX_OK.test(line))   return 'info';
  return 'dim';
}

// escapeHTML returns line with HTML-significant characters replaced. Used
// when rendering with filter highlights — we build small HTML fragments
// to wrap matches in <mark>, so the line content itself must be escaped
// to prevent log content from injecting markup.
function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, function(c) {
    return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];
  });
}

function highlightLine(line, needle) {
  if (!needle) return escapeHTML(line);
  var lower = line.toLowerCase();
  var n = needle.toLowerCase();
  var out = '';
  var i = 0;
  while (i < line.length) {
    var j = lower.indexOf(n, i);
    if (j < 0) { out += escapeHTML(line.substring(i)); break; }
    out += escapeHTML(line.substring(i, j));
    out += '<mark>' + escapeHTML(line.substring(j, j + n.length)) + '</mark>';
    i = j + n.length;
  }
  return out;
}

// Panel state. One object per source, holds the rendered DOM references
// + the lines we've materialised. Kept off the DOM nodes themselves so
// repaints can rebuild the <pre> contents without losing state.
function makePanel(spec) {
  return {
    key: spec.key,
    title: spec.title,
    hint: spec.hint,
    lines: [],
    filter: '',
    paused: false,
    pre: null,
    status: null,
    livePill: null
  };
}

function renderPanel(panel) {
  var search = E('input', {
    'type': 'search',
    'class': 'cbi-input-text',
    'placeholder': _('filter (substring)…'),
    'value': panel.filter
  });
  search.addEventListener('input', function() {
    panel.filter = search.value;
    repaint(panel);
  });

  var pauseBtn = E('button', { 'class': 'btn ctrl' }, panel.paused ? '▶ ' + _('resume') : '⏸ ' + _('pause'));
  pauseBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    panel.paused = !panel.paused;
    pauseBtn.textContent = panel.paused ? '▶ ' + _('resume') : '⏸ ' + _('pause');
    pauseBtn.classList.toggle('paused', panel.paused);
    panel.livePill.textContent = panel.paused ? _('paused') : _('live');
    panel.livePill.classList.toggle('live', !panel.paused);
  });
  if (panel.paused) pauseBtn.classList.add('paused');

  var copyBtn = E('button', { 'class': 'btn ctrl' }, '⧉ ' + _('copy'));
  copyBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    var text = panel.lines.join('\n');
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text);
      ui.addNotification(null, E('p', _('Copied %d lines from %s.').format(panel.lines.length, panel.title)), 'info');
    } else {
      ui.addNotification(null, E('p', _('Clipboard unavailable — select the log text and copy manually.')), 'warning');
    }
  });

  var scrollBtn = E('button', { 'class': 'btn ctrl' }, '↓ ' + _('end'));
  scrollBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    if (panel.pre) panel.pre.scrollTop = panel.pre.scrollHeight;
  });

  panel.livePill = E('span', { 'class': 'pill live' }, _('live'));
  panel.status = E('span', { 'class': 'status' }, '');
  panel.pre = E('pre', { 'class': 'purewrt-log-pre' });

  return E('div', { 'class': 'cbi-section', 'style': 'margin-top:1em' }, [
    E('div', { 'class': 'purewrt-log-toolbar' }, [
      E('h3', {}, panel.title),
      panel.livePill,
      search,
      pauseBtn,
      copyBtn,
      scrollBtn,
      E('span', { 'class': 'filler' }),
      panel.status
    ]),
    E('p', { 'class': 'cbi-section-note', 'style': 'margin:.2em 0 .4em 0' }, panel.hint),
    panel.pre
  ]);
}

// repaint renders panel.lines into panel.pre, applying the filter and
// per-line classification + highlighting. Preserves scroll position when
// the user is reading (scrolled up); follows tail when they're at bottom.
function repaint(panel) {
  if (!panel.pre) return;
  var atBottom = (panel.pre.scrollTop + panel.pre.clientHeight + SCROLL_PIN_PX) >= panel.pre.scrollHeight;
  var needle = panel.filter.trim();

  var rendered = panel.lines;
  var hidden = 0;
  if (needle) {
    var n = needle.toLowerCase();
    rendered = [];
    panel.lines.forEach(function(l) {
      if (l.toLowerCase().indexOf(n) >= 0) rendered.push(l);
      else hidden++;
    });
  }

  if (!rendered.length) {
    panel.pre.innerHTML = '';
    var msg = panel.lines.length === 0 ? _('(no log data yet)') : _('(no lines match the filter)');
    panel.pre.appendChild(E('span', { 'class': 'purewrt-log-line dim' }, msg));
  } else {
    // Build the HTML in one go and assign innerHTML — faster than N
    // appendChild calls for large logs (1000-line repaints stay under 5 ms).
    var html = rendered.map(function(line) {
      return '<span class="purewrt-log-line ' + classifyLine(line) + '">' +
        highlightLine(line, needle) + '</span>';
    }).join('');
    panel.pre.innerHTML = html;
  }

  // Status line: total + filtered breakdown.
  var statusText = _('%d lines').format(panel.lines.length);
  if (hidden > 0) statusText += ' · ' + _('%d filtered').format(hidden);
  panel.status.textContent = statusText;

  if (atBottom) panel.pre.scrollTop = panel.pre.scrollHeight;
}

// fetchAndUpdate pulls one source from rpcd and merges new lines onto
// the panel's buffer (capped at MAX_RENDERED_LINES). The backend returns
// the most recent ~300 lines on every call — we keep our own buffer
// to avoid losing context when the upstream tail rotates out.
function fetchAndUpdate(panel) {
  return callLogs(panel.key).then(function(text) {
    var fresh = (text || '').trim();
    var lines = fresh ? fresh.split('\n') : [];
    // Pure replace strategy is simplest and correct: each /logs call
    // returns the tail of the upstream ring buffer, so we always reflect
    // exactly what logread shows. Cap at MAX_RENDERED_LINES so the DOM
    // doesn't grow unbounded for a noisy daemon.
    if (lines.length > MAX_RENDERED_LINES) {
      var drop = lines.length - MAX_RENDERED_LINES;
      lines = [ _('--- truncated, dropped %d older lines ---').format(drop) ].concat(lines.slice(-MAX_RENDERED_LINES));
    }
    panel.lines = lines.length ? lines : panel.lines;
    repaint(panel);
  }, function(err) {
    panel.lines = [ _('read failed: ') + (err && err.message || err) ];
    repaint(panel);
  });
}

function refreshAll(panels) {
  return Promise.all(panels.map(function(p) {
    if (p.paused || p.disabled) return Promise.resolve();
    return fetchAndUpdate(p);
  }));
}

// repaintDisabled paints the "not installed" notice into a panel that
// was frozen at render-time. Doesn't run line classification or filter
// logic — the panel is just a placeholder until the user installs the
// optional package.
function repaintDisabled(panel) {
  if (!panel.pre || !panel.disabled) return;
  panel.pre.innerHTML = '';
  panel.pre.appendChild(E('span', { 'class': 'purewrt-log-line warn' },
    panel.disabledMsg || _('(feature not installed)')));
  if (panel.status) panel.status.textContent = _('not installed');
  if (panel.livePill) {
    panel.livePill.textContent = _('off');
    panel.livePill.classList.remove('live');
  }
}

return view.extend({
  render: function() {
    ensureStyles();
    // Filter out optional sources whose backend feature isn't installed.
    // Zapret is the only such source today; the check is hoisted into
    // the render promise chain so a missing rpcd permission falls back
    // to "show the panel" (callZapretInstalled's expect defaults to
    // false, which would HIDE the panel — but the page degrades on
    // failure to show too little rather than too much).
    return callZapretInstalled().then(function(zapretInstalled) {
      var panels = SOURCES.map(makePanel);
      // For sources whose backend feature is optional and not present,
      // freeze the panel: skip the poll loop and replace the body with a
      // "not installed" notice. Panel stays visible so the user sees the
      // feature exists — matches the Zapret config tab's UX.
      panels.forEach(function(p, i) {
        var spec = SOURCES[i];
        if (spec.requiresZapret && !zapretInstalled) {
          p.paused = true;
          p.disabled = true;
          p.disabledMsg = _('Zapret is not installed. Install the optional `zapret` (or `purewrt-zapret`) package to enable this daemon and its log feed.');
        }
      });
      var panelNodes = panels.map(renderPanel);

      // Initial load — populate each panel before first render so users
      // don't see "(no log data yet)" placeholders flash on every visit.
      // Disabled panels skip the fetch (rpcd would just return empty
      // anyway) and get their notice rendered immediately.
      var initialLoads = panels.map(function(p) {
        return p.disabled ? Promise.resolve() : fetchAndUpdate(p);
      });
      panels.forEach(function(p) { if (p.disabled) repaintDisabled(p); });
      return Promise.all(initialLoads).then(function() { return { panels: panels, panelNodes: panelNodes }; });
    }).then(function(state) {
      var panels = state.panels;
      var panelNodes = state.panelNodes;
      var refreshBtn = E('button', { 'class': 'btn cbi-button cbi-button-apply' }, '↻ ' + _('Refresh now'));
      refreshBtn.addEventListener('click', function(ev) {
        ev.preventDefault();
        refreshBtn.disabled = true;
        refreshAll(panels).finally(function() { refreshBtn.disabled = false; });
      });
      var pauseAllBtn = E('button', { 'class': 'btn' }, '⏸ ' + _('Pause all'));
      var allPaused = false;
      pauseAllBtn.addEventListener('click', function(ev) {
        ev.preventDefault();
        allPaused = !allPaused;
        panels.forEach(function(p) {
          p.paused = allPaused;
          if (p.livePill) {
            p.livePill.textContent = allPaused ? _('paused') : _('live');
            p.livePill.classList.toggle('live', !allPaused);
          }
        });
        pauseAllBtn.textContent = allPaused ? '▶ ' + _('Resume all') : '⏸ ' + _('Pause all');
        // Force a UI sync on each panel's individual pause-button by
        // re-rendering — cheaper to just relabel; the per-panel buttons
        // sync on next user interaction with them anyway.
      });

      var root = E('div', { 'class': 'cbi-map' }, [
        E('h2', _('PureWRT Logs')),
        E('div', { 'class': 'cbi-section' }, [
          E('div', { 'style': 'display:flex;align-items:center;gap:.5em;flex-wrap:wrap' }, [
            refreshBtn,
            pauseAllBtn,
            E('span', { 'style': 'color:#8b949e;font-size:.85em' }, _(
              'Auto-refresh every %ds. Each panel tail-follows while scrolled to the bottom, freezes when you scroll up to read.').format(POLL_MS / 1000))
          ])
        ])
      ].concat(panelNodes));

      // Poll loop — parked on the root node via teardown closure so a SPA
      // re-navigation (LuCI caches view modules and re-calls render())
      // releases the old timer instead of stacking another one.
      var timerId = window.setInterval(function() {
        refreshAll(panels);
      }, POLL_MS);
      var stopOnce = function() {
        if (timerId !== null) { window.clearInterval(timerId); timerId = null; }
      };
      var parent = root.parentNode || document.body;
      var mo = new MutationObserver(function() {
        if (!document.body.contains(root)) { stopOnce(); mo.disconnect(); }
      });
      mo.observe(parent, { childList: true, subtree: true });

      return root;
    });
  },
  handleSave: null, handleSaveApply: null, handleReset: null
});
