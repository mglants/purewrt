'use strict';
'require view';
'require rpc';
'require ui';
'require uci';
'require purewrt.styles';
'require purewrt.format as fmt';

// PureWRT General — the canonical landing page. Shows at-a-glance health
// of the routing stack + entry points to the wizard and the most-touched
// admin tabs. Reads all data via the existing statistics + config_state
// RPCs so there's no new server-side endpoint to maintain.

var callStatistics = rpc.declare({ object: 'purewrt', method: 'statistics' });
var callConfigState = rpc.declare({ object: 'purewrt', method: 'config_state' });
var callReload = rpc.declare({ object: 'purewrt', method: 'reload' });
// 0 → use cached repo index (refreshed by Mihomo tab's Refresh button or
// >1h-stale auto-refresh). Cheap; safe to call on every General-page load.
// expect.updates unwraps the {updates:[...]} envelope from the rpcd
// dispatcher (ubus rejects top-level JSON arrays so the wire format
// has to be an object).
var callApkUpdates = rpc.declare({ object: 'purewrt', method: 'apk_updates_available', params: [ 'force' ], expect: { updates: [] } });

// Formatting helpers (humanAgo / humanUptime / pill) live in
// purewrt.format — shared with statistics.js and subscriptions.js.
var humanAgo = fmt.humanAgo, humanUptime = fmt.humanUptime, pill = fmt.pill;

// ---- status banner ----

// statusBanner is the headline strip at the top of the page. Three states:
//   - never applied  → muted "PureWRT not applied yet" + wizard CTA
//   - applied + dirty → warn "Last applied X ago, config has unapplied changes" + apply CTA
//   - applied clean  → ok "Last applied X ago, everything in sync"
function statusBanner(state) {
  state = state || {};
  var applied = Number(state.applied_unix || 0);
  var dirty = !!state.dirty;
  if (!applied) {
    return E('div', { 'class': 'purewrt-banner purewrt-banner-muted' }, [
      E('strong', {}, _('PureWRT has never been applied. ')),
      _('Open the Setup Wizard below to get started.')
    ]);
  }
  if (dirty) {
    return E('div', { 'class': 'purewrt-banner purewrt-banner-warn' }, [
      E('strong', {}, _('Last applied: %s ago. ').format(humanAgo(applied))),
      _('Config has unapplied changes — click Apply now or go to Save & Apply on any settings page.')
    ]);
  }
  return E('div', { 'class': 'purewrt-banner purewrt-banner-ok' }, [
    E('strong', {}, _('Last applied: %s ago. ').format(humanAgo(applied))),
    _('Live state is in sync with saved config.')
  ]);
}

// ---- action buttons row ----

// actionsRow renders the primary CTAs the user reaches for from the
// landing page. Each entry routes to a sibling LuCI view by replacing the
// `/general` segment of the current URL so deep-linked / nested paths
// (e.g. wizard?step=2) work without hard-coded absolute paths.
function actionsRow(applyHandler) {
  var basePath = window.location.pathname.replace(/\/general\/?$/, '');
  function navBtn(label, suffix, variant) {
    var btn = E('button', { 'class': 'btn cbi-button cbi-button-' + (variant || 'neutral'), 'style': 'margin-right:.5em;margin-bottom:.5em' }, [ label ]);
    btn.addEventListener('click', function(ev) {
      ev.preventDefault();
      window.location = basePath + suffix;
    });
    return btn;
  }
  var applyBtn = E('button', { 'class': 'btn cbi-button cbi-button-apply', 'style': 'margin-right:.5em;margin-bottom:.5em' }, [ _('Apply now') ]);
  applyBtn.addEventListener('click', function(ev) { ev.preventDefault(); applyHandler(applyBtn); });

  // Dashboard button: opens metacubexd in a new tab. URL mirrors what
  // the old quickstart.js (now deleted) constructed: the dashboard HTML
  // lives at <browser-host>:<dashboard-port>/ui/<dashboard-name>/ and the
  // backend params (hostname/port/secret) are passed in the hash so the
  // dashboard JS knows which mihomo to talk to. Disabled only when
  // dashboard_enabled is explicitly '0' — clicking it then would just 404.
  // An UNSET key means the backend default (DashboardEnabled=true) applies and
  // mihomo serves external-ui, so don't gray the button for absent-means-on.
  var dashboardEnabled = uci.get('purewrt', 'settings', 'dashboard_enabled') !== '0';
  var dashBtn = E('button', {
    'class': 'btn cbi-button cbi-button-action',
    'style': 'margin-right:.5em;margin-bottom:.5em' + (dashboardEnabled ? '' : ';opacity:.4;cursor:not-allowed'),
    'title': dashboardEnabled ? '' : _('Dashboard disabled — toggle it on in Settings or via the wizard')
  }, [ _('Open Dashboard') ]);
  if (dashboardEnabled) {
    dashBtn.addEventListener('click', function(ev) { ev.preventDefault(); openDashboard(); });
  } else {
    dashBtn.disabled = true;
  }

  return E('div', { 'class': 'purewrt-card' }, [
    E('h3', {}, _('Actions')),
    navBtn(_('Run Setup Wizard'), '/wizard', 'action'),
    dashBtn,
    applyBtn,
    navBtn(_('Subscriptions'), '/subscriptions'),
    navBtn(_('Rule Providers'), '/ruleproviders'),
    navBtn(_('Sections / Routing'), '/sections'),
    navBtn(_('Statistics'), '/statistics'),
    navBtn(_('Settings'), '/settings')
  ]);
}

// openDashboard builds the metacubexd URL and opens it in a new tab.
// Host = window.location.hostname (the IP the user typed into LuCI is by
// definition reachable from their browser; dashboard_listen is typically
// 0.0.0.0:9090 which isn't directly addressable). Port = port half of
// dashboard_listen (default 9090). Secret comes from settings.secret.
function openDashboard() {
  var listen = uci.get('purewrt', 'settings', 'dashboard_listen') || '0.0.0.0:9090';
  var port = '9090';
  if (listen.indexOf(':') >= 0) port = listen.split(':').pop();
  var name = uci.get('purewrt', 'settings', 'dashboard_name') || 'metacubexd';
  var secret = uci.get('purewrt', 'settings', 'secret') || '';
  var host = window.location.hostname || '192.168.1.1';
  var proto = window.location.protocol.replace(':', '') || 'http';
  // metacubexd reads its backend connection params from the hash query.
  // Without these the dashboard defaults to 127.0.0.1:9090 which is
  // unreachable from the user's laptop. The trailing http=1 / https=1 tells
  // it which scheme to use for the API calls.
  var params = [
    'hostname=' + encodeURIComponent(host),
    'port=' + encodeURIComponent(port),
    (proto === 'https' ? 'https=1' : 'http=1')
  ];
  if (secret) params.push('secret=' + encodeURIComponent(secret));
  var url = proto + '://' + host + ':' + port + '/ui/' + encodeURIComponent(name) + '/#/setup?' + params.join('&');
  window.open(url, '_blank', 'noopener');
}

function handleApply(btn) {
  btn.disabled = true;
  var orig = btn.textContent;
  btn.textContent = _('Applying…');
  return callReload().then(function() {
    ui.addNotification(null, E('p', _('PureWRT applied.')), 'info');
  }).catch(function(e) {
    ui.addNotification(null, E('p', _('Apply failed: %s').format(e && e.message || e)), 'danger');
  }).finally(function() {
    btn.disabled = false;
    btn.textContent = orig;
    // refresh status after apply
    window.setTimeout(function() { location.reload(); }, 800);
  });
}

// ---- summary cards ----

function summaryCards(stats) {
  stats = stats || {};
  var services = stats.services || [];
  function svcCard(name) {
    var s = services.find(function(x) { return x.name === name; }) || { name: name };
    var running = s.pid > 0;
    return E('div', { 'class': 'purewrt-card', 'style': 'flex:1;min-width:14em' }, [
      E('div', { 'class': 'purewrt-stat-label' }, name),
      E('div', { 'style': 'display:flex;align-items:center;gap:.5em' }, [
        running ? pill(_('running'), 'ok') : pill(_('stopped'), 'danger'),
        running ? E('span', { 'class': 'purewrt-text-dim' }, _('uptime %s').format(humanUptime(s.uptime_sec)))
                : E('span', { 'class': 'purewrt-text-muted' }, _('not running'))
      ])
    ]);
  }

  var ruleCount = (stats.rule_providers || []).length;
  var proxyCount = (stats.proxy_providers || []).length;
  var subCount = countSubscriptions();
  var ipv6Enabled = (uci.get('purewrt', 'settings', 'ipv6') || '1') === '1';
  var profile = uci.get('purewrt', 'settings', 'resource_profile') || 'standard';
  var lastUpdate = stats.last_update || null;
  var skipped = stats.skipped_subscription_rule_imports || 0;

  function statCard(label, value, sub) {
    return E('div', { 'class': 'purewrt-card', 'style': 'flex:1;min-width:11em' }, [
      E('div', { 'class': 'purewrt-stat-label' }, label),
      E('div', { 'class': 'purewrt-stat-value' }, String(value)),
      sub ? E('div', { 'class': 'purewrt-text-dim', 'style': 'margin-top:.2em' }, sub) : E([])
    ]);
  }

  return E('div', { 'style': 'display:flex;gap:1em;flex-wrap:wrap;margin:1em 0' }, [
    svcCard('mihomo'),
    svcCard('purewrt-api'),
    statCard(_('Subscriptions'), subCount),
    statCard(_('Rule providers'), ruleCount, skipped ? _('%d skipped').format(skipped) : null),
    statCard(_('Proxy providers'), proxyCount),
    statCard(_('Resource profile'), profile),
    statCard(_('IPv6'), ipv6Enabled ? _('on') : _('off')),
    statCard(_('Last provider update'), lastUpdate || '—')
  ]);
}

function countSubscriptions() {
  var n = 0;
  var sections = uci.sections('purewrt', 'subscription') || [];
  sections.forEach(function(s) {
    if (s.enabled !== '0') n++;
  });
  return n;
}

// ---- routing sets (nft static + dnsmasq dynamic, merged) ----

// mergedSetsTable folds stats.nftables (populated by rule providers at apply
// time) and stats.dnsmasq (populated on the fly when dnsmasq resolves a
// domain that matches a routed rule) into one table. The Source column makes
// the distinction visible: static sets reflect what PureWRT pushed; dynamic
// sets reflect what's actually being looked up right now.
function mergedSetsTable(stats) {
  var nft = (stats.nftables || []).map(function(s) {
    return {
      set: s.set,
      description: s.description || '',
      entries: s.entries || 0,
      source: 'static'
    };
  });
  var dns = (stats.dnsmasq || []).map(function(s) {
    return {
      set: s.set,
      description: s.description || '',
      entries: s.entries || 0,
      source: 'dynamic'
    };
  });
  var rowsData = nft.concat(dns).sort(function(a, b) {
    return (a.set || '').localeCompare(b.set || '');
  });
  if (!rowsData.length) {
    return E('p', { 'class': 'purewrt-text-muted' }, _('No routing sets reported yet. Apply PureWRT to populate the static sets; dynamic sets fill in as dnsmasq resolves matched domains.'));
  }
  var rows = rowsData.slice(0, 16).map(function(s) {
    var pillCls = s.source === 'static' ? 'purewrt-pill-info' : 'purewrt-pill-ok';
    return E('tr', {}, [
      E('td', { 'style': 'padding:.3em .6em;font-family:monospace;font-size:.85em' }, s.set),
      E('td', { 'style': 'padding:.3em .6em' }, s.description || '-'),
      E('td', { 'style': 'padding:.3em .6em;text-align:right;font-variant-numeric:tabular-nums' }, String(s.entries)),
      E('td', { 'style': 'padding:.3em .6em' }, E('span', { 'class': 'purewrt-pill ' + pillCls }, s.source))
    ]);
  });
  var hidden = rowsData.length - rows.length;
  function th(label, align) {
    return E('th', { 'style': 'text-align:' + (align || 'left') + ';padding:.4em .6em;border-bottom:1px solid var(--border-color-medium,#333);color:#aaa;font-size:.85em;text-transform:uppercase' }, label);
  }
  return E('div', {}, [
    E('table', { 'style': 'border-collapse:collapse;width:100%' }, [
      E('thead', {}, [ E('tr', {}, [
        th(_('Set')),
        th(_('Description')),
        th(_('Entries'), 'right'),
        th(_('Source'))
      ]) ]),
      E('tbody', {}, rows)
    ]),
    hidden > 0
      ? E('p', { 'class': 'purewrt-text-dim', 'style': 'margin-top:.5em' },
          _('Plus %d more — see Statistics for the full table.').format(hidden))
      : E([])
  ]);
}

// ---- apk update-available banner ----

// updatesBanner surfaces upgradable first-party packages (purewrt /
// purewrt) so the user sees a hint without having to drill into LuCI's
// Software page. Mihomo and Zapret have their own per-package hints on
// their respective tabs — keeping the General banner scoped to the
// purewrt package itself avoids duplicating those signals here.
function updatesBanner(updates) {
  if (!updates || !updates.length) return null;
  var row = updates.find(function(u) { return u && u.name === 'purewrt'; });
  if (!row || !row.upgrade_available) return null;
  return E('div', { 'class': 'purewrt-banner purewrt-banner-warn' }, [
    E('strong', {}, _('PureWRT update available: ')),
    (row.installed || '?') + ' → ' + (row.available || '?'),
    ' — ',
    _('apply via System → Software (apk upgrade purewrt).')
  ]);
}

// ---- VPN-pending reminder (carried over from Subscriptions banner) ----

function vpnPendingBanner() {
  if (uci.get('purewrt', 'settings', 'wizard_vpn_pending') !== '1') return null;
  // The standalone /vpn tab is gone — VPN editing now lives inline on the
  // Sections / Routing page (modal from the per-section VPN picker).
  var basePath = window.location.pathname.replace(/\/general\/?$/, '');
  return E('div', { 'class': 'purewrt-banner purewrt-banner-warn' }, [
    E('strong', {}, _('VPN routing pending: ')),
    _('the setup wizard noted you plan to configure a VPN. Open Sections / Routing, create a section with action = vpn, and click "+ Add VPN" to define the interface. '),
    E('a', { 'href': basePath + '/sections', 'style': 'color:white;text-decoration:underline' }, _('Open Sections / Routing'))
  ]);
}

// zapretPendingBanner mirrors vpnPendingBanner for DPI bypass — set by
// the wizard when zapret is installed and the user asked for a reminder.
function zapretPendingBanner() {
  if (uci.get('purewrt', 'settings', 'wizard_zapret_pending') !== '1') return null;
  var basePath = window.location.pathname.replace(/\/general\/?$/, '');
  return E('div', { 'class': 'purewrt-banner purewrt-banner-warn' }, [
    E('strong', {}, _('DPI bypass pending: ')),
    _('the setup wizard noted you plan to configure zapret. Open the Zapret tab to set up desync strategies (or run Blockcheck to find one). '),
    E('a', { 'href': basePath + '/zapret', 'style': 'color:white;text-decoration:underline' }, _('Open Zapret'))
  ]);
}

// ---- view ----

return view.extend({
  load: function() {
    return Promise.all([
      callStatistics().catch(function() { return {}; }),
      callConfigState().catch(function() { return {}; }),
      uci.load('purewrt').catch(function() { return null; }),
      callApkUpdates('0').catch(function() { return []; })
    ]);
  },
  render: function(data) {
    var stats = (data && data[0]) || {};
    var state = (data && data[1]) || {};
    var updates = (data && data[3]) || [];
    var children = [
      E('h2', {}, _('PureWRT')),
      statusBanner(state),
      updatesBanner(updates),
      vpnPendingBanner(),
      zapretPendingBanner(),
      actionsRow(handleApply),
      summaryCards(stats),
      E('div', { 'class': 'purewrt-card' }, [
        E('h3', {}, _('Routing sets')),
        E('p', { 'class': 'purewrt-text-dim' }, _('Static sets come from rule providers applied to nftables. Dynamic sets are populated by dnsmasq as it resolves matched domains; empty dynamic sets are normal until matching traffic appears.')),
        mergedSetsTable(stats)
      ])
    ].filter(function(c) { return c != null; });
    return E('div', { 'class': 'cbi-map' }, children);
  }
});
