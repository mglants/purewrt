'use strict';
'require view';
'require rpc';
'require ui';
'require uci';
'require network';
'require purewrt.styles';

// PureWRT setup wizard — 8-step linear flow. Replaces the old Quick Start
// page (which mixed subscription input with global settings) and serves as
// the canonical "add subscription" entry point too (Subscriptions page no
// longer offers inline add). State lives in module scope; each step's
// Continue button mutates it and re-renders the active panel.

var callPreview = rpc.declare({ object: 'purewrt', method: 'preview', params: [ 'url' ] });
var callImport = rpc.declare({ object: 'purewrt', method: 'import', params: [ 'url', 'mode' ] });
var callReload = rpc.declare({ object: 'purewrt', method: 'reload' });
var callWizardReset = rpc.declare({ object: 'purewrt', method: 'wizard_reset' });
var callZapretInstalled = rpc.declare({ object: 'purewrt', method: 'zapret_installed', expect: { installed: false } });
var callDefaultListsCatalog = rpc.declare({ object: 'purewrt', method: 'default_lists_catalog', expect: { catalog: [] } });
var callNativeListAdd = rpc.declare({ object: 'purewrt', method: 'native_list_add', params: [ 'url', 'section', 'priority' ] });
var callUpdate = rpc.declare({ object: 'purewrt', method: 'update' });

// Initial state. The wizard always starts at step 1 unless the caller
// passed ?step=N in the URL. UCI defaults are seeded from current settings
// where applicable so the wizard reflects the existing config when
// re-run as a reconfiguration tool, not just first-run.
function makeInitialState() {
  // ipv6_wan_interface is a UCI list option; uci.get returns either an
  // array (multi-value) or a single string. Normalize to an array.
  var rawWan = uci.get('purewrt', 'settings', 'ipv6_wan_interface');
  var wanList = Array.isArray(rawWan) ? rawWan.slice() : (rawWan ? [ String(rawWan) ] : []);
  return {
    step: 1,
    source: 'default',              // 'subscription' | 'manual' | 'default' — default-lists preselected
    resetAck: false,                // ack of the destructive config flush (gates Apply)
    defaultLists: [],               // catalog.json entries (loaded in load())
    listMap: {},                    // {listName: {section, enabled}} for source=default
    proxyUrl: '',                   // proxy nodes URL for source=default (imported proxy-only)
    sub: {
      url: '',
      name: 'main',
      userAgent: '',
      headers: []
    },
    previewResult: null,            // populated by callPreview
    previewError: null,
    // ruleOverrides: {<providerName>: {section: 'common', ignored: false}}.
    // Keyed by RuleProvider.Name from preview. Built on preview load with the
    // auto-classified defaults, then user-mutable in step 3 (Routing). Applied
    // after callImport finishes so the user's choices win over the default
    // classifier.
    ruleOverrides: {},
    // sectionRouting: {<sectionName>: {action, proxy:{type,filter,exclude,strategy}, vpn, zapret:[]}}
    // — the unified per-section protocol config shown in the routing board for
    // BOTH sources. Consolidates the old sectionVpn + sectionProxy. Seeded from
    // the preview SectionGroups / current uci section / name convention.
    sectionRouting: {},
    // proxyNodeNames: null until the Default-lists "Proxy nodes URL" is previewed,
    // then the array of node names used for the live matched-server preview.
    proxyNodeNames: null,
    proxyPreviewError: null,
    proxyPreviewLoading: false,
    profile: uci.get('purewrt', 'settings', 'resource_profile') || 'standard',
    ipv6: (uci.get('purewrt', 'settings', 'ipv6') || '1') === '1',
    ipv6WanInterfaces: wanList,     // [] = autodetect at apply time
    ipv6WanDetected: [],            // populated in load() from network.getNetworks()
    dohChoice: 'cloudflare',        // cloudflare | google | quad9 | none
    autoUpdate: (uci.get('purewrt', 'settings', 'auto_update_enabled') || '1') === '1',
    autoUpdateCron: uci.get('purewrt', 'settings', 'auto_update_cron') || '17 */6 * * *',
    mihomoAutoUpdate: (uci.get('purewrt', 'settings', 'mihomo_auto_update_enabled') || '0') === '1',
    mihomoAutoUpdateCron: uci.get('purewrt', 'settings', 'mihomo_auto_update_cron') || '23 4 * * *',
    dashboard: (uci.get('purewrt', 'settings', 'dashboard_enabled') || '1') === '1',
    vpnPending: false,
    zapretPending: (uci.get('purewrt', 'settings', 'wizard_zapret_pending') || '0') === '1',
    zapretInstalled: false,
    applying: false,
    applyDone: false,
    applyError: null
  };
}

var WIZARD_STEPS = 9;

// hasRoutableProviders is the gate for showing/skipping the Routing step.
// Without a preview (manual setup, or before user clicked Preview) or with
// zero rule providers in the plan, there's nothing to route — skip the
// step rather than showing an empty table.
function hasRoutableProviders() {
  var rps = state.previewResult && (state.previewResult.RuleProviders || state.previewResult.rule_providers);
  return Array.isArray(rps) && rps.length > 0;
}

// seedRuleOverrides initializes state.ruleOverrides from the preview plan
// the first time we see it. Preserves any user edits already made.
function seedRuleOverrides() {
  if (!state.previewResult) return;
  var rps = state.previewResult.RuleProviders || state.previewResult.rule_providers || [];
  rps.forEach(function(rp) {
    var name = rp.Name || rp.name;
    if (!name) return;
    if (state.ruleOverrides[name]) return; // user-edited already, don't clobber
    state.ruleOverrides[name] = {
      section: rp.Section || rp.section || 'common',
      ignored: false
    };
  });
}

// ---- Unified routing model (shared by both sources) -------------------------

// routeItems returns the routable items for the current source as a uniform
// list the drag-flow board operates on, backed by the existing per-source
// stores (ruleOverrides for subscription rule providers, listMap for default
// catalog lists) so the downstream import/apply paths are unchanged.
function routeItems() {
  if (state.source === 'subscription') {
    var rps = (state.previewResult && (state.previewResult.RuleProviders || state.previewResult.rule_providers)) || [];
    return rps.map(function(rp) {
      var name = rp.Name || rp.name;
      var ov = state.ruleOverrides[name] || (state.ruleOverrides[name] = { section: rp.Section || rp.section || 'common', ignored: false });
      return {
        id: name, name: name, kind: 'rule', meta: rp.RouteAction || rp.route_action || '',
        get section() { return ov.section; },
        get active() { return !ov.ignored; },
        setSection: function(s) { ov.section = s; },
        setActive: function(b) { ov.ignored = !b; }
      };
    });
  }
  if (state.source === 'default') {
    return (state.defaultLists || []).map(function(entry) {
      var st = state.listMap[entry.name] || (state.listMap[entry.name] = { section: entry.suggested_section || 'common', enabled: true });
      var counts = [];
      if (entry.domains) counts.push(entry.domains + ' ' + _('domains'));
      if (entry.subnets) counts.push(entry.subnets + ' ' + _('subnets'));
      return {
        id: entry.name, name: entry.name, kind: 'list', meta: counts.join(', '),
        get section() { return st.section; },
        get active() { return st.enabled; },
        setSection: function(s) { st.section = s; },
        setActive: function(b) { st.enabled = b; }
      };
    });
  }
  return [];
}

// previewSectionGroup finds the preview's per-section proxy group (subscription
// SectionGroups) by name, so a section's proxy config can seed from what the
// subscription wants.
function previewSectionGroup(name) {
  var groups = (state.previewResult && (state.previewResult.SectionGroups || state.previewResult.section_groups)) || [];
  for (var i = 0; i < groups.length; i++) {
    if ((groups[i].Name || groups[i].name) === name) return groups[i];
  }
  return null;
}

// ensureSectionRouting lazily seeds + returns the unified protocol config for a
// section: action + proxy/vpn/zapret payload. Source order: preview SectionGroup
// (proxy fields) → current uci section → name convention (direct/reject) → proxy.
function ensureSectionRouting(name) {
  if (state.sectionRouting[name]) return state.sectionRouting[name];
  var grp = previewSectionGroup(name);
  var z = uci.get('purewrt', name, 'zapret_strategy');
  var r = {
    action: uci.get('purewrt', name, 'action') || (name === 'direct' ? 'direct' : name === 'reject' ? 'reject' : 'proxy'),
    proxy: {
      type:     (grp && (grp.ProxyGroupType || grp.proxy_group_type)) || uci.get('purewrt', name, 'proxy_group_type') || 'url-test',
      filter:   (grp && (grp.ProxyFilter || grp.proxy_filter)) || uci.get('purewrt', name, 'proxy_filter') || '',
      exclude:  (grp && (grp.ProxyExcludeFilter || grp.proxy_exclude_filter)) || uci.get('purewrt', name, 'proxy_exclude_filter') || '',
      strategy: (grp && (grp.ProxyStrategy || grp.proxy_strategy)) || uci.get('purewrt', name, 'proxy_strategy') || 'sticky-sessions'
    },
    vpn: uci.get('purewrt', name, 'vpn') || '',
    zapret: Array.isArray(z) ? z.slice() : (z ? [ String(z) ] : [])
  };
  state.sectionRouting[name] = r;
  return r;
}

// routingNodeNames is the proxy node list used for the live matched-server
// preview: the subscription preview's nodes, or the default-lists "Proxy nodes
// URL" preview's nodes.
function routingNodeNames() {
  if (state.source === 'default') return state.proxyNodeNames || [];
  var s = (state.previewResult && (state.previewResult.Summary || state.previewResult.summary)) || {};
  return s.ProxyNodeNames || s.proxy_node_names || [];
}

// ensureProxyPreview auto-fetches the Default-lists "Proxy nodes URL" node names
// (once) so the routing board's proxy lanes show matched servers without a
// manual button. Fire-and-forget: the board renders immediately and repopulates
// via renderApp when the fetch resolves.
function ensureProxyPreview() {
  if (state.source !== 'default') return;
  if (!state.proxyUrl || state.proxyNodeNames !== null || state.proxyPreviewLoading) return;
  state.proxyPreviewLoading = true;
  state.proxyPreviewError = null;
  callPreview(state.proxyUrl).then(function(r) {
    var s = (r && (r.Summary || r.summary)) || {};
    state.proxyNodeNames = s.ProxyNodeNames || s.proxy_node_names || [];
  }).catch(function(err) {
    state.proxyPreviewError = err && err.message || String(err);
    state.proxyNodeNames = [];
  }).finally(function() {
    state.proxyPreviewLoading = false;
    renderApp();
  });
}

// availableZapretStrategies lists the zapret strategy names defined on the
// router (preserved across the wizard reset), for the zapret protocol picker.
function availableZapretStrategies() {
  var out = [];
  (uci.sections('purewrt', 'zapret_strategy') || []).forEach(function(z) {
    var name = z.name || z['.name'];
    if (name) out.push(name);
  });
  return out;
}

var state = null;

// DoH resolver presets. Each maps the user's friendly choice to the actual
// list of URLs that BootstrapDoHResolvers should hold. The 'cloudflare'
// option keeps Cloudflare's IPv4 + IPv6 endpoints; 'none' clears the list
// and disables bootstrap (system resolver is used). Matches the strings the
// wizard writes to settings.bootstrap_doh_resolver list.
var DOH_PRESETS = {
  cloudflare: { enabled: '1', urls: [ 'https://1.1.1.1/dns-query', 'https://1.0.0.1/dns-query' ] },
  google:     { enabled: '1', urls: [ 'https://8.8.8.8/dns-query', 'https://8.8.4.4/dns-query' ] },
  quad9:      { enabled: '1', urls: [ 'https://9.9.9.9/dns-query', 'https://149.112.112.112/dns-query' ] },
  none:       { enabled: '0', urls: [] }
};

var CRON_PRESETS = {
  '6h':  '17 */6 * * *',
  '24h': '17 4 * * *'
};

function stepperHeader() {
  var steps = [
    _('Source'), _('Subscription'), _('Routing'), _('Profile'), _('IPv6'),
    _('DNS'), _('Schedule'), _('VPN'), _('Review')
  ];
  // Mark the Routing step as muted when it won't actually render so the
  // pill chain visually matches what the user will go through.
  var routingActive = !shouldSkipRouting();
  return E('div', { 'class': 'purewrt-card', 'style': 'display:flex;gap:.4em;flex-wrap:wrap;align-items:center;justify-content:space-between;padding:.6em 1em' },
    steps.map(function(label, idx) {
      var n = idx + 1;
      var skipped = (n === 3 && !routingActive);
      var cls = 'purewrt-pill ' + (n === state.step ? 'purewrt-pill-info'
        : (n < state.step ? 'purewrt-pill-ok'
          : 'purewrt-pill-muted'));
      var style = 'min-width:7em' + (skipped ? ';opacity:.4' : '');
      return E('span', { 'class': cls, 'style': style }, n + '. ' + label);
    }));
}

function navButtons(opts) {
  opts = opts || {};
  var back = opts.canBack !== false && state.step > 1
    ? E('button', { 'class': 'btn cbi-button cbi-button-neutral', 'click': function(ev) { ev.preventDefault(); goBack(); } }, [ _('Back') ])
    : E('span', {});
  var forwardLabel = opts.forwardLabel || _('Continue');
  var forward = opts.canForward === false
    ? null
    : E('button', { 'class': 'btn cbi-button cbi-button-apply', 'click': function(ev) { ev.preventDefault(); (opts.onForward || goForward)(); } }, [ forwardLabel ]);
  var right = forward ? [ forward ] : [];
  return E('div', { 'style': 'display:flex;justify-content:space-between;margin-top:1em' }, [
    back,
    E('div', {}, right)
  ]);
}

// Step layout: 1 Source, 2 Subscription, 3 Routing (conditional), 4 Profile,
// 5 IPv6, 6 DNS, 7 Schedule, 8 VPN, 9 Review.
//
// Routing is skipped (in both directions) when:
//   - source is 'manual' (no subscription, nothing to route), OR
//   - source is 'subscription' but the preview returned 0 rule providers
//     (proxy-URI-only subscriptions don't have rules to classify)
function shouldSkipRouting() {
  if (state.source === 'manual') return true;
  // Default lists always route into the board (lists + per-section protocol).
  if (state.source === 'default') return false;
  // Subscription: show the board when the preview produced rule providers to
  // route OR per-section proxy groups to configure.
  if (hasRoutableProviders()) return false;
  var groups = (state.previewResult && (state.previewResult.SectionGroups || state.previewResult.section_groups)) || [];
  return groups.length === 0;
}

function goForward() {
  if (state.step === 1 && state.source === 'manual') {
    // Manual setup: skip Subscription AND Routing (jump to Profile)
    state.step = 4;
  } else if (state.step === 2 && shouldSkipRouting()) {
    // Subscription with no rules / default lists: skip Routing
    state.step = 4;
  } else {
    state.step += 1;
  }
  if (state.step > WIZARD_STEPS) state.step = WIZARD_STEPS;
  // Entering the routing board: auto-fetch the default-lists proxy servers so
  // the proxy lanes preview matched nodes without a manual button.
  if (state.step === 3) ensureProxyPreview();
  renderApp();
}

function goBack() {
  if (state.step === 4 && state.source === 'manual') {
    state.step = 1;
  } else if (state.step === 4 && shouldSkipRouting()) {
    state.step = 2;
  } else {
    state.step -= 1;
  }
  if (state.step < 1) state.step = 1;
  state.applyError = null;
  renderApp();
}

// ---- Step 1: Welcome + source choice ----

// resetWarningBanner warns that applying the wizard flushes all config.
function resetWarningBanner() {
  return E('div', { 'class': 'purewrt-banner purewrt-banner-danger' }, [
    E('strong', {}, _('Heads up: ')),
    _('Applying this wizard resets ALL PureWRT configuration — subscriptions, proxy/rule providers, routing sections, device assignments, DNS, and settings — to defaults. Only your VPN and Zapret configurations (and the mihomo binary + controller credentials) are preserved.')
  ]);
}

function renderStep1() {
  function pick(value) {
    return function() { state.source = value; renderApp(); };
  }
  function card(value, title, desc) {
    var selected = state.source === value;
    var style = 'cursor:pointer;border:1px solid ' + (selected ? 'var(--color-primary,#00a8e8)' : 'var(--border-color-low,#333)') +
      ';border-radius:6px;padding:1em;margin:.5em 0;background:' + (selected ? 'rgba(0,168,232,0.06)' : 'transparent') + ';';
    return E('div', { 'style': style, 'click': pick(value) }, [
      E('h4', { 'style': 'margin:0 0 .25em' }, title),
      E('div', { 'class': 'purewrt-text-dim' }, desc)
    ]);
  }
  return E('div', { 'class': 'purewrt-card' }, [
    E('h3', {}, _('Welcome to PureWRT')),
    E('p', { 'class': 'purewrt-text-dim' }, _('This wizard walks you through configuring proxy routing, IPv6, updates, and DNS. Most users start with a subscription URL provided by their proxy vendor.')),
    resetWarningBanner(),
    card('default', _('Default lists (recommended, lightest)'), _('Use pre-built blocklists published for PureWRT. The router imports them with almost no CPU (no parsing/dedup) and just maps each list to a routing section. Best for low-power devices.')),
    card('subscription', _('Use a subscription URL'), _('Paste a Clash/Mihomo subscription URL, proxy list, or rule list. The wizard will preview what will be imported before applying. Heaviest to process on the router.')),
    card('manual', _('Manual setup'), _('Skip the subscription step. You\'ll set global options here and configure proxy nodes / rule providers manually from the regular tabs.')),
    navButtons({ canBack: false })
  ]);
}

// ---- Step 2: Subscription URL + preview ----

function renderStep2() {
  var urlInput = E('input', { 'class': 'cbi-input-text', 'style': 'width:100%;max-width:42em', 'placeholder': 'https://example.com/subscription', 'value': state.sub.url });
  urlInput.addEventListener('input', function() { state.sub.url = urlInput.value; });

  var nameInput = E('input', { 'class': 'cbi-input-text', 'style': 'width:14em', 'placeholder': 'main', 'value': state.sub.name });
  nameInput.addEventListener('input', function() { state.sub.name = nameInput.value; });

  var uaInput = E('input', { 'class': 'cbi-input-text', 'style': 'width:100%;max-width:42em', 'placeholder': _('default'), 'value': state.sub.userAgent });
  uaInput.addEventListener('input', function() { state.sub.userAgent = uaInput.value; });

  var previewPane = E('div', { 'style': 'margin-top:1em' });
  if (state.previewError) {
    previewPane.appendChild(E('div', { 'class': 'purewrt-banner purewrt-banner-danger' }, _('Preview failed: %s').format(state.previewError)));
  }
  if (state.previewResult) {
    previewPane.appendChild(renderPreviewCard(state.previewResult));
    previewPane.appendChild(E('p', { 'class': 'purewrt-text-dim', 'style': 'margin-top:.5em' },
      _('Continue to the Routing step to assign each rule to a section and pick its protocol (proxy / VPN / zapret) + servers.')));
  }

  var previewBtn = E('button', { 'class': 'btn cbi-button cbi-button-action' }, [ _('Preview') ]);
  previewBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    if (!state.sub.url) {
      ui.addNotification(null, E('p', _('Enter a subscription URL first.')), 'warning');
      return;
    }
    state.previewError = null;
    state.previewResult = null;
    previewBtn.disabled = true;
    previewBtn.textContent = _('Downloading…');
    return callPreview(state.sub.url).then(function(r) {
      state.previewResult = r;
      // Reset overrides so a re-preview against a different URL doesn't
      // carry stale per-provider edits from the previous URL's preview.
      state.ruleOverrides = {};
      state.sectionRouting = {};
      seedRuleOverrides();
    }).catch(function(err) {
      state.previewError = err && err.message || String(err);
    }).finally(function() {
      previewBtn.disabled = false;
      renderApp();
    });
  });

  // Continue is always shown — we don't re-render on every keystroke (would
  // steal focus from the inputs). The click handler validates state.sub.url
  // at the moment the user clicks.
  function onContinue() {
    if (!state.sub.url) {
      ui.addNotification(null, E('p', _('Enter a subscription URL first, or go back and pick Manual setup.')), 'warning');
      return;
    }
    goForward();
  }
  return E('div', { 'class': 'purewrt-card' }, [
    E('h3', {}, _('Subscription URL')),
    E('p', { 'class': 'purewrt-text-dim' }, _('Paste the URL provided by your proxy vendor. Click Preview to see what will be imported before committing anything.')),
    E('div', { 'class': 'purewrt-kv', 'style': 'max-width:none' }, [
      E('dt', {}, _('URL')),   E('dd', {}, urlInput),
      E('dt', {}, _('Name')),  E('dd', {}, nameInput),
      E('dt', {}, _('User-Agent')), E('dd', {}, uaInput)
    ]),
    E('div', { 'style': 'margin:.75em 0' }, [ previewBtn ]),
    previewPane,
    navButtons({ onForward: onContinue, forwardLabel: state.previewResult ? _('Continue') : _('Continue (skip preview)') })
  ]);
}

function renderPreviewCard(p) {
  // ImportPlan shape returned by `purewrt preview` (internal/provider/
  // import_plan.go). The user-actionable counts live on the embedded
  // Analysis under .Summary; Sections are .SectionGroups; rule/proxy
  // providers are at the top level. Lowercased fallbacks keep the code
  // forward-compatible if json tags are added later.
  var summary = p.Summary || p.summary || {};
  var rows = [
    [ _('Subscription name'), p.SubscriptionName || p.subscription_name || '-' ],
    [ _('Import mode'),       p.Mode || p.mode || '-' ],
    [ _('Detected type'),     summary.Type || summary.type || '-' ],
    [ _('Proxy nodes'),       summary.ProxyNodes || summary.proxy_nodes || 0 ],
    [ _('Proxy providers'),   countList(p.ProxyProviders || p.proxy_providers) ],
    [ _('Rule providers'),    countList(p.RuleProviders  || p.rule_providers) ],
    [ _('Rules (inline)'),    summary.Rules || summary.rules || 0 ],
    [ _('Sections to create'), namesList(p.CreatedSections || p.created_sections || []) ],
    [ _('Section overrides'),  namesList(p.SectionGroups   || p.section_groups   || []) ]
  ];
  var warnings = (p.Warnings || p.warnings || []);
  // Render rule provider names compactly under the table — useful at a
  // glance before applying so the user sees the actual ruleset list.
  var ruleProviders = p.RuleProviders || p.rule_providers || [];
  var proxyProviders = p.ProxyProviders || p.proxy_providers || [];
  var body = rows.map(function(r) {
    return E('tr', {}, [
      E('th', { 'style': 'text-align:left;padding:.25em .75em;color:#888;vertical-align:top;white-space:nowrap' }, r[0]),
      E('td', { 'style': 'padding:.25em .75em' }, String(r[1]))
    ]);
  });
  return E('div', { 'class': 'purewrt-card', 'style': 'margin-top:0' }, [
    E('h4', { 'style': 'margin-top:0' }, _('Import preview')),
    E('table', { 'style': 'border-collapse:collapse' }, body),
    ruleProviders.length ? E('details', { 'style': 'margin-top:.5em' }, [
      E('summary', { 'style': 'cursor:pointer;color:#888' }, _('%d rule providers').format(ruleProviders.length)),
      E('ul', { 'style': 'margin:.25em 0 0 1.25em;font-family:monospace;font-size:.85em' },
        ruleProviders.map(function(rp) {
          var n = rp.Name || rp.name || '?';
          var sec = rp.Section || rp.section || '';
          var act = rp.RouteAction || rp.route_action || '';
          return E('li', {}, n + (sec ? ' → ' + sec : '') + (act ? ' [' + act + ']' : ''));
        }))
    ]) : E([]),
    proxyProviders.length ? E('details', { 'style': 'margin-top:.25em' }, [
      E('summary', { 'style': 'cursor:pointer;color:#888' }, _('%d proxy providers').format(proxyProviders.length)),
      E('ul', { 'style': 'margin:.25em 0 0 1.25em;font-family:monospace;font-size:.85em' },
        proxyProviders.map(function(pp) {
          return E('li', {}, (pp.Name || pp.name || '?') + ' (' + (pp.Type || pp.type || '?') + ')');
        }))
    ]) : E([]),
    warnings.length ? E('div', { 'class': 'purewrt-banner purewrt-banner-warn', 'style': 'margin-top:.5em' }, [
      E('strong', {}, _('Warnings')),
      E('ul', { 'style': 'margin:.25em 0 0 1.25em' }, warnings.map(function(w) { return E('li', {}, w); }))
    ]) : E([])
  ]);
}

// matchProxyNodes applies mihomo's filter semantics client-side: keep names
// matching the include regex (empty = all), then drop names matching the
// exclude regex (empty = none). Returns {nodes, error} — error is set when a
// regex is invalid so the UI can flag it instead of silently matching nothing.
function matchProxyNodes(names, filter, exclude) {
  var inc = null, exc = null;
  try { if (filter) inc = new RegExp(filter); } catch (e) { return { nodes: [], error: _('invalid include regex') }; }
  try { if (exclude) exc = new RegExp(exclude); } catch (e) { return { nodes: [], error: _('invalid exclude regex') }; }
  var out = (names || []).filter(function(n) {
    if (inc && !inc.test(n)) return false;
    if (exc && exc.test(n)) return false;
    return true;
  });
  return { nodes: out, error: null };
}

// Human-readable labels for the mode dropdowns (the option VALUE stays the bare
// key; only the shown text is described). Used by the routing board and mirrored
// on the Sections tab.
var PROTOCOL_LABELS = {
  proxy:  _('Proxy — route via mihomo'),
  direct: _('Direct — no proxy'),
  reject: _('Reject — drop traffic'),
  vpn:    _('VPN — route via VPN interface'),
  zapret: _('Zapret — DPI bypass')
};
var GROUP_TYPE_LABELS = {
  'select':       _('Select — pick a node manually'),
  'url-test':     _('URL-test — auto-pick fastest'),
  'load-balance': _('Load-balance — spread across nodes')
};
var STRATEGY_LABELS = {
  'sticky-sessions':    _('Sticky — same node per src/dst'),
  'consistent-hashing': _('Hashing — node by destination'),
  'round-robin':        _('Round-robin — rotate nodes')
};

// optionsFor builds <option> nodes for a select from a [value] list, labelling
// each via the given label map (falling back to the raw value), marking cur.
function optionsFor(values, labels, cur) {
  return values.map(function(v) {
    var o = E('option', { 'value': v }, (labels && labels[v]) || v);
    if (v === cur) o.selected = true;
    return o;
  });
}

// laneProxyConfig renders a section lane's proxy-group controls (group type,
// include/exclude filter, load-balance strategy) plus a live matched-server
// preview computed from routingNodeNames() against the filter/exclude. Reads +
// writes state.sectionRouting[name].proxy. Used by renderRoutingBoard for any
// lane whose protocol is 'proxy'.
function laneProxyConfig(name) {
  var ov = ensureSectionRouting(name).proxy;
  var nodeNames = routingNodeNames();

  var matchEl = E('div', { 'style': 'margin-top:.3em' });
  function updateMatch() {
    while (matchEl.firstChild) matchEl.removeChild(matchEl.firstChild);
    if (!nodeNames.length) {
      matchEl.appendChild(E('em', { 'class': 'purewrt-text-dim' }, state.proxyPreviewLoading
        ? _('Loading servers…')
        : _('Servers resolve at runtime — add a Proxy nodes URL / subscription to preview which match.')));
      return;
    }
    var r = matchProxyNodes(nodeNames, ov.filter, ov.exclude);
    if (r.error) { matchEl.appendChild(E('span', { 'class': 'purewrt-text-danger' }, r.error)); return; }
    var chips = r.nodes.slice(0, 30).map(function(n) { return E('span', { 'class': 'purewrt-server-chip' }, n); });
    matchEl.appendChild(E('div', { 'class': 'purewrt-lane-members' }, chips.length ? chips : [ E('em', { 'class': 'purewrt-text-dim' }, _('no servers match')) ]));
    matchEl.appendChild(E('div', { 'class': 'purewrt-text-dim' },
      _('%d of %d servers').format(r.nodes.length, nodeNames.length) + (r.nodes.length > 30 ? ' ' + _('(first 30)') : '')));
  }

  var typeSel = E('select', { 'class': 'cbi-input-select' }, optionsFor([ 'select', 'url-test', 'load-balance' ], GROUP_TYPE_LABELS, ov.type));
  var filterIn = E('input', { 'class': 'cbi-input-text', 'style': 'width:11em', 'placeholder': _('include regex'), 'value': ov.filter });
  filterIn.addEventListener('input', function() { ov.filter = filterIn.value; updateMatch(); });
  var excludeIn = E('input', { 'class': 'cbi-input-text', 'style': 'width:11em', 'placeholder': _('exclude regex'), 'value': ov.exclude });
  excludeIn.addEventListener('input', function() { ov.exclude = excludeIn.value; updateMatch(); });
  var stratSel = E('select', { 'class': 'cbi-input-select' }, optionsFor([ 'sticky-sessions', 'consistent-hashing', 'round-robin' ], STRATEGY_LABELS, ov.strategy));
  var stratWrap = E('span', { 'style': ov.type === 'load-balance' ? '' : 'display:none' }, [ stratSel ]);
  typeSel.addEventListener('change', function() { ov.type = typeSel.value; stratWrap.style.display = (ov.type === 'load-balance') ? '' : 'none'; });
  stratSel.addEventListener('change', function() { ov.strategy = stratSel.value; });

  updateMatch();
  return E('div', {}, [
    E('div', { 'style': 'display:flex;gap:.4em;align-items:center;flex-wrap:wrap;margin-top:.25em' }, [
      typeSel,
      E('span', { 'class': 'purewrt-text-dim' }, _('filter')), filterIn,
      E('span', { 'class': 'purewrt-text-dim' }, _('exclude')), excludeIn,
      stratWrap
    ]),
    matchEl
  ]);
}

function countList(v) {
  if (Array.isArray(v)) return v.length;
  return Number(v || 0);
}

function namesList(v) {
  if (!Array.isArray(v)) return '-';
  return v.map(function(x) { return x.name || x.Name || x; }).join(', ') || '-';
}

// ---- Step 3: Routing (conditional — only when preview has rule providers) ----

// allSections is the set of routing sections shown as lanes in the board:
// the five built-ins, plus every section an active item targets, plus any
// custom section the subscription preview wants. Built-ins lead in a fixed
// order; the rest are appended alphabetically.
function allSections() {
  var standard = [ 'common', 'media', 'ai', 'direct', 'reject' ];
  var set = {};
  routeItems().forEach(function(it) { if (it.section) set[it.section] = true; });
  var groups = (state.previewResult && (state.previewResult.SectionGroups || state.previewResult.section_groups)) || [];
  groups.forEach(function(g) { var n = g.Name || g.name; if (n) set[n] = true; });
  standard.forEach(function(s) { delete set[s]; });
  return standard.concat(Object.keys(set).sort());
}

// enabledVPNs returns the enabled VPN configs (preserved across the wizard's
// apply-time reset) so the Default-lists step can offer per-section VPN
// routing. Each entry: { name, label }.
function enabledVPNs() {
  var out = [];
  (uci.sections('purewrt', 'vpn') || []).forEach(function(v) {
    if (v.enabled === '0' || v.enabled === 0 || v.enabled === false) return;
    var name = v.name || v['.name'];
    if (!name) return;
    out.push({ name: name, label: name + (v.interface ? ' (' + v.interface + ')' : '') });
  });
  return out;
}

// SKIP_LANE is the pseudo-section id for the "not imported" lane. Dragging a
// card here marks the item inactive (subscription ignored / default disabled).
var SKIP_LANE = '__skip__';

// boardDrag holds the in-flight pointer drag: the item id, the start point,
// the floating ghost element, and whether the move threshold was crossed.
var boardDrag = null;

// makeCardDraggable wires pointer-based drag on a rule card: press + move
// past a threshold lifts a floating ghost that follows the pointer; the lane
// under the pointer highlights; release drops the item into that lane. Works
// for mouse + touch + pen (Pointer Events), unlike HTML5 drag. onDrop(laneName)
// is called with the target lane id (a section name or SKIP_LANE), or not at
// all if released outside any lane / below threshold.
function makeCardDraggable(cardEl, itemId, onDrop) {
  cardEl.addEventListener('pointerdown', function(ev) {
    if (ev.button != null && ev.button !== 0) return; // primary button / touch only
    ev.preventDefault();
    boardDrag = { id: itemId, startX: ev.clientX, startY: ev.clientY, ghost: null, started: false };

    function laneUnder(x, y) {
      var el = document.elementFromPoint(x, y);
      return el && el.closest ? el.closest('.purewrt-lane') : null;
    }
    function clearHover() {
      var prev = document.querySelector('.purewrt-lane.drag-over');
      if (prev) prev.classList.remove('drag-over');
    }
    function onMove(e) {
      if (!boardDrag) return;
      if (!boardDrag.started) {
        if (Math.abs(e.clientX - boardDrag.startX) < 5 && Math.abs(e.clientY - boardDrag.startY) < 5) return;
        boardDrag.started = true;
        cardEl.classList.add('purewrt-chip-dragging');
        var g = cardEl.cloneNode(true);
        g.className = 'purewrt-drag-ghost';
        document.body.appendChild(g);
        boardDrag.ghost = g;
      }
      boardDrag.ghost.style.left = (e.clientX + 8) + 'px';
      boardDrag.ghost.style.top = (e.clientY + 8) + 'px';
      clearHover();
      var lane = laneUnder(e.clientX, e.clientY);
      if (lane) lane.classList.add('drag-over');
    }
    function onUp(e) {
      document.removeEventListener('pointermove', onMove);
      document.removeEventListener('pointerup', onUp);
      var drag = boardDrag;
      boardDrag = null;
      if (!drag) return;
      if (drag.ghost && drag.ghost.parentNode) drag.ghost.parentNode.removeChild(drag.ghost);
      cardEl.classList.remove('purewrt-chip-dragging');
      clearHover();
      if (!drag.started) return; // a tap/click, not a drag
      var lane = laneUnder(e.clientX, e.clientY);
      if (lane && lane.getAttribute('data-lane')) onDrop(lane.getAttribute('data-lane'));
    }
    document.addEventListener('pointermove', onMove);
    document.addEventListener('pointerup', onUp);
  });
}

// renderRoutingBoard is the unified routing step for BOTH sources. Each routing
// section is a full-width lane that PICKS A PROTOCOL (proxy/direct/reject/vpn/
// zapret) with its config + live server preview, and CONTAINS the rule cards
// routed into it. Rules are moved between sections by dragging their card from
// one lane to another (pointer-based, mouse + touch). A trailing "Skip" lane
// holds not-imported rules. Edits live in ruleOverrides/listMap (item→section +
// active) and sectionRouting (section→protocol); applied by applyRuleOverrides +
// applySectionRouting.
function renderRoutingBoard() {
  var items = routeItems();
  var sections = allSections();
  var vpns = enabledVPNs();
  var zaprets = availableZapretStrategies();
  var byId = {};
  items.forEach(function(it) { byId[it.id] = it; });

  var bySection = {};
  var skipped = [];
  items.forEach(function(it) {
    if (!it.active) { skipped.push(it); return; }
    (bySection[it.section] = bySection[it.section] || []).push(it);
  });

  // A rule card living inside a lane. Dragging it calls onDrop(targetLane).
  function card(it) {
    var el = E('div', { 'class': 'purewrt-chip' + (it.active ? '' : ' purewrt-chip-inactive') }, [
      E('span', { 'class': 'purewrt-chip-handle', 'title': _('drag to a section') }, '⠿'),
      E('span', { 'class': 'purewrt-chip-name', 'title': it.name + (it.meta ? ' — ' + it.meta : '') }, it.name)
    ]);
    makeCardDraggable(el, it.id, function(targetLane) {
      var item = byId[it.id];
      if (!item) return;
      if (targetLane === SKIP_LANE) { item.setActive(false); }
      else { item.setSection(targetLane); item.setActive(true); }
      renderApp();
    });
    return el;
  }
  // cardsEl wraps a lane's rule cards in an outlined "Rules · N" box so the
  // rule→section grouping is visually obvious.
  function cardsEl(list, kind) {
    var inner = list.length
      ? E('div', { 'class': 'purewrt-lane-cards' }, list.map(card))
      : E('div', { 'class': 'purewrt-lane-cards' }, [ E('span', { 'class': 'purewrt-lane-empty' }, _('drag rules here')) ]);
    return E('div', { 'class': 'purewrt-rules-box' }, [
      E('div', { 'class': 'purewrt-rules-cap' }, (kind || _('Rules')) + ' · ' + list.length),
      inner
    ]);
  }

  function lane(name) {
    var r = ensureSectionRouting(name);
    var protoSel = E('select', { 'class': 'cbi-input-select' }, optionsFor([ 'proxy', 'direct', 'reject', 'vpn', 'zapret' ], PROTOCOL_LABELS, r.action));
    protoSel.addEventListener('change', function() { r.action = protoSel.value; renderApp(); });
    var count = (bySection[name] || []).length;
    var head = E('div', { 'class': 'purewrt-lane-head' }, [
      E('span', { 'class': 'purewrt-lane-name' }, name),
      E('span', { 'class': 'purewrt-lane-count' }, count + ' ' + (count === 1 ? _('rule') : _('rules'))),
      protoSel
    ]);

    var cfg;
    if (r.action === 'proxy') {
      cfg = laneProxyConfig(name);
    } else if (r.action === 'vpn') {
      if (vpns.length === 0) {
        cfg = E('p', { 'class': 'purewrt-text-dim' }, [
          _('No enabled VPNs. Add one on the '),
          E('a', { 'href': window.location.pathname.replace(/\/wizard\/?$/, '/sections') }, _('Sections / VPN Routing')),
          _(' tab — it then appears here.')
        ]);
      } else {
        var vsel = E('select', { 'class': 'cbi-input-select' },
          [ E('option', { 'value': '' }, _('First enabled VPN')) ].concat(vpns.map(function(v) { var o = E('option', { 'value': v.name }, v.label); if (v.name === r.vpn) o.selected = true; return o; })));
        vsel.addEventListener('change', function() { r.vpn = vsel.value; });
        cfg = E('div', { 'style': 'margin-top:.25em' }, [ E('span', { 'class': 'purewrt-text-dim' }, _('via ')), vsel ]);
      }
    } else if (r.action === 'zapret') {
      if (zaprets.length === 0) {
        cfg = E('p', { 'class': 'purewrt-text-dim' }, [
          _('No zapret strategies defined. Add them on the '),
          E('a', { 'href': window.location.pathname.replace(/\/wizard\/?$/, '/zapret') }, _('Zapret')),
          _(' tab — they then appear here.')
        ]);
      } else {
        cfg = E('div', { 'style': 'margin-top:.25em;display:flex;flex-wrap:wrap;gap:.6em' }, zaprets.map(function(z) {
          var cb = E('input', { 'type': 'checkbox', 'checked': r.zapret.indexOf(z) >= 0 ? 'checked' : null });
          cb.addEventListener('change', function() { var i = r.zapret.indexOf(z); if (cb.checked && i < 0) r.zapret.push(z); if (!cb.checked && i >= 0) r.zapret.splice(i, 1); });
          return E('label', { 'style': 'display:flex;gap:.3em;align-items:center' }, [ cb, E('span', {}, z) ]);
        }));
      }
    } else {
      cfg = E('p', { 'class': 'purewrt-text-dim', 'style': 'margin:.25em 0 0' },
        r.action === 'reject' ? _('Traffic to this section is dropped.') : _('Traffic to this section goes direct (no proxy).'));
    }

    return E('div', { 'class': 'purewrt-lane purewrt-lane-' + r.action, 'data-lane': name }, [ head, cfg, cardsEl(bySection[name] || []) ]);
  }

  var laneEls = sections.map(lane);
  // Trailing "Skip" lane — not-imported rules. Always present so users have a
  // place to drag rules out of routing (and back).
  laneEls.push(E('div', { 'class': 'purewrt-lane purewrt-lane-skip', 'data-lane': SKIP_LANE }, [
    E('div', { 'class': 'purewrt-lane-head' }, [
      E('span', { 'class': 'purewrt-lane-name' }, _('Skip (not imported)')),
      E('span', { 'class': 'purewrt-lane-count' }, skipped.length + '')
    ]),
    E('p', { 'class': 'purewrt-text-dim', 'style': 'margin:.1em 0 0' }, _('Rules dragged here are not imported. Drag them back into a section to include them.')),
    cardsEl(skipped, _('Skipped'))
  ]));

  return E('div', { 'class': 'purewrt-card' }, [
    E('h3', {}, _('Routing — drag each rule into a section; set the section\'s protocol')),
    E('p', { 'class': 'purewrt-text-dim' }, items.length
      ? _('Each section routes via its protocol (proxy / VPN / zapret / direct / reject). Drag a rule card from one section to another to re-route it.')
      : _('No rule lists to route — just set each section\'s protocol below.')),
    E('div', {}, laneEls),
    navButtons()
  ]);
}

// ---- Step 4: Resource profile ----

function renderStep3() {
  function card(value, title, desc) {
    var selected = state.profile === value;
    var style = 'cursor:pointer;border:1px solid ' + (selected ? 'var(--color-primary,#00a8e8)' : 'var(--border-color-low,#333)') +
      ';border-radius:6px;padding:1em;margin:.5em 0;background:' + (selected ? 'rgba(0,168,232,0.06)' : 'transparent') + ';';
    return E('div', { 'style': style, 'click': function() { state.profile = value; renderApp(); } }, [
      E('h4', { 'style': 'margin:0 0 .25em' }, title),
      E('div', { 'class': 'purewrt-text-dim' }, desc)
    ]);
  }
  return E('div', { 'class': 'purewrt-card' }, [
    E('h3', {}, _('Router resource profile')),
    E('p', { 'class': 'purewrt-text-dim' }, _('Pick the profile that matches your router. PureWRT tunes mihomo, dashboard, IPv6, and rule dedup based on this — the wrong choice still works but wastes RAM or skips features.')),
    card('low',      _('Low — < 256 MB RAM'), _('Small SoCs: WRT3200, MT7621, older routers. Disables mihomo dashboard, geodata auto-update, IPv6 routing, and rule dedup. Cache uses tmpfs.')),
    card('standard', _('Standard — 256 MB – 1 GB RAM'), _('Modern home routers (BPi-R3, ARMv8 SoCs). Full IPv6, dashboard on, geodata enabled, section-level dedup.')),
    card('high',     _('High — > 1 GB RAM'), _('Mini-PCs, SBC with plenty of RAM. Full-rule dedup, dashboard, geodata. Suitable for very large subscription lists.')),
    navButtons()
  ]);
}

// ---- Step 4: IPv6 ----

function renderStep4() {
  function radio(value, label, sub) {
    var selected = state.ipv6 === value;
    var style = 'cursor:pointer;border:1px solid ' + (selected ? 'var(--color-primary,#00a8e8)' : 'var(--border-color-low,#333)') +
      ';border-radius:6px;padding:1em;margin:.5em 0;background:' + (selected ? 'rgba(0,168,232,0.06)' : 'transparent') + ';';
    return E('div', { 'style': style, 'click': function() { state.ipv6 = value; renderApp(); } }, [
      E('h4', { 'style': 'margin:0 0 .25em' }, label),
      E('div', { 'class': 'purewrt-text-dim' }, sub)
    ]);
  }
  var consequences = state.ipv6 === false ? E('div', { 'class': 'purewrt-banner purewrt-banner-warn', 'style': 'margin-top:.5em' }, [
    E('strong', {}, _('Disabling IPv6 will do all of the following:')),
    E('ul', { 'style': 'margin:.25em 0 0 1.25em' }, [
      E('li', {}, _('PureWRT skips IPv6 nftset generation and IPv6 dnsmasq directives.')),
      E('li', {}, _('Add dnsmasq filter-aaaa so AAAA queries return empty (apps stop waiting 1–4 s for v6 to time out).')),
      E('li', {}, _('Disable the v6 WAN interfaces below and reload network so the kernel never holds a public v6 address.'))
    ]),
    E('p', { 'style': 'margin:.5em 0 0' }, _('Re-enable IPv6 later from this same wizard to reverse all three.'))
  ]) : E([]);
  var picker = state.ipv6 === false ? renderIPv6WANPicker() : E([]);
  return E('div', { 'class': 'purewrt-card' }, [
    E('h3', {}, _('IPv6')),
    radio(true,  _('Enable IPv6'),  _('Recommended if your ISP gives you a routable IPv6 prefix. Mihomo + nftables route both v4 and v6.')),
    radio(false, _('Disable IPv6'), _('Pick this on ISPs with broken or NAT64-only v6, or when v6 noise is interfering with the proxy.')),
    consequences,
    picker,
    navButtons()
  ]);
}

// renderIPv6WANPicker shows the detected v6 interfaces and lets the user
// pick which ones get `disabled=1` in /etc/config/network. Multi-WAN setups
// can have several (wan6 + a 6in4 tunnel + wan2_6 etc.) so this is a
// multi-select. Empty selection = autodetect at apply time (the Go side
// scans every dhcpv6 interface and toggles them all). Pattern matches the
// "Linux interfaces" picker on the Zapret page.
function renderIPv6WANPicker() {
  var detected = state.ipv6WanDetected || [];
  var saved = state.ipv6WanInterfaces || [];
  // Show every detected interface as a checkbox row. Anything in `saved`
  // that ISN'T in `detected` gets appended as a "custom" row so the user
  // can see + keep their override even when the interface is missing from
  // the current scan.
  var detectedNames = detected.map(function(d) { return d.name; });
  var customs = saved.filter(function(s) { return detectedNames.indexOf(s) < 0; });
  var rows = detected.map(function(d) {
    return ifaceRow(d.name, d.label || d.name, d.proto, saved.indexOf(d.name) >= 0);
  }).concat(customs.map(function(name) {
    return ifaceRow(name, name + ' ' + _('(custom)'), '', true);
  }));
  // Free-form "add another" input so power users can type an interface
  // name we didn't detect (rare PPPoE + IPv6CP setups, manual 6in4
  // overrides). Submits on Enter or "Add" click.
  var addInput = E('input', { 'class': 'cbi-input-text', 'style': 'width:14em', 'placeholder': 'wan2_6' });
  var addBtn = E('button', { 'class': 'btn cbi-button cbi-button-neutral' }, [ _('Add') ]);
  function addCustom() {
    var v = (addInput.value || '').trim();
    if (!v) return;
    if (state.ipv6WanInterfaces.indexOf(v) < 0) {
      state.ipv6WanInterfaces.push(v);
    }
    addInput.value = '';
    renderApp();
  }
  addBtn.addEventListener('click', function(ev) { ev.preventDefault(); addCustom(); });
  addInput.addEventListener('keydown', function(ev) {
    if (ev.key === 'Enter') { ev.preventDefault(); addCustom(); }
  });

  var emptyHint = (detected.length === 0)
    ? E('p', { 'class': 'purewrt-text-dim' }, _('No v6 interfaces detected in /etc/config/network. The apply step will fall back to autodetect at apply time (any proto=dhcpv6 section), or you can type one below.'))
    : (saved.length === 0
        ? E('p', { 'class': 'purewrt-text-dim' }, _('Nothing checked — the apply step will autodetect every proto=dhcpv6 interface and disable them all. Check specific ones above to lock the list.'))
        : E([]));

  return E('div', { 'class': 'purewrt-card', 'style': 'margin-top:.5em' }, [
    E('h4', { 'style': 'margin-top:0' }, _('IPv6 WAN interfaces to disable')),
    E('p', { 'class': 'purewrt-text-dim' }, _('OpenWrt interfaces detected with proto=dhcpv6. Multi-WAN routers can have several — check the ones you want to bring down when IPv6 is off.')),
    E('div', {}, rows),
    emptyHint,
    E('div', { 'style': 'display:flex;gap:.5em;align-items:center;margin-top:.5em' }, [
      E('label', { 'style': 'min-width:8em' }, _('Add custom name')),
      addInput, addBtn
    ])
  ]);
}

function ifaceRow(name, label, proto, checked) {
  var cb = E('input', { 'type': 'checkbox', 'checked': checked ? 'checked' : null });
  cb.addEventListener('change', function() {
    var idx = state.ipv6WanInterfaces.indexOf(name);
    if (cb.checked && idx < 0) state.ipv6WanInterfaces.push(name);
    if (!cb.checked && idx >= 0) state.ipv6WanInterfaces.splice(idx, 1);
  });
  return E('label', { 'style': 'display:flex;gap:.5em;align-items:center;padding:.25em 0' }, [
    cb,
    E('span', {}, label),
    proto ? E('span', { 'class': 'purewrt-text-dim', 'style': 'font-family:monospace' }, [ ' (', proto, ')' ]) : E([])
  ]);
}

// ---- Step 5: Bootstrap DoH ----

function renderStep5() {
  function card(value, label, sub) {
    var selected = state.dohChoice === value;
    var style = 'cursor:pointer;border:1px solid ' + (selected ? 'var(--color-primary,#00a8e8)' : 'var(--border-color-low,#333)') +
      ';border-radius:6px;padding:1em;margin:.5em 0;background:' + (selected ? 'rgba(0,168,232,0.06)' : 'transparent') + ';';
    return E('div', { 'style': style, 'click': function() { state.dohChoice = value; renderApp(); } }, [
      E('h4', { 'style': 'margin:0 0 .25em' }, label),
      E('div', { 'class': 'purewrt-text-dim' }, sub)
    ]);
  }
  return E('div', { 'class': 'purewrt-card' }, [
    E('h3', {}, _('Bootstrap DNS')),
    E('p', { 'class': 'purewrt-text-dim' }, _('Used to resolve the subscription URL and mihomo update server before the proxy is running. DoH bypasses ISP DNS rewrites — important in censored regions.')),
    card('cloudflare', _('Cloudflare (1.1.1.1)'), _('Default. Fast, widely accessible.')),
    card('google',     _('Google (8.8.8.8)'),     _('Reliable but blocked in some regions.')),
    card('quad9',      _('Quad9 (9.9.9.9)'),      _('Privacy-focused. Slightly slower in EU/US.')),
    card('none',       _('None (system resolver)'), _('Skip DoH bootstrap. Only safe when your ISP\'s DNS isn\'t intercepted.')),
    navButtons()
  ]);
}

// ---- Step 6: Updates + Dashboard ----

function renderStep6() {
  var updateChk = E('input', { 'type': 'checkbox', 'checked': state.autoUpdate ? 'checked' : null });
  updateChk.addEventListener('change', function() { state.autoUpdate = updateChk.checked; renderApp(); });

  var cronSelect = E('select', { 'class': 'cbi-input-select' }, [
    E('option', { 'value': '6h' },     _('Every 6 hours (default)')),
    E('option', { 'value': '24h' },    _('Every 24 hours')),
    E('option', { 'value': 'custom' }, _('Custom (edit cron expression)'))
  ]);
  var currentCron = state.autoUpdateCron;
  var matched = Object.keys(CRON_PRESETS).find(function(k) { return CRON_PRESETS[k] === currentCron; }) || 'custom';
  Array.prototype.forEach.call(cronSelect.options, function(o) { if (o.value === matched) o.selected = true; });

  var cronInput = E('input', { 'class': 'cbi-input-text', 'style': 'width:14em;margin-left:.5em', 'value': currentCron });
  cronInput.style.display = (matched === 'custom') ? '' : 'none';
  cronSelect.addEventListener('change', function() {
    if (cronSelect.value === 'custom') {
      cronInput.style.display = '';
    } else {
      cronInput.style.display = 'none';
      state.autoUpdateCron = CRON_PRESETS[cronSelect.value];
    }
  });
  cronInput.addEventListener('input', function() { state.autoUpdateCron = cronInput.value; });

  var dashChk = E('input', { 'type': 'checkbox', 'checked': state.dashboard ? 'checked' : null });
  dashChk.addEventListener('change', function() { state.dashboard = dashChk.checked; });

  var mihomoUpdChk = E('input', { 'type': 'checkbox', 'checked': state.mihomoAutoUpdate ? 'checked' : null });
  mihomoUpdChk.addEventListener('change', function() { state.mihomoAutoUpdate = mihomoUpdChk.checked; renderApp(); });
  var mihomoCronInput = E('input', { 'class': 'cbi-input-text', 'style': 'width:14em', 'value': state.mihomoAutoUpdateCron });
  mihomoCronInput.addEventListener('input', function() { state.mihomoAutoUpdateCron = mihomoCronInput.value; });

  return E('div', { 'class': 'purewrt-card' }, [
    E('h3', {}, _('Updates & dashboard')),
    E('div', { 'style': 'margin:.75em 0' }, [
      E('label', { 'style': 'display:flex;gap:.5em;align-items:center' }, [ updateChk, E('strong', {}, _('Auto-update subscriptions + rule providers')) ]),
      E('p', { 'class': 'purewrt-text-dim', 'style': 'margin:.25em 0 .5em 1.5em' }, _('Cron runs `purewrt update-if-needed` on the schedule below. Failed downloads retry 3 times with backoff.')),
      state.autoUpdate ? E('div', { 'style': 'margin-left:1.5em;display:flex;gap:.5em;align-items:center' }, [
        E('span', {}, _('Schedule')), cronSelect, cronInput
      ]) : E([])
    ]),
    E('hr', { 'style': 'opacity:.2' }),
    E('div', { 'style': 'margin:.75em 0' }, [
      E('label', { 'style': 'display:flex;gap:.5em;align-items:center' }, [ dashChk, E('strong', {}, _('Mihomo dashboard (metacubexd)')) ]),
      E('p', { 'class': 'purewrt-text-dim', 'style': 'margin:.25em 0 0 1.5em' }, _('Web UI at /ui/metacubexd/. Adds ~5 MB of static assets + RAM overhead. Honored even on the low resource profile — leave checked if you want the dashboard on a memory-constrained router, uncheck to save the memory.'))
    ]),
    E('hr', { 'style': 'opacity:.2' }),
    E('div', { 'style': 'margin:.75em 0' }, [
      E('label', { 'style': 'display:flex;gap:.5em;align-items:center' }, [ mihomoUpdChk, E('strong', {}, _('Auto-update the mihomo core binary')) ]),
      E('p', { 'class': 'purewrt-text-dim', 'style': 'margin:.25em 0 .5em 1.5em' }, _('Off by default. Runs `purewrt mihomo-auto-update` nightly: checks GitHub for a new release, installs it, and auto-reverts to the package binary if the new release fails its warmup probe.')),
      state.mihomoAutoUpdate ? E('div', { 'style': 'margin-left:1.5em;display:flex;gap:.5em;align-items:center' }, [
        E('span', {}, _('Schedule')), mihomoCronInput
      ]) : E([])
    ]),
    navButtons()
  ]);
}

// ---- Step 7: VPN placeholder ----

function renderStep7() {
  function pick(value) { return function() { state.vpnPending = value; renderApp(); }; }
  function card(value, label, sub) {
    var selected = state.vpnPending === value;
    var style = 'cursor:pointer;border:1px solid ' + (selected ? 'var(--color-primary,#00a8e8)' : 'var(--border-color-low,#333)') +
      ';border-radius:6px;padding:1em;margin:.5em 0;background:' + (selected ? 'rgba(0,168,232,0.06)' : 'transparent') + ';';
    return E('div', { 'style': style, 'click': pick(value) }, [
      E('h4', { 'style': 'margin:0 0 .25em' }, label),
      E('div', { 'class': 'purewrt-text-dim' }, sub)
    ]);
  }
  // DPI-bypass (zapret) block: zapret has no global on/off — it activates
  // through sections with action=zapret plus strategy config on its own
  // tab, so the wizard mirrors the VPN pattern and just sets a reminder.
  var zapretBlock;
  if (state.zapretInstalled) {
    var zapretChk = E('input', { 'type': 'checkbox', 'checked': state.zapretPending ? 'checked' : null });
    zapretChk.addEventListener('change', function() { state.zapretPending = zapretChk.checked; });
    zapretBlock = E('div', { 'style': 'margin:.75em 0' }, [
      E('label', { 'style': 'display:flex;gap:.5em;align-items:center' }, [ zapretChk, E('strong', {}, _('Remind me to configure DPI bypass (zapret)')) ]),
      E('p', { 'class': 'purewrt-text-dim', 'style': 'margin:.25em 0 0 1.5em' }, _('zapret is installed. Its desync strategies (per-protocol DPI evasion, autotune) are configured on the Zapret tab; checking this shows a reminder banner on the General page.'))
    ]);
  } else {
    zapretBlock = E('p', { 'class': 'purewrt-text-dim', 'style': 'margin:.75em 0' },
      _('DPI bypass (zapret) is not installed — `apk add zapret` to unlock per-protocol desync strategies on the Zapret tab. PureWRT detects it automatically; no reinstall needed.'));
  }
  return E('div', { 'class': 'purewrt-card' }, [
    E('h3', {}, _('VPN & DPI bypass')),
    E('p', { 'class': 'purewrt-text-dim' }, _('PureWRT can route specific sections through an existing VPN interface (WireGuard / OpenVPN) instead of through the proxy. This is configured on the VPN Routing tab — the wizard just sets a reminder.')),
    card(true,  _('Yes, I\'ll set up VPN later'), _('After the wizard finishes, a reminder banner will appear pointing at the VPN Routing tab.')),
    card(false, _('Not using a VPN'), _('Skip the reminder. You can configure VPN routing any time from its own tab.')),
    E('hr', { 'style': 'opacity:.2' }),
    zapretBlock,
    navButtons()
  ]);
}

// ---- Step 8: Review + Apply ----

function renderStep8() {
  // Build a one-line routing summary: how many providers were re-routed
  // away from their default, how many marked ignored. Empty when the
  // Routing step was skipped (no rules).
  var routingSummary = '-';
  if (state.source === 'subscription' && hasRoutableProviders()) {
    var ignored = 0, rerouted = 0, total = 0;
    Object.keys(state.ruleOverrides).forEach(function(name) {
      total++;
      var ov = state.ruleOverrides[name];
      if (ov.ignored) { ignored++; return; }
      var rp = pickPreviewRP(name);
      var def = rp ? (rp.Section || rp.section || 'common') : 'common';
      if (ov.section !== def) rerouted++;
    });
    if (ignored === 0 && rerouted === 0) {
      routingSummary = _('%d providers, no overrides').format(total);
    } else {
      routingSummary = _('%d total, %d re-routed, %d ignored').format(total, rerouted, ignored);
    }
  }
  var sourceLabel = { subscription: _('Subscription URL'), manual: _('Manual setup'), 'default': _('Default lists') }[state.source] || state.source;
  var defaultSummary = '-';
  if (state.source === 'default') {
    var picked = (state.defaultLists || []).filter(function(e) {
      var st = state.listMap[e.name];
      return st && st.enabled;
    }).map(function(e) { return e.name + '→' + (state.listMap[e.name].section); });
    defaultSummary = picked.length ? picked.join(', ') : _('none selected');
  }
  var rows = [
    [ _('Source'),       sourceLabel ],
    [ _('Subscription'), state.source === 'subscription' ? (state.sub.url || '-') : _('(skipped)') ],
  ];
  if (state.source === 'default') {
    rows.push([ _('Default lists'), defaultSummary ]);
    rows.push([ _('Proxy nodes URL'), state.proxyUrl || _('none (proxy sections have no backend)') ]);
  } else {
    rows.push([ _('Routing'), routingSummary ]);
  }
  // Per-section protocol overrides (vpn/zapret/direct/reject) chosen on the board.
  var protoBits = Object.keys(state.sectionRouting).filter(function(k) {
    var a = state.sectionRouting[k].action;
    return a && a !== 'proxy';
  }).map(function(k) {
    var r = state.sectionRouting[k];
    if (r.action === 'vpn') return k + '→vpn' + (r.vpn ? '(' + r.vpn + ')' : '');
    if (r.action === 'zapret') return k + '→zapret' + (r.zapret && r.zapret.length ? '(' + r.zapret.join('/') + ')' : '');
    return k + '→' + r.action;
  });
  if (protoBits.length) rows.push([ _('Section protocols'), protoBits.join(', ') ]);
  rows = rows.concat([
    [ _('Resource profile'), state.profile ],
    [ _('IPv6'),         state.ipv6 ? _('Enabled') : _('Disabled (+ filter-aaaa, wan6 down)') ],
    [ _('Bootstrap DNS'), state.dohChoice ],
    [ _('Auto-update'),  state.autoUpdate ? state.autoUpdateCron : _('Off') ],
    [ _('Mihomo auto-update'), state.mihomoAutoUpdate ? state.mihomoAutoUpdateCron : _('Off') ],
    [ _('Dashboard'),    state.dashboard ? _('Enabled') : _('Disabled') ],
    [ _('VPN reminder'), state.vpnPending ? _('Yes') : _('No') ]
  ]);
  if (state.zapretInstalled) {
    rows.push([ _('DPI bypass (zapret)'), state.zapretPending ? _('Reminder set') : _('No') ]);
  }
  var summary = E('table', { 'style': 'border-collapse:collapse' }, rows.map(function(r) {
    return E('tr', {}, [
      E('th', { 'style': 'text-align:left;padding:.25em .75em;color:#888' }, r[0]),
      E('td', { 'style': 'padding:.25em .75em' }, String(r[1]))
    ]);
  }));

  var applyPane = E('div', { 'style': 'margin-top:1em' });
  if (state.applyError) {
    applyPane.appendChild(E('div', { 'class': 'purewrt-banner purewrt-banner-danger' }, _('Apply failed: %s').format(state.applyError)));
  }
  if (state.applyDone) {
    applyPane.appendChild(E('div', { 'class': 'purewrt-banner purewrt-banner-ok' }, [
      E('strong', {}, _('Setup complete.')),
      ' ',
      E('a', { 'href': window.location.pathname.replace(/\/wizard\/?$/, '/subscriptions'), 'style': 'color:white;text-decoration:underline' }, _('Go to Subscriptions'))
    ]));
  }

  var applyBtn = E('button', { 'class': 'btn cbi-button cbi-button-apply' }, [ state.applying ? _('Applying…') : _('Apply') ]);
  // Destructive: Apply is gated on the acknowledge checkbox below.
  if (state.applying || state.applyDone || !state.resetAck) applyBtn.disabled = true;
  applyBtn.addEventListener('click', function(ev) { ev.preventDefault(); runApply(); });

  var ackChk = E('input', { 'type': 'checkbox', 'checked': state.resetAck ? 'checked' : null });
  if (state.applying || state.applyDone) ackChk.disabled = true;
  ackChk.addEventListener('change', function() { state.resetAck = ackChk.checked; renderApp(); });
  var ack = E('label', { 'style': 'display:flex;gap:.5em;align-items:flex-start;margin-top:1em' }, [
    ackChk,
    E('span', {}, _('I understand applying will reset my PureWRT configuration to defaults (VPN and Zapret are preserved).'))
  ]);

  return E('div', { 'class': 'purewrt-card' }, [
    E('h3', {}, _('Review')),
    resetWarningBanner(),
    summary,
    applyPane,
    ack,
    E('div', { 'style': 'display:flex;justify-content:space-between;margin-top:1em' }, [
      E('button', { 'class': 'btn cbi-button cbi-button-neutral', 'click': function(ev) { ev.preventDefault(); if (!state.applying) goBack(); } }, [ _('Back') ]),
      applyBtn
    ])
  ]);
}

// ---- Apply ----

function runApply() {
  state.applying = true;
  state.applyError = null;
  renderApp();

  // 0. Flush ALL config to defaults first (preserves VPN/Zapret + credentials
  //    + mihomo binary + lists URL — see WizardReset). Then refresh the uci
  //    cache so the staged writes below land on the reset config, not the
  //    stale page-load state (same unload+load pattern as applyRuleOverrides).
  return callWizardReset().then(function() {
    if (typeof uci.unload === 'function') uci.unload('purewrt');
    return uci.load('purewrt');
  }).then(function() {
  // 1. Stage UCI writes. Settings are all in section 'settings' of type 'main'.
  var doh = DOH_PRESETS[state.dohChoice] || DOH_PRESETS.cloudflare;
  uci.set('purewrt', 'settings', 'resource_profile', state.profile);
  uci.set('purewrt', 'settings', 'ipv6', state.ipv6 ? '1' : '0');
  // The mode field is the source-of-truth when set; clear it so the legacy
  // boolean drives the effective state in auto-mode.
  uci.set('purewrt', 'settings', 'ipv6_mode', 'auto');
  uci.set('purewrt', 'settings', 'bootstrap_doh_enabled', doh.enabled);
  uci.set('purewrt', 'settings', 'bootstrap_doh_resolver', doh.urls);
  uci.set('purewrt', 'settings', 'auto_update_enabled', state.autoUpdate ? '1' : '0');
  uci.set('purewrt', 'settings', 'auto_update_cron', state.autoUpdateCron || '17 */6 * * *');
  // The existing uci.apply() below triggers the init script's
  // install_cron(), which writes/removes the mihomo cron block — no extra
  // rpcd plumbing needed.
  uci.set('purewrt', 'settings', 'mihomo_auto_update_enabled', state.mihomoAutoUpdate ? '1' : '0');
  uci.set('purewrt', 'settings', 'mihomo_auto_update_cron', state.mihomoAutoUpdateCron || '23 4 * * *');
  uci.set('purewrt', 'settings', 'dashboard_enabled', state.dashboard ? '1' : '0');
  uci.set('purewrt', 'settings', 'wizard_vpn_pending', state.vpnPending ? '1' : '0');
  uci.set('purewrt', 'settings', 'wizard_zapret_pending', state.zapretPending ? '1' : '0');
  // ipv6_wan_interface is a UCI list. Empty list = autodetect at apply
  // time (backend scans every proto=dhcpv6 section). Only persist a list
  // when IPv6 is being disabled — when v6 is on the list is irrelevant
  // and we don't want a stale override surviving.
  if (state.ipv6 === false && state.ipv6WanInterfaces.length > 0) {
    uci.set('purewrt', 'settings', 'ipv6_wan_interface', state.ipv6WanInterfaces);
  } else {
    uci.unset('purewrt', 'settings', 'ipv6_wan_interface');
  }

  return uci.save();
  }).then(function() {
    return uci.apply();
  }).then(function() {
    // 2. Source-specific provisioning, then apply.
    if (state.source === 'subscription' && state.sub.url) {
      // Import internally runs UpdateDetailed + Apply.
      return callImport(state.sub.url);
    }
    if (state.source === 'default') {
      // Optional proxy nodes URL imported proxy-only (no rules), then each
      // enabled list registered as a native_import provider (persist only),
      // then any per-section VPN routing, then one update (fetch) + reload
      // (apply) — far cheaper than per-list applies.
      var base = uci.get('purewrt', 'settings', 'default_lists_base_url') || '';
      if (base && !/\/$/.test(base)) base += '/';
      var adds = (state.defaultLists || []).filter(function(e) {
        var st = state.listMap[e.name];
        return st && st.enabled;
      }).map(function(e) {
        var st = state.listMap[e.name];
        // Pass the catalog's per-list priority when present; empty ⇒ the
        // manager falls back to the section's (or default) priority.
        return callNativeListAdd(base + e.file, st.section, String(e.priority || ''));
      });
      var chain = Promise.resolve();
      if (state.proxyUrl) chain = chain.then(function() { return callImport(state.proxyUrl, 'proxy_only'); });
      chain = chain.then(function() { return Promise.all(adds); });
      // Per-section protocol (proxy/vpn/zapret/...) is applied uniformly in
      // step 4 below via applySectionRouting, for both sources.
      return chain
        .then(function() { return callUpdate(); })
        .then(function() { return callReload(); });
    }
    return callReload();
  }).then(function() {
    // 3. Per-rule-provider overrides from the Routing step. Done AFTER
    //    callImport because the import is what creates the rule_provider
    //    UCI sections; we then mutate them in place. Reload UCI first so
    //    we see the freshly-imported sections (uci.load reads /etc/config,
    //    where Import + UpdateDetailed wrote earlier).
    if (!hasOverridesToApply()) return null;
    return applyRuleOverrides();
  }).then(function() {
    // 4. Per-section protocol routing (action + proxy/vpn/zapret payload) from
    //    the board, for both sources. Done after the import wrote/created the
    //    section configs; locks proxy sections so auto-update won't revert them.
    if (state.source !== 'subscription' && state.source !== 'default') return null;
    return applySectionRouting();
  }).then(function() {
    state.applyDone = true;
    state.applying = false;
    renderApp();
  }).catch(function(err) {
    state.applyError = err && err.message || String(err);
    state.applying = false;
    renderApp();
  });
}

function hasOverridesToApply() {
  if (state.source !== 'subscription') return false;
  var keys = Object.keys(state.ruleOverrides);
  for (var i = 0; i < keys.length; i++) {
    var rp = pickPreviewRP(keys[i]);
    var defaultSection = rp ? (rp.Section || rp.section || 'common') : 'common';
    var ov = state.ruleOverrides[keys[i]];
    if (ov.ignored) return true;
    if (ov.section !== defaultSection) return true;
  }
  return false;
}

function pickPreviewRP(name) {
  var rps = (state.previewResult && (state.previewResult.RuleProviders || state.previewResult.rule_providers)) || [];
  for (var i = 0; i < rps.length; i++) {
    if ((rps[i].Name || rps[i].name) === name) return rps[i];
  }
  return null;
}

// applySectionRouting writes the unified per-section protocol config from the
// routing board onto the section UCI (which import/reset created). For each
// section in state.sectionRouting that exists, it sets `action` plus the
// protocol payload and clears the others, so switching protocol is clean:
//   proxy  → proxy_group_type/filter/exclude/strategy + user_overridden_proxy_group=1
//   vpn    → vpn=<name>
//   zapret → zapret_strategy list
//   direct/reject → action only
// Replaces the old applySectionVpnRouting + applySectionProxyOverrides. Mirrors
// the uci refresh→set→save→apply pattern; final callReload regenerates state.
function applySectionRouting() {
  var names = Object.keys(state.sectionRouting);
  if (names.length === 0) return null;
  if (typeof uci.unload === 'function') uci.unload('purewrt');
  return uci.load('purewrt').then(function() {
    var existing = {};
    (uci.sections('purewrt', 'section') || []).forEach(function(s) { existing[s['.name']] = true; });
    var mutated = 0;
    names.forEach(function(name) {
      if (!existing[name]) return; // import/reset didn't create this section — skip
      var r = state.sectionRouting[name];
      uci.set('purewrt', name, 'action', r.action);
      if (r.action === 'proxy') {
        uci.set('purewrt', name, 'proxy_group_type', r.proxy.type);
        uci.set('purewrt', name, 'proxy_filter', r.proxy.filter);
        uci.set('purewrt', name, 'proxy_exclude_filter', r.proxy.exclude);
        uci.set('purewrt', name, 'proxy_strategy', r.proxy.strategy);
        uci.set('purewrt', name, 'user_overridden_proxy_group', '1');
        uci.unset('purewrt', name, 'vpn');
        uci.unset('purewrt', name, 'zapret_strategy');
      } else if (r.action === 'vpn') {
        uci.set('purewrt', name, 'vpn', r.vpn || '');
        uci.unset('purewrt', name, 'zapret_strategy');
      } else if (r.action === 'zapret') {
        uci.set('purewrt', name, 'zapret_strategy', r.zapret || []);
        uci.unset('purewrt', name, 'vpn');
      } else {
        // direct / reject — clear protocol-specific options.
        uci.unset('purewrt', name, 'vpn');
        uci.unset('purewrt', name, 'zapret_strategy');
      }
      mutated++;
    });
    if (mutated === 0) return null;
    return uci.save().then(function() {
      return uci.apply();
    }).then(function() {
      return callReload();
    });
  });
}

// applyRuleOverrides walks the user's per-provider edits and writes them
// onto the rule_provider sections the just-finished import wrote. Each
// rule_provider lives as an anonymous UCI section keyed by `.name` (the
// internal UCI section id) with a `name` option (the user-visible name);
// we look up by `name` to find the right section to mutate.
function applyRuleOverrides() {
  // Force a fresh read of /etc/config/purewrt so uci.sections sees the
  // newly-imported rule providers (uci's in-memory cache from page load
  // doesn't know about them).
  if (typeof uci.unload === 'function') uci.unload('purewrt');
  return uci.load('purewrt').then(function() {
    var sections = uci.sections('purewrt', 'rule_provider') || [];
    var mutated = 0;
    sections.forEach(function(sec) {
      var name = sec.name;
      var ov = state.ruleOverrides[name];
      if (!ov) return;
      var sid = sec['.name'];
      if (ov.ignored) {
        uci.set('purewrt', sid, 'enabled', '0');
        mutated++;
        return;
      }
      if (sec.section !== ov.section) {
        uci.set('purewrt', sid, 'section', ov.section);
        // Recompute route_action too so the per-section nft chain treats
        // the provider's IPs correctly. PureWRT regenerates everything on
        // apply, but the route_action is also used by the LuCI rule
        // providers tab as the "action" badge.
        var routeAction = ov.section === 'direct' ? 'direct'
          : ov.section === 'reject' ? 'reject'
          : 'proxy';
        uci.set('purewrt', sid, 'route_action', routeAction);
        mutated++;
      }
    });
    if (mutated === 0) return null;
    return uci.save().then(function() {
      return uci.apply();
    }).then(function() {
      // Trigger an actual purewrt apply so the new section assignments
      // hit the live nft/dnsmasq state.
      return callReload();
    });
  });
}

// ---- Renderer ----

// ---- Step 2 (default lists): map each published list to a section ----

function renderStep2Default() {
  var rows = [];
  if (!state.defaultLists || state.defaultLists.length === 0) {
    rows.push(E('div', { 'class': 'purewrt-banner purewrt-banner-warn' },
      _('No default lists available. Check the "default_lists_base_url" setting and that the catalog is reachable, or pick another source.')));
  }
  (state.defaultLists || []).forEach(function(entry) {
    var st = state.listMap[entry.name] || { section: entry.suggested_section || 'common', enabled: true };
    state.listMap[entry.name] = st;
    var chk = E('input', { 'type': 'checkbox', 'checked': st.enabled ? 'checked' : null });
    chk.addEventListener('change', function() { st.enabled = chk.checked; });
    var counts = [];
    if (entry.domains) counts.push(entry.domains + ' ' + _('domains'));
    if (entry.subnets) counts.push(entry.subnets + ' ' + _('subnets'));
    rows.push(E('div', { 'style': 'margin:.5em 0;display:flex;align-items:center;gap:.5em;flex-wrap:wrap' }, [
      E('label', { 'style': 'display:flex;gap:.4em;align-items:center' }, [ chk, E('strong', {}, entry.name) ]),
      E('span', { 'class': 'purewrt-text-dim' }, counts.length ? '(' + counts.join(', ') + ')' : '')
    ]));
  });
  // Proxy nodes URL — imported proxy-only (no rules), giving the proxy
  // sections an actual backend. Optional: sections routed via VPN don't need it.
  var proxyInput = E('input', {
    'class': 'cbi-input-text', 'type': 'text', 'style': 'width:100%;max-width:42em',
    'placeholder': _('https://… (Clash/mihomo subscription or proxy list)'),
    'value': state.proxyUrl
  });
  // Changing the URL invalidates a prior preview — its servers are re-fetched
  // automatically when the Routing step opens (see ensureProxyPreview).
  proxyInput.addEventListener('input', function() {
    state.proxyUrl = proxyInput.value.trim();
    state.proxyNodeNames = null;
    state.proxyPreviewError = null;
  });
  var proxyBlock = E('div', { 'style': 'margin:.75em 0' }, [
    E('label', { 'style': 'display:block;font-weight:bold;margin-bottom:.25em' }, _('Proxy nodes URL (optional)')),
    E('p', { 'class': 'purewrt-text-dim', 'style': 'margin:.1em 0 .4em' }, _('A mihomo/Clash subscription or proxy list. Imported proxy-only (no rules) — this is what the proxy sections route through. Leave blank if every section is routed via VPN. Its servers are fetched automatically on the next step.')),
    proxyInput
  ]);

  return E('div', { 'class': 'purewrt-card' }, [
    E('h3', {}, _('Default lists')),
    E('p', { 'class': 'purewrt-text-dim' }, _('Pick which published lists to use. The next step (Routing) maps each to a section and picks the per-section protocol (proxy / VPN / zapret) + servers.')),
    E('div', {}, rows),
    proxyBlock,
    navButtons()
  ]);
}

function currentStep() {
  switch (state.step) {
    // Step numbering changed when Routing was inserted at position 3.
    // The old renderStep3..renderStep8 functions cover what are now
    // steps 4..9 (Profile, IPv6, DNS, Schedule, VPN, Review).
    case 1: return renderStep1();         // Source
    case 2: return state.source === 'default' ? renderStep2Default() : renderStep2();
    case 3: return renderRoutingBoard();  // Routing (shared drag-flow; skipped per shouldSkipRouting)
    case 4: return renderStep3();         // Profile
    case 5: return renderStep4();         // IPv6
    case 6: return renderStep5();         // Bootstrap DNS
    case 7: return renderStep6();         // Updates & Dashboard
    case 8: return renderStep7();         // VPN reminder
    case 9: return renderStep8();         // Review + Apply
  }
  return renderStep1();
}

var rootEl = null;
function renderApp() {
  if (!rootEl) return;
  var c = E('div', {}, [
    stepperHeader(),
    currentStep()
  ]);
  rootEl.innerHTML = '';
  rootEl.appendChild(c);
}

function parseStepFromURL() {
  var m = /[?&]step=(\d+)/.exec(window.location.search);
  if (!m) return null;
  var n = parseInt(m[1], 10);
  if (n < 1 || n > WIZARD_STEPS) return null;
  return n;
}

// detectIPv6WANInterfaces walks LuCI's network model and returns the
// section names + protocols of every interface that's v6-capable. We treat
// these as "candidates the user might want to disable when turning off
// IPv6". Same filter as the Go side: proto=dhcpv6, plus the obvious
// 6in4/6rd tunnels and any static interface with v6 addressing.
function detectIPv6WANInterfaces() {
  return network.getNetworks().then(function(nets) {
    var out = [];
    (nets || []).forEach(function(n) {
      var proto = (n.getProtocol && n.getProtocol()) || '';
      var name = (n.getName && n.getName()) || '';
      if (!name || name === 'loopback' || name === 'lan') return;
      // Proto is the authoritative signal — these are all v6-specific.
      // Name match (ends in '6' or '_6') catches static interfaces that
      // happen to be named after v6 by convention but use a generic proto.
      // `wan` doesn't end in 6 so it's correctly excluded.
      var match = (proto === 'dhcpv6' || proto === '6in4' || proto === '6rd' ||
                   proto === '6to4'   || proto === 'aiccu' ||
                   /6$/.test(name));
      if (!match) return;
      out.push({ name: name, proto: proto, label: name });
    });
    // Sort: known "wan6" first (most common), then alphabetical.
    out.sort(function(a, b) {
      if (a.name === 'wan6') return -1;
      if (b.name === 'wan6') return 1;
      return a.name.localeCompare(b.name);
    });
    return out;
  }).catch(function() { return []; });
}

return view.extend({
  load: function() {
    return Promise.all([
      uci.load('purewrt'),
      detectIPv6WANInterfaces(),
      callZapretInstalled().catch(function() { return false; }),
      callDefaultListsCatalog().catch(function() { return []; })
    ]);
  },
  render: function(data) {
    state = makeInitialState();
    state.ipv6WanDetected = (data && data[1]) || [];
    state.zapretInstalled = !!(data && data[2]);
    state.defaultLists = (data && data[3]) || [];
    // Seed the saved-interfaces list with detected ones when nothing was
    // saved yet — gives the user a sensible default ("disable everything
    // detected") instead of an empty checkbox grid.
    if (state.ipv6WanInterfaces.length === 0 && state.ipv6WanDetected.length > 0) {
      state.ipv6WanInterfaces = state.ipv6WanDetected.map(function(d) { return d.name; });
    }
    var urlStep = parseStepFromURL();
    if (urlStep) {
      // ?step=N jumps directly. Default source to 'subscription' so step 2
      // renders correctly when jumped to from the Subscriptions page's
      // "Add via wizard" link.
      state.step = urlStep;
      if (urlStep >= 2) state.source = 'subscription';
    }
    rootEl = E('div', { 'class': 'cbi-map' }, [
      E('h2', {}, _('PureWRT setup wizard'))
    ]);
    // Defer initial render so rootEl is already mounted (renderApp uses
    // innerHTML on the live node).
    window.setTimeout(renderApp, 0);
    return rootEl;
  }
});
