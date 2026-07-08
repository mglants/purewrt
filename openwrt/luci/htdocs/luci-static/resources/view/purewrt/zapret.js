'use strict';
'require view';
'require form';
'require rpc';
'require ui';
'require network';
'require uci';
'require purewrt.styles';
'require purewrt.table_section as tableSection';
'require purewrt.save_chain as saveChain';

// callZapretInstalled tells us whether the optional Zapret package is on
// the box. The view's load() runs this; render() short-circuits to a
// "not installed" placeholder before building the (heavy) form when
// the check returns false. expect:{installed:false} means rpcd permission
// problems also fall through to the placeholder rather than throwing.
var callZapretInstalled = rpc.declare({ object: 'purewrt', method: 'zapret_installed', expect: { installed: false } });
// apk_updates_available returns an envelope object because ubus rejects
// top-level JSON arrays; expect.updates unwraps it back to the array.
var callApkUpdates = rpc.declare({ object: 'purewrt', method: 'apk_updates_available', params: [ 'force' ], expect: { updates: [] } });

// The Blockcheck tool (merged single-host + multi-host). `hosts` is one or
// more whitespace-separated domains; the CLI splits on whitespace and, for
// 2+ hosts, blockcheck2.sh emits a COMMON-intersection strategy.
var callZapretCheck = rpc.declare({ object: 'purewrt', method: 'zapret_check', params: [ 'hosts', 'interface', 'scan', 'repeats', 'http', 'tls12', 'tls13', 'http3', 'https_get' ] });
var callZapretCheckStart = rpc.declare({ object: 'purewrt', method: 'zapret_check_start', params: [ 'hosts', 'interface', 'scan', 'repeats', 'http', 'tls12', 'tls13', 'http3', 'https_get' ] });
var callZapretCheckStatus = rpc.declare({ object: 'purewrt', method: 'zapret_check_status', params: [ ] });
var callZapretCheckStop = rpc.declare({ object: 'purewrt', method: 'zapret_check_stop' });
var callZapretCompiledOpt = rpc.declare({ object: 'purewrt', method: 'zapret_compiled_opt', expect: { output: '' } });
// zapret_blobs lists shipped nfqws2 fake-payload .bin files for the profile
// blob picker. Envelope object (ubus rejects top-level arrays) unwrapped to [].
var callZapretBlobs = rpc.declare({ object: 'purewrt', method: 'zapret_blobs', expect: { blobs: [] } });
var callZapretRestart = rpc.declare({ object: 'purewrt', method: 'zapret_restart' });
// Shared strategy candidate list (single source of truth — embed / /etc /
// purewrt-lists, resolved by the CLI). Drives both the preset dropdown and the
// strategy tester; replaces the old hardcoded ZAPRET_PRESETS.
var callZapretCandidates = rpc.declare({ object: 'purewrt', method: 'zapret_candidates', expect: { candidates: [] } });
var callZapretStrategyTest = rpc.declare({ object: 'purewrt', method: 'zapret_strategy_test', params: [ 'name', 'interface', 'sites', 'download', 'suite' ] });
var callZapretSweepStart = rpc.declare({ object: 'purewrt', method: 'zapret_strategy_sweep_start', params: [ 'interface', 'sites', 'isp', 'download', 'suite' ] });
var callZapretSweepStatus = rpc.declare({ object: 'purewrt', method: 'zapret_strategy_sweep_status', params: [ ] });

// zapretPresets maps candidate name → its object (protocols/ports/pkt/params/
// blobs), populated in render() from the fetched candidate list. applyPresetTo
// reads it to fill the strategy-editor fields.
var zapretPresets = {};

// applyPresetTo uses each form option's widget instance to write the preset
// values. The previous DOM-poking helpers (querySelectorAll on
// `[data-widget-id]` / `[id$="..."]`) matched the wrapper DIVs instead of
// the real input/select/cbi-dropdown elements, so changing the preset
// silently did nothing in the LuCI modal. `option.getUIElement(sectionId)`
// returns the widget object LuCI created for that section, which exposes a
// `setValue` that handles inputs, dropdowns, and MultiValue uniformly.
// setSimpleWidget writes to a plain <input>/<select>/<textarea> by its
// LuCI widget id, then dispatches the events LuCI listens for so the form
// model registers the change.
function setSimpleWidget(sectionId, option, value) {
  var el = document.querySelector('[id="widget.cbid.purewrt.' + sectionId + '.' + option + '"]');
  if (!el) return false;
  el.value = (value == null) ? '' : value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
}

// setMultiDropdown drives LuCI's cbi-dropdown widget (used by MultiValue):
// it toggles the `selected` attribute on each <li data-value>, rewrites the
// hidden input that holds the joined value, and dispatches a `widget-change`
// event on the wrapper so the form model picks the new selection up. We
// don't try to call the dropdown's own JS class — accessing it via
// `findClassInstance` returns null after the section is moved into a modal.
function setMultiDropdown(sectionId, option, values) {
  var wrap = document.querySelector('[id="cbid.purewrt.' + sectionId + '.' + option + '"]');
  if (!wrap) return false;
  var want = {};
  (values || []).forEach(function(v) { want[v] = true; });
  var picked = [];
  wrap.querySelectorAll('li[data-value]').forEach(function(li) {
    var v = li.getAttribute('data-value');
    if (want[v]) {
      li.setAttribute('selected', '');
      picked.push(v);
    } else {
      li.removeAttribute('selected');
    }
  });
  var hidden = wrap.querySelector('input[type=hidden]');
  if (hidden) hidden.value = picked.join(' ');
  wrap.setAttribute('data-changed', 'true');
  wrap.dispatchEvent(new CustomEvent('cbi-dropdown-change', { bubbles: true }));
  wrap.dispatchEvent(new CustomEvent('widget-change', { bubbles: true }));
  return true;
}

// applyPresetTo pushes the preset's values into each dependent field.
// Uses direct DOM-by-id selectors rather than `option.getUIElement` because
// the latter returns null once the section wrapper is moved into LuCI's
// modal (the bound class instance gets detached).
function applyPresetTo(sectionId, presetKey, fields) {
  var data = zapretPresets[presetKey];
  if (!data) return;
  Object.keys(fields).forEach(function(key) {
    var optName = fields[key];
    if (!optName) return;
    var val = data[key];
    if (key === 'protocols')
      setMultiDropdown(sectionId, optName, val);
    else
      setSimpleWidget(sectionId, optName, val);
  });
}

// profileTitle never surfaces a raw cfgXXXX section id. Falls back through the
// friendly fields (name -> OpenWrt network -> first Linux interface) before
// giving up to the section id, so anonymous profiles still read sensibly.
function profileTitle(sid) {
  var name = uci.get('purewrt', sid, 'name');
  if (name) return name;
  var net = uci.get('purewrt', sid, 'network');
  if (net) return net;
  var ifaces = uci.get('purewrt', sid, 'interface');
  if (Array.isArray(ifaces)) ifaces = ifaces[0];
  if (ifaces) return ifaces;
  return sid || _('New profile');
}

function strategyTitle(sid) {
  return uci.get('purewrt', sid, 'name') || sid || _('New strategy');
}

function strategyProtocols(sid) {
  var v = uci.get('purewrt', sid, 'protocols') || uci.get('purewrt', sid, 'protocol') || [ 'tcp' ];

  if (!Array.isArray(v))
    v = String(v).split(/\s+/);

  return v.filter(function(x) { return x; }).join(', ') || 'tcp';
}

function strategyPorts(sid) {
  var out = [];
  var tcp = uci.get('purewrt', sid, 'tcp_ports');
  var udp = uci.get('purewrt', sid, 'udp_ports');

  if (tcp)
    out.push('tcp:' + tcp);
  if (udp)
    out.push('udp:' + udp);

  return out.join(' ') || '-';
}

function strategySummary(sid) {
  var queue = uci.get('purewrt', sid, 'queue_num');

  return [
    strategyTitle(sid),
    uci.get('purewrt', sid, 'preset') || 'custom',
    uci.get('purewrt', sid, 'profile') || 'wan',
    strategyProtocols(sid),
    strategyPorts(sid),
    queue && queue !== '0' ? queue : 'auto'
  ];
}

function profileSummary(sid) {
  var mode = uci.get('purewrt', sid, 'interface_mode') || 'mwan3_members';
  var net = uci.get('purewrt', sid, 'network') || '';
  var ifaces = uci.get('purewrt', sid, 'interface');
  if (Array.isArray(ifaces))
    ifaces = ifaces.join(',');
  else
    ifaces = ifaces || '';
  var target = ifaces || net || '-';
  return [
    profileTitle(sid),
    mode,
    target,
    uci.get('purewrt', sid, 'fwmark') || 'auto'
  ];
}

// Match a section by its rendered LuCI wrapper id (`cbi-<package>-<type>`).
// The bare `data-section-type` attribute is NOT emitted by LuCI, so the old
// `getAttribute('data-section-type')` filter rejected every node and tableSection
// silently no-op'd. Walking up to the wrapper gives a reliable section-type test.
function inWrapper(wrapperId) {
  return function(node) {
    var p = node.closest('.cbi-section');
    return !!(p && p.id === wrapperId);
  };
}

// devName coerces a LuCI network device to its name string. getL3Device() /
// getDevice() return a Device OBJECT on this LuCI (26.x) — not a name — so we
// must call .getName(); older versions return the string directly. Handle both.
function devName(x) {
  if (!x) return '';
  if (typeof x === 'string') return x;
  if (typeof x.getName === 'function') {
    var n = x.getName();
    return (typeof n === 'string') ? n : '';
  }
  return '';
}

// wanDeviceOf resolves an OpenWrt network to the Linux device blockcheck2.sh
// should bind curl to (--interface). Prefers the L3 device, falls back to the
// primary device. Returns '' for deviceless/down networks (e.g. an mbim WAN
// that isn't up), which the picker skips.
function wanDeviceOf(net) {
  if (!net) return '';
  var n = '';
  if (typeof net.getL3Device === 'function') n = devName(net.getL3Device());
  if (!n && typeof net.getDevice === 'function') n = devName(net.getDevice());
  return n;
}

// buildWanSelect builds the interface picker as OpenWrt logical networks:
// the OPTION LABEL is the friendly network name ("wStarlink"), the VALUE is the
// resolved Linux device ("br-lan.3000") that reaches blockcheck2.sh. Defaults
// to the active-WAN network (default route) so the probe egresses the real
// internet path instead of the first bridge — the bug that made every probe
// time out. Falls back to WAN6, then the first usable network.
function buildWanSelect(networks, wanNets, wan6Nets) {
  var sel = E('select', { 'class': 'cbi-input-select' });
  var wanName = '';
  if (wanNets && wanNets[0]) wanName = wanNets[0].getName();
  else if (wan6Nets && wan6Nets[0]) wanName = wan6Nets[0].getName();
  var defaultDev = '', count = 0;
  (networks || []).forEach(function(net) {
    var name = net.getName && net.getName();
    if (!name || name === 'loopback' || name === 'lo') return;
    var dev = wanDeviceOf(net);
    if (!dev) return;
    sel.appendChild(E('option', { 'value': dev }, name + ' (' + dev + ')'));
    if (name === wanName && !defaultDev) defaultDev = dev;
    if (!defaultDev) defaultDev = dev; // running first-usable fallback
    count++;
  });
  if (!count) {
    sel.appendChild(E('option', { 'value': '' }, _('(default route)')));
  } else {
    // Prefer the WAN device if we matched one; otherwise the first option.
    var wanDev = '';
    (networks || []).forEach(function(net) {
      if (net.getName && net.getName() === wanName) { var d = wanDeviceOf(net); if (d) wanDev = d; }
    });
    sel.value = wanDev || defaultDev;
  }
  return sel;
}

// stratFromTestLine normalizes a "- curl_test_... : <daemon> <strategy>" line
// to just the nfqws clause (drops the leading daemon token).
function stratFromTestLine(line) {
  var parts = line.split(' : ');
  if (parts.length < 2) return '';
  var strat = parts[parts.length - 1].replace(/!!!!!\s*$/, '').trim();
  var fields = strat.split(/\s+/);
  if (fields.length > 1 && fields[0].indexOf('--') !== 0) strat = fields.slice(1).join(' ');
  return strat;
}

// parseBlockcheckStrategies scrapes working strategies from raw blockcheck2.sh
// output. Three sources, deduped by exact clause: (1) LIVE per-test winners — a
// "- curl_test... : nfqws <strat>" line immediately followed by "AVAILABLE" —
// so strategies show up during the run, not only at the end; (2) the curated
// "working strategy found !!!!!" summary lines; (3) the multi-host "* COMMON"
// intersection block. Returns [{ params, common }].
function parseBlockcheckStrategies(text) {
  var out = [], seen = {};
  var push = function(strat, common) {
    if (!strat) return;
    var key = (common ? 'C:' : '') + strat;
    if (seen[key]) return;
    seen[key] = true;
    out.push({ params: strat, common: !!common });
  };
  var lines = (text || '').split('\n');

  // (1) live winners: remember the last test line, commit it on AVAILABLE.
  var pending = '';
  lines.forEach(function(line) {
    if (line.indexOf('curl_test') >= 0 && line.indexOf(' : ') >= 0 && line.replace(/^\s+/, '').indexOf('-') === 0) {
      pending = stratFromTestLine(line);
    } else if (/!!!!!\s*AVAILABLE/.test(line)) {
      push(pending, false);
      pending = '';
    }
  });

  // (2) curated per-host winners.
  lines.forEach(function(line) {
    if (line.indexOf('working strategy found') < 0 || line.indexOf('!!!!!') < 0) return;
    push(stratFromTestLine(line), false);
  });

  // (3) COMMON intersection block.
  var ci = (text || '').indexOf('* COMMON');
  if (ci >= 0) {
    var tail = text.substring(ci);
    var end = tail.indexOf('Please note this SUMMARY');
    if (end >= 0) tail = tail.substring(0, end);
    tail.split('\n').forEach(function(line) {
      line = line.trim();
      if (line.indexOf('--') === 0) push(line, true);
    });
  }
  return out;
}

// blockcheckVerdict explains a zero-strategy result so an empty list isn't read
// as "everything blocked". Distinguishes a bad test domain (cert-CN mismatch)
// and an unreachable baseline (link/route/IP-block) from a real DPI verdict.
function blockcheckVerdict(text, foundCount) {
  if (foundCount > 0) return '';
  var t = text || '';
  var cert = (t.match(/does not match|code=60/g) || []).length;
  var curlTests = (t.match(/curl_test/g) || []).length;
  if (cert > 0 && curlTests > 0 && cert >= curlTests)
    return _('All probes failed TLS certificate verification — this domain has no valid cert for its exact name (bare CDN names like googlevideo.com fail). Not a DPI result: try youtube.com or a specific host.');
  if (/code=28|code=000|Connection timed out/.test(t))
    return _('The baseline (no-bypass) probe failed — the host is unreachable direct on this interface (link / route / IP-block). This result is inconclusive, not a DPI verdict. Check the WAN interface selection and that the host is reachable.');
  // Format drift: blockcheck2.sh emitted its success markers, but the parser
  // extracted nothing. Distinguishes a genuinely all-blocked run (no markers)
  // from a broken parser (markers present, zero clauses) so an upstream output
  // change surfaces as an explicit notice instead of a silent empty list.
  if (/working strategy found|!!!!!\s*AVAILABLE|\* COMMON/.test(t))
    return _('Blockcheck reported working strategies, but PureWRT could not parse them — the blockcheck2.sh output format may have changed. See the raw output below and report this.');
  return '';
}

// stageStrategyFromParams stages (does NOT write) a zapret_strategy from one
// blockcheck winner. It appears in LuCI's Unsaved Changes; Save & Apply
// commits it. Protocols/ports come from the nfqws --filter-tcp/udp clause when
// present, else from the card's protocol toggles. Returns the derived name.
function stageStrategyFromParams(params, common, hostsLabel, protoDefaults) {
  var sid = uci.add('purewrt', 'zapret_strategy');
  var base = (common ? 'bc_common' : 'bc_' + (hostsLabel || 'host'));
  base = base.replace(/[^A-Za-z0-9_]+/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '') || 'bc';
  var existing = {};
  uci.sections('purewrt', 'zapret_strategy').forEach(function(s) {
    var n = s.name || s['.name']; if (n) existing[n] = true;
  });
  var name = base, i = 2;
  while (existing[name]) { name = base + '_' + i; i++; }
  uci.set('purewrt', sid, 'name', name);
  uci.set('purewrt', sid, 'enabled', '1');
  uci.set('purewrt', sid, 'profile', 'wan');
  uci.set('purewrt', sid, 'preset', 'custom');
  uci.set('purewrt', sid, 'params', params);
  var protos = [], tcpPorts = '', udpPorts = '';
  var mt = params.match(/--filter-tcp=(\S+)/); if (mt) { protos.push('tcp'); tcpPorts = mt[1]; }
  var mu = params.match(/--filter-udp=(\S+)/); if (mu) { protos.push('udp'); udpPorts = mu[1]; }
  if (!protos.length && protoDefaults) {
    protos = protoDefaults.protocols || [];
    tcpPorts = protoDefaults.tcp_ports || '';
    udpPorts = protoDefaults.udp_ports || '';
  }
  if (protos.length) uci.set('purewrt', sid, 'protocols', protos);
  if (tcpPorts) uci.set('purewrt', sid, 'tcp_ports', tcpPorts);
  if (udpPorts) uci.set('purewrt', sid, 'udp_ports', udpPorts);
  return name;
}

// stageCandidate stages a full candidate (from the shared list) as a
// zapret_strategy — its params/protocols/ports plus any blob decls added to
// the wan profile's Custom-blobs list (pointing at the shipped fake dir; the
// router's ResolveBlob prefers the shipped copy). Returns the staged name.
function stageCandidate(cand) {
  var sid = uci.add('purewrt', 'zapret_strategy');
  var existing = {};
  uci.sections('purewrt', 'zapret_strategy').forEach(function(s) { var n = s.name || s['.name']; if (n) existing[n] = true; });
  var name = cand.name, i = 2;
  while (existing[name]) { name = cand.name + '_' + i; i++; }
  uci.set('purewrt', sid, 'name', name);
  uci.set('purewrt', sid, 'enabled', '1');
  uci.set('purewrt', sid, 'profile', 'wan');
  uci.set('purewrt', sid, 'preset', 'custom');
  uci.set('purewrt', sid, 'params', cand.params);
  if (cand.protocols && cand.protocols.length) uci.set('purewrt', sid, 'protocols', cand.protocols);
  if (cand.tcp_ports) uci.set('purewrt', sid, 'tcp_ports', cand.tcp_ports);
  if (cand.udp_ports) uci.set('purewrt', sid, 'udp_ports', cand.udp_ports);
  (cand.blobs || []).forEach(function(b) {
    if (!b.name || !b.file) return;
    var decl = b.name + ':@/usr/libexec/zapret/files/fake/' + b.file;
    uci.sections('purewrt', 'zapret_profile').forEach(function(p) {
      var psid = p['.name'];
      if ((p.name || psid) !== 'wan') return;
      var cur = uci.get('purewrt', psid, 'blob') || [];
      if (!Array.isArray(cur)) cur = cur ? [cur] : [];
      if (cur.indexOf(decl) < 0) { cur.push(decl); uci.set('purewrt', psid, 'blob', cur); }
    });
  });
  return name;
}

// renderZapretStatusBlock is a config-derived (no live probe) summary shown at
// the top of the page: enabled profiles/strategies, which routing sections use
// Action=zapret, and a quiet note when a strategy is enabled but nothing routes
// to it (so it silently won't take effect). Not a global DoctorWarning —
// advanced users configure zapret deliberately.
function renderZapretStatusBlock() {
  function flagOn(s) { return s.enabled === '1'; }
  var profiles = uci.sections('purewrt', 'zapret_profile').filter(flagOn);
  var strategies = uci.sections('purewrt', 'zapret_strategy').filter(flagOn);
  var sections = uci.sections('purewrt', 'section');
  var zapretSections = sections.filter(function(s) { return s.enabled !== '0' && s.action === 'zapret'; });
  var nameOf = function(s) { return s.name || s['.name']; };

  var rows = [];
  rows.push(E('div', {}, [
    E('strong', {}, _('Enabled profiles: ')),
    profiles.length ? profiles.map(nameOf).join(', ') : _('none')
  ]));
  rows.push(E('div', {}, [
    E('strong', {}, _('Enabled strategies: ')),
    strategies.length ? strategies.map(nameOf).join(', ') : _('none')
  ]));
  rows.push(E('div', {}, [
    E('strong', {}, _('Routing sections using Zapret: ')),
    zapretSections.length ? zapretSections.map(nameOf).join(', ') : _('none')
  ]));
  if (strategies.length > 0 && zapretSections.length === 0) {
    rows.push(E('div', { 'class': 'alert-message warning', 'style': 'margin-top:.5em' },
      _('%d zapret strategy(ies) are enabled, but no routing section has Action = Zapret — they will not take effect. Set a section\'s Action to Zapret on the Sections / Routing page.').format(strategies.length)));
  }
  return E('div', { 'class': 'cbi-section purewrt-card', 'style': 'margin-bottom:1em' }, [
    E('h3', {}, _('Zapret status')),
    E('div', { 'style': 'display:flex;flex-direction:column;gap:.25em' }, rows)
  ]);
}

// renderBlockcheckCard is the merged DPI-bypass finder (former manual blockcheck
// + autotune). 1 host = single-host debug; 2+ hosts = COMMON-intersection run.
// Streams live output via the background job, lists working strategies with a
// Create button (staged, never auto-written), and explains empty results.
function renderBlockcheckCard(networks, wanNets, wan6Nets) {
  var input = E('input', { 'class': 'cbi-input-text', 'style': 'width:100%;max-width:36em', 'placeholder': 'youtube.com rutracker.org' });
  var wan = buildWanSelect(networks, wanNets, wan6Nets);
  var scan = E('select', { 'class': 'cbi-input-select' }, [
    E('option', { 'value': 'quick' }, _('quick')),
    E('option', { 'value': 'standard' }, _('standard')),
    E('option', { 'value': 'force' }, _('force'))
  ]);
  var repeats = E('input', { 'class': 'cbi-input-text', 'value': '1', 'style': 'width:6em' });
  var http = E('input', { 'type': 'checkbox' });
  var tls12 = E('input', { 'type': 'checkbox', 'checked': 'checked' });
  var tls13 = E('input', { 'type': 'checkbox', 'checked': 'checked' });
  var http3 = E('input', { 'type': 'checkbox' });
  var httpsGet = E('input', { 'type': 'checkbox' });
  var verdict = E('div', { 'class': 'alert-message warning', 'style': 'display:none;margin:.5em 0' });
  var strategiesBox = E('div', { 'style': 'margin:.5em 0' });
  var out = E('pre', { 'style': 'white-space:pre-wrap;max-height:32em;overflow:auto;font-family:monospace;font-size:.85em;background:#1a1a1a;padding:.5em;border-radius:4px' });
  var pollTimer = null;
  // Accumulate found strategies across polls. poll_bg_job only returns the last
  // ~500 lines of the log, so early winners scroll out of the tail window — we
  // must remember them here or they'd vanish from the list mid-run. Keyed by
  // clause; a clause seen in the COMMON block is upgraded to common=true.
  var acc = {}, accOrder = [];
  function resetAcc() { acc = {}; accOrder = []; }
  function mergeStrategies(list) {
    (list || []).forEach(function(s) {
      if (!acc[s.params]) { acc[s.params] = { params: s.params, common: !!s.common }; accOrder.push(s.params); }
      else if (s.common) { acc[s.params].common = true; }
    });
  }
  function checked(v) { return v.checked ? '1' : '0'; }
  function protoDefaults() {
    var protos = [], tcp = '', udp = '';
    if (tls12.checked || tls13.checked || http.checked || httpsGet.checked) { protos.push('tcp'); tcp = '443'; }
    if (http3.checked) { protos.push('udp'); udp = '443'; }
    if (!protos.length) { protos = [ 'tcp' ]; tcp = '443'; }
    return { protocols: protos, tcp_ports: tcp, udp_ports: udp };
  }
  function hostsLabel() { return ((input.value || '').trim().split(/\s+/)[0]) || 'host'; }
  function renderStrategies(text) {
    strategiesBox.innerHTML = '';
    // Verdict only when NOTHING has been found across the whole run.
    var v = blockcheckVerdict(text, accOrder.length);
    if (v) { verdict.textContent = v; verdict.style.display = ''; }
    else { verdict.style.display = 'none'; }
    if (!accOrder.length) return;
    strategiesBox.appendChild(E('h4', {}, _('Working strategies (%d)').format(accOrder.length)));
    accOrder.forEach(function(key) {
      var s = acc[key];
      var btn = E('button', { 'class': 'btn cbi-button cbi-button-add' }, [ _('Create strategy') ]);
      btn.addEventListener('click', function(ev) {
        ev.preventDefault();
        var name = stageStrategyFromParams(s.params, s.common, hostsLabel(), protoDefaults());
        btn.disabled = true;
        btn.textContent = _('Staged: %s').format(name);
        ui.addNotification(null, E('p', _('Strategy "%s" staged. Review it in Unsaved Changes, then Save & Apply to create it.').format(name)), 'info');
      });
      strategiesBox.appendChild(E('div', { 'style': 'display:flex;gap:.5em;align-items:center;margin:.25em 0;flex-wrap:wrap' }, [
        s.common ? E('span', { 'class': 'purewrt-pill run', 'style': 'flex:0 0 auto' }, _('COMMON'))
                 : E('span', { 'style': 'flex:0 0 auto;opacity:.6' }, '•'),
        E('code', { 'style': 'flex:1 1 20em;word-break:break-all;background:#21262d;padding:.15em .4em;border-radius:3px' }, s.params),
        btn
      ]));
    });
  }
  function stopPolling() {
    if (pollTimer) { window.clearTimeout(pollTimer); pollTimer = null; }
  }
  function setRunning(on) {
    stopBtn.style.display = on ? '' : 'none';
    runBtn.disabled = !!on;
  }
  function renderStatus(r) {
    var text = r.output || '';
    out.textContent = text || _('Running blockcheck...');
    out.scrollTop = out.scrollHeight;
    mergeStrategies(parseBlockcheckStrategies(text));
    renderStrategies(text);
  }
  function pollStatus() {
    return callZapretCheckStatus().then(function(r) {
      renderStatus(r);
      if (r.running === 1 || r.running === true) {
        setRunning(true);
        pollTimer = window.setTimeout(pollStatus, 1500);
      } else {
        setRunning(false);
        if (r.rc && r.rc !== '0' && r.rc !== '143')
          ui.addNotification(null, E('p', _('Blockcheck exited with an error. See output below.')), 'warning');
      }
    }).catch(function(e) {
      stopPolling();
      setRunning(false);
      ui.addNotification(null, E('p', e.message), 'danger');
    });
  }
  // Reattach on load: resume polling if a run is live, or show the last
  // completed run's output (survives tab close / page revisit).
  function attachRunningCheck() {
    return callZapretCheckStatus().then(function(r) {
      if (r.running === 1 || r.running === true) {
        setRunning(true);
        renderStatus(r);
        pollTimer = window.setTimeout(pollStatus, 1500);
      } else if (r.rc !== undefined && r.rc !== null && r.rc !== '' && (r.output || '').length > 0) {
        renderStatus(r);
      } else {
        out.textContent = '';
      }
    }).catch(function(e) {
      ui.addNotification(null, E('p', e.message), 'danger');
    });
  }
  window.setTimeout(attachRunningCheck, 0);
  var runBtn = E('button', { 'class': 'btn cbi-button cbi-button-action' }, [ _('Run blockcheck') ]);
  var stopBtn = E('button', { 'class': 'btn cbi-button cbi-button-remove', 'style': 'display:none;margin-left:.5em' }, [ _('Stop') ]);
  stopBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    stopBtn.disabled = true;
    return callZapretCheckStop().then(function() {
      stopPolling();
      setRunning(false);
      stopBtn.disabled = false;
      ui.addNotification(null, E('p', _('Blockcheck stopped.')), 'info');
      // one final status read to show the stopped output tail
      return callZapretCheckStatus().then(renderStatus);
    }).catch(function(e) {
      stopBtn.disabled = false;
      ui.addNotification(null, E('p', e.message), 'danger');
    });
  });
  runBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    var raw = (input.value || '').trim();
    if (!raw) {
      ui.addNotification(null, E('p', _('Enter at least one host.')), 'warning');
      return;
    }
    stopPolling();
    resetAcc();
    strategiesBox.innerHTML = '';
    verdict.style.display = 'none';
    out.textContent = _('Running blockcheck...');
    setRunning(true);
    return callZapretCheckStart(raw, wan.value, scan.value, repeats.value, checked(http), checked(tls12), checked(tls13), checked(http3), checked(httpsGet)).then(function(r) {
      if (r.result === 'busy') {
        ui.addNotification(null, E('p', _('A blockcheck is already running. Showing its current output.')), 'warning');
      } else if (r.result !== 'started') {
        setRunning(false);
        return callZapretCheck(raw, wan.value, scan.value, repeats.value, checked(http), checked(tls12), checked(tls13), checked(http3), checked(httpsGet)).then(function(syncResult) {
          var text = syncResult.output || JSON.stringify(syncResult, null, 2);
          out.textContent = text;
          mergeStrategies(parseBlockcheckStrategies(text));
          renderStrategies(text);
        });
      }
      return pollStatus();
    }).catch(function(e) {
      stopPolling();
      setRunning(false);
      ui.addNotification(null, E('p', e.message), 'danger');
    });
  });
  var row = function(label, control) {
    return E('div', { 'style': 'display:flex;gap:.75em;align-items:center;margin:.35em 0' }, [
      E('label', { 'style': 'min-width:8em' }, label),
      control
    ]);
  };
  return E('div', { 'class': 'cbi-section purewrt-card' }, [
    E('h3', {}, _('Blockcheck — DPI-bypass finder')),
    E('p', { 'class': 'purewrt-text-dim' }, _('Runs zapret blockcheck2 against one or more hosts with live output, then lists the working nfqws strategies. One host debugs a single site; 2+ hosts (space-separated) also yields the COMMON strategy that works for all of them. Runs in the background — you can close this tab and come back. Nothing is written until you click Create strategy and Save & Apply.')),
    row(_('Hosts'), input),
    row(_('WAN interface'), wan),
    row(_('Scan level'), scan),
    row(_('Repeats'), repeats),
    E('div', { 'style': 'display:flex;gap:1em;flex-wrap:wrap;margin:.5em 0' }, [
      E('label', {}, [ http, ' ', _('HTTP') ]),
      E('label', {}, [ tls12, ' ', _('TLS 1.2') ]),
      E('label', {}, [ tls13, ' ', _('TLS 1.3') ]),
      E('label', {}, [ http3, ' ', _('HTTP3/QUIC') ]),
      E('label', {}, [ httpsGet, ' ', _('HTTPS GET') ])
    ]),
    E('div', { 'style': 'margin:.5em 0' }, [ runBtn, stopBtn ]),
    verdict,
    strategiesBox,
    out
  ]);
}

// renderStrategyTesterCard sweeps the shared candidate list against target
// sites through real nfqws2 desync (backend zapret-strategy-test/-sweep),
// ranks by sites unblocked, and lets you Apply the winner. Complements
// Blockcheck (which discovers) — this validates a curated set + applies it.
function renderStrategyTesterCard(networks, wanNets, wan6Nets, candidates) {
  var sites = E('input', { 'class': 'cbi-input-text', 'style': 'width:100%;max-width:36em', 'placeholder': 'redirector.googlevideo.com telegram.org discord.com (blank = defaults)' });
  var wan = buildWanSelect(networks, wanNets, wan6Nets);
  // ISP filter: distinct isp values across candidates ("common" first).
  var isps = [];
  candidates.forEach(function(c) {
    var v = c.isp || 'common';
    if (isps.indexOf(v) < 0) isps.push(v);
  });
  isps.sort(function(a, b) { return a === 'common' ? -1 : b === 'common' ? 1 : a.localeCompare(b); });
  var ispSel = E('select', { 'class': 'cbi-input-select' });
  isps.forEach(function(v) { ispSel.appendChild(E('option', { 'value': v }, v)); });
  var candSel = E('select', { 'class': 'cbi-input-select' });
  function rebuildCandidates() {
    candSel.innerHTML = '';
    var isp = ispSel.value;
    candidates.filter(function(c) { return (c.isp || 'common') === isp; })
      .forEach(function(c) { candSel.appendChild(E('option', { 'value': c.name }, c.name)); });
  }
  ispSel.addEventListener('change', rebuildCandidates);
  rebuildCandidates();
  var resultsBox = E('div', { 'style': 'margin:.5em 0' });
  var pollTimer = null;
  function verdictChip(v) {
    var cls = v === 'fixed' ? 'run' : (v === 'already-ok' ? 'idle' : 'upd');
    return E('span', { 'class': 'purewrt-pill ' + cls, 'style': 'margin:0 .25em .25em 0' }, v);
  }
  function renderRows(rows) {
    resultsBox.innerHTML = '';
    if (!rows || !rows.length) return;
    resultsBox.appendChild(E('h4', {}, _('Results (ranked by sites unblocked)')));
    rows.forEach(function(r) {
      var name = r.strategy;
      var summary = _('%d fixed / %d ok / %d total').format(r.fixed || 0, r.passed || 0, r.total || 0);
      var applyBtn = E('button', { 'class': 'btn cbi-button cbi-button-add' }, [ _('Apply') ]);
      applyBtn.addEventListener('click', function(ev) {
        ev.preventDefault();
        var cand = zapretPresets[name];
        if (!cand) { ui.addNotification(null, E('p', _('Unknown candidate %s').format(name)), 'warning'); return; }
        var sn = stageCandidate(cand);
        applyBtn.disabled = true; applyBtn.textContent = _('Staged: %s').format(sn);
        ui.addNotification(null, E('p', _('Strategy "%s" staged. Review in Unsaved Changes, then Save & Apply.').format(sn)), 'info');
      });
      var chips = (r.sites || []).map(function(s) {
        var tip = (s.site || '') + ' ' + (s.appconnect_ms || 0) + 'ms' + (s.download_bytes ? ' ' + s.download_bytes + 'B' : '');
        return E('span', { 'style': 'margin-right:.4em', 'title': tip }, [ E('code', {}, (s.site || '').replace(/\..*$/, '')), ' ', verdictChip(s.verdict || '?') ]);
      });
      resultsBox.appendChild(E('div', { 'style': 'display:flex;gap:.75em;align-items:center;flex-wrap:wrap;border-bottom:1px solid #333;padding:.4em 0' }, [
        E('strong', { 'style': 'flex:0 0 12em' }, name),
        E('span', { 'style': 'flex:0 0 12em' }, summary),
        E('div', { 'style': 'flex:1 1 20em' }, chips),
        applyBtn
      ]));
    });
  }
  function stopPolling() { if (pollTimer) { window.clearTimeout(pollTimer); pollTimer = null; } }
  function pollSweep() {
    return callZapretSweepStatus().then(function(r) {
      // The sweep streams one JSON object per line as each candidate finishes,
      // so parse line-by-line (ignoring a partial trailing line) and rank
      // client-side — results appear incrementally instead of all at the end.
      var rows = [];
      (r.output || '').split('\n').forEach(function(line) {
        line = line.trim();
        if (!line) return;
        try { rows.push(JSON.parse(line)); } catch (e) { /* partial/!json line */ }
      });
      rows.sort(function(a, b) { return (b.fixed || 0) - (a.fixed || 0) || (b.passed || 0) - (a.passed || 0); });
      var running = (r.running === 1 || r.running === true);
      // The sweep emits its ranked table only when it finishes, so while it
      // runs there are no rows yet — keep a progress line instead of blanking
      // the box (which reads as "nothing happening").
      if (rows.length) {
        renderRows(rows);
        if (running)
          resultsBox.appendChild(E('em', { 'class': 'purewrt-text-dim spinning', 'style': 'display:block;margin-top:.4em' }, _('Tested %d so far — still running…').format(rows.length)));
      } else if (running) {
        resultsBox.innerHTML = E('em', { 'class': 'purewrt-text-dim spinning' }, _('Testing candidates — results stream in as each finishes…')).outerHTML;
      } else {
        resultsBox.innerHTML = E('em', { 'class': 'purewrt-text-dim' }, _('Sweep finished with no results.')).outerHTML;
      }
      if (running) pollTimer = window.setTimeout(pollSweep, 2000);
    }).catch(function() {
      // A transient status-poll failure (busy rpcd, dropped request) shouldn't
      // abandon a sweep that's still running server-side — keep polling.
      pollTimer = window.setTimeout(pollSweep, 2000);
    });
  }
  var dlChk = E('input', { 'type': 'checkbox' });
  var dlVal = function() { return dlChk.checked ? '1' : ''; };
  // Target-suite selector: curated served list (+ manual sites) or the
  // hyperion-cs/dpi-checkers CDN suite (36 hosts, ignores the sites box).
  var suiteSel = E('select', { 'class': 'cbi-input-select' }, [
    E('option', { 'value': '' }, _('Curated / manual')),
    E('option', { 'value': 'dpi' }, _('DPI-checkers suite (CDN hosts)'))
  ]);
  var suiteVal = function() { return suiteSel.value; };
  var testBtn = E('button', { 'class': 'btn cbi-button cbi-button-action' }, [ _('Test selected') ]);
  testBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    resultsBox.innerHTML = _('Testing %s…').format(candSel.value);
    return callZapretStrategyTest(candSel.value, wan.value, (sites.value || '').trim(), dlVal(), suiteVal()).then(function(r) {
      renderRows([r]);
    }).catch(function(e) { ui.addNotification(null, E('p', e.message), 'danger'); });
  });
  var sweepBtn = E('button', { 'class': 'btn cbi-button cbi-button-apply', 'style': 'margin-left:.5em' }, [ _('Test all') ]);
  sweepBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    stopPolling();
    resultsBox.innerHTML = _('Testing all %s candidates — this takes a while…').format(ispSel.value);
    return callZapretSweepStart(wan.value, (sites.value || '').trim(), ispSel.value, dlVal(), suiteVal()).then(function(r) {
      if (r && (r.result === 'started' || r.result === 'busy')) return pollSweep();
      ui.addNotification(null, E('p', _('Sweep failed to start.')), 'danger');
    }).catch(function(e) { stopPolling(); ui.addNotification(null, E('p', e.message), 'danger'); });
  });
  window.setTimeout(function() { callZapretSweepStatus().then(function(r) { if (r && (r.running === 1 || r.running === true)) pollSweep(); }).catch(function() {}); }, 0);
  var row = function(label, control) {
    return E('div', { 'style': 'display:flex;gap:.75em;align-items:center;margin:.35em 0' }, [ E('label', { 'style': 'min-width:8em' }, label), control ]);
  };
  return E('div', { 'class': 'cbi-section purewrt-card' }, [
    E('h3', {}, _('Strategy tester')),
    E('p', { 'class': 'purewrt-text-dim' }, _('Tests the shared strategy candidates against your target sites through real nfqws2 desync, ranked by how many sites they unblock. "Test selected" tries one; "Test all" tries every candidate (slow). Apply stages the winner. Blank target sites uses the served suite. Only meaningful behind real DPI — on an open/SYN-blocked path everything shows "already-ok"/"still-blocked".')),
    row(_('Target sites'), sites),
    row(_('Target suite'), suiteSel),
    row(_('WAN interface'), wan),
    row(_('ISP'), ispSel),
    row(_('Candidate'), candSel),
    row(_('Download probe'), E('label', {}, [ dlChk, ' ', E('span', { 'class': 'purewrt-text-dim' }, _('verify bytes actually flow (catches throttling after handshake); slower')) ])),
    E('div', { 'style': 'margin:.5em 0' }, [ testBtn, sweepBtn ]),
    resultsBox
  ]);
}

// renderNotInstalledPlaceholder builds the page body shown when the
// Zapret userspace daemons aren't on the system. The tab still appears
// in the menu so users discover the feature exists; the body explains
// what they need to install. Keeping it discoverable is friendlier than
// hiding the tab — a missing menu entry leaves users wondering whether
// PureWRT supports Zapret at all.
function renderNotInstalledPlaceholder() {
  return E('div', { 'class': 'cbi-map' }, [
    E('h2', _('PureWRT Zapret')),
    E('div', {
      'class': 'alert-message warning',
      'style': 'margin:1em 0;padding:1em 1.2em;display:flex;flex-direction:column;gap:.5em'
    }, [
      E('strong', {}, _('Zapret is not installed on this router.')),
      E('p', { 'style': 'margin:.2em 0' }, _(
        'Zapret is the optional DPI-bypass daemon (nfqws / tpws) used by PureWRT to circumvent traffic shaping or protocol filtering. \
        Without it, the PureWRT routing pipeline still works; you just lose the per-section DPI-bypass strategies and the autotune / check tooling on this page.'
      )),
      E('p', { 'style': 'margin:.2em 0' }, [
        _('To install on OpenWrt 25.12 (apk-based): '),
        E('code', { 'style': 'background:#21262d;padding:.1em .4em;border-radius:3px' }, 'apk add zapret'),
        _(' (or the bundled '),
        E('code', { 'style': 'background:#21262d;padding:.1em .4em;border-radius:3px' }, 'purewrt-zapret'),
        _(' if your feed provides it). Reload this page after install.')
      ]),
      E('p', { 'class': 'cbi-section-note', 'style': 'margin:.4em 0 0 0' }, _(
        'Detection signal: presence of /usr/bin/nfqws or /usr/bin/tpws. PureWRT does not auto-install Zapret because it ships as a separate package with its own update cadence and kernel-module dependencies.'
      ))
    ])
  ]);
}

return view.extend({
  load: function() {
    return Promise.all([
      uci.load('purewrt'),
      network.getDevices(),
      callZapretInstalled().catch(function() { return false; }),
      callApkUpdates('0').catch(function() { return []; }),
      network.getNetworks().catch(function() { return []; }),
      network.getWANNetworks().catch(function() { return []; }),
      network.getWAN6Networks().catch(function() { return []; }),
      callZapretBlobs().catch(function() { return []; }),
      callZapretCandidates().catch(function() { return []; })
    ]);
  },

  render: function(data) {
    var zapretInstalled = !!(data && data[2]);
    if (!zapretInstalled) {
      return renderNotInstalledPlaceholder();
    }
    var devices = (data && data[1]) || [];
    var networks = (data && data[4]) || [];
    var wanNets = (data && data[5]) || [];
    var wan6Nets = (data && data[6]) || [];
    var availBlobs = (data && data[7]) || [];
    var candidates = (data && data[8]) || [];
    // Populate the shared preset map from the fetched candidate list (single
    // source of truth for the preset dropdown + the strategy tester).
    zapretPresets = {};
    candidates.forEach(function(c) { if (c && c.name) zapretPresets[c.name] = c; });
    var apkUpdates = (data && data[3]) || [];
    var zapretRow = apkUpdates.find(function(u) { return u && u.name === 'zapret'; });
    var m = new form.Map('purewrt', _('PureWRT Zapret'));

    // ---- Integration mode ----
    var st = m.section(form.NamedSection, 'settings', 'main', _('Zapret integration mode'));
    var upstreamPath = st.option(form.Value, 'zapret_upstream_config_path', _('Upstream zapret2 config path'));
    upstreamPath.placeholder = '/opt/zapret2/config';
    upstreamPath.description = _('When set, PureWRT also writes the compiled single-NFQWS2_OPT shell file here so the upstream <code>/etc/init.d/zapret2</code> lifecycle picks it up. Leave empty to keep only the legacy per-strategy env file.');
    var showCompiled = st.option(form.Button, '_compiled_opt', _('Show compiled NFQWS2_OPT'));
    showCompiled.inputstyle = 'action';
    showCompiled.description = _('Read-only preview of what nfqws2 will see on the next <code>apply</code>.');
    showCompiled.onclick = function() {
      return callZapretCompiledOpt().then(function(text) {
        ui.showModal(_('Compiled NFQWS2_OPT'), [
          E('pre', { 'style': 'white-space:pre-wrap;max-height:60vh;overflow:auto;font-family:monospace;font-size:0.85em' }, text || _('(no strategies enabled)')),
          E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Close'))
        ]);
      });
    };
    // Restart is an operational action, not a destructive one — keep the
    // neutral/action color so it's not visually confused with Delete.
    var restartBtn = st.option(form.Button, '_restart', _('Restart zapret2'));
    restartBtn.inputstyle = 'action';
    restartBtn.description = _('Triggers <code>/etc/init.d/zapret2 restart</code> (or the legacy purewrt-zapret init when zapret2 is not installed). Use after changing strategies if you want them live without a full PureWRT apply.');
    restartBtn.onclick = function() {
      return callZapretRestart().then(function(r) {
        ui.addNotification(null, E('p', _('zapret restart: %s').format(r && r.result || 'ok')), 'info');
      });
    };

    // ---- Runtime profiles (folded into a table after m.render) ----
    var p = m.section(form.TypedSection, 'zapret_profile', _('Zapret runtime profiles'));
    p.addremove = true;
    p.anonymous = false;
    p.sectiontitle = profileTitle;
    p.option(form.Flag, 'enabled', _('Enabled'));
    p.option(form.Value, 'name', _('Name'));
    var mode = p.option(form.ListValue, 'interface_mode', _('Interface matching mode'));
    mode.value('single', _('Single interface'));
    mode.value('network', _('OpenWrt network'));
    mode.value('mwan3_members', _('All mwan3 member interfaces'));
    mode.default = 'mwan3_members';
    mode.description = _('All-member mode emits nftables matches for every mwan3 WAN member, so failover does not require regenerating rules.');
    var networkName = p.option(form.Value, 'network', _('OpenWrt network'));
    networkName.placeholder = 'auto';
    networkName.description = _('Use OpenWrt network names such as auto, wan, wan6, or vpn.');
    var dev = p.option(form.Value, 'device', _('Linux device override'));
    dev.placeholder = 'eth1';
    dev.description = _('Advanced override. Usually leave empty and use OpenWrt network instead.');
    var ifaces = p.option(form.DynamicList, 'interface', _('Linux interfaces'));
    ifaces.placeholder = 'wan';
    devices.forEach(function(d) {
      var name = d.getName && d.getName();
      if (name && name !== 'lo')
        ifaces.value(name, name);
    });
    ifaces.description = _('One or more Linux devices. In mwan3 member mode, PureWRT resolves all mwan3 member devices at apply time and uses them for nftables matching.');
    var pfw = p.option(form.Value, 'fwmark', _('Generated packet fwmark'));
    pfw.placeholder = '0x40000000';
    pfw.modalonly = true;
    var pnfq = p.option(form.Value, 'nfqws_bin', _('nfqws binary'));
    pnfq.placeholder = '/usr/libexec/zapret/nfqws2';
    pnfq.modalonly = true;
    var ptpws = p.option(form.Value, 'tpws_bin', _('tpws binary'));
    ptpws.placeholder = '/usr/libexec/zapret/tpws';
    ptpws.modalonly = true;
    var plua = p.option(form.Value, 'lua_bundle_dir', _('Lua bundle directory'));
    plua.placeholder = '/usr/libexec/zapret/lua';
    plua.modalonly = true;
    plua.description = _('Directory containing zapret2 Lua scripts. The generated NFQWS2_OPT prepends --lua-init=@&lt;dir&gt;/...lua so named blobs like fake_default_tls resolve.');
    // Custom blobs: pick from the shipped fake-payload .bin files. Each option's
    // VALUE is the nfqws2 declaration `name:@/path` (name = filename minus .bin);
    // the generator emits it as --blob= in the head, and a strategy references
    // the name (fake:blob=name / seqovl_pattern=name). The stock
    // fake_default_tls/http/quic need no entry.
    var pblob = p.option(form.MultiValue, 'blob', _('Custom blobs'));
    pblob.modalonly = true;
    availBlobs.forEach(function(bl) {
      if (bl && bl.name && bl.path)
        pblob.value(bl.name + ':@' + bl.path, bl.name);
    });
    if (!availBlobs.length)
      pblob.value('', _('(no fake .bin files found on router)'));
    pblob.description = _('Select shipped nfqws2 fake payloads to declare (--blob=). Once selected, reference one by its name in a strategy\'s params, e.g. <code>fake:blob=tls_clienthello_www_google_com</code> or <code>seqovl_pattern=&lt;name&gt;</code>. The stock <code>fake_default_tls/http/quic</code> are always available and need no entry.');

    // ---- Strategies (folded into a table after m.render) ----
    var zs = m.section(form.TypedSection, 'zapret_strategy', _('Zapret strategies'));
    zs.addremove = true;
    zs.anonymous = false;
    zs.sectiontitle = strategyTitle;
    zs.option(form.Flag, 'enabled', _('Enabled'));
    zs.option(form.Value, 'name', _('Name'));
    var preset = zs.option(form.ListValue, 'preset', _('Preset'));
    preset.value('custom', _('custom'));
    // Preset options come from the fetched candidate list, labelled by ISP.
    candidates.forEach(function(c) {
      preset.value(c.name, c.isp ? c.name + ' (' + c.isp + ')' : c.name);
    });
    preset.description = _('Selecting a preset overwrites protocols, ports, packet limits, and nfqws parameters from the shared candidate list. Use custom for manual tuning.');
    var profile = zs.option(form.ListValue, 'profile', _('Runtime profile'));
    var profileValues = { wan: true };
    profile.value('wan', 'wan');
    uci.sections('purewrt', 'zapret_profile').forEach(function(sec) {
      var name = sec.name || sec['.name'];
      if (name && !profileValues[name]) {
        profile.value(name, name);
        profileValues[name] = true;
      }
    });
    profile.default = 'wan';
    var queue = zs.option(form.Value, 'queue_num', _('NFQUEUE number'));
    queue.datatype = 'uinteger';
    queue.placeholder = _('auto');
    queue.description = _('Leave empty or 0 to auto-assign starting at 200. Set only to avoid conflicts with external NFQUEUE users.');
    var protocols = zs.option(form.MultiValue, 'protocols', _('Protocols'));
    protocols.value('tcp', _('TCP'));
    protocols.value('udp', _('UDP'));
    var tcpPorts = zs.option(form.Value, 'tcp_ports', _('TCP ports'));
    tcpPorts.placeholder = '443,2053,2083,2087,2096,8443';
    var udpPorts = zs.option(form.Value, 'udp_ports', _('UDP ports'));
    udpPorts.placeholder = '443';
    var tcpOut = zs.option(form.Value, 'tcp_pkt_out', _('TCP outgoing packet limit'));
    tcpOut.datatype = 'uinteger';
    tcpOut.modalonly = true;
    var tcpIn = zs.option(form.Value, 'tcp_pkt_in', _('TCP incoming packet limit'));
    tcpIn.datatype = 'uinteger';
    tcpIn.modalonly = true;
    var udpOut = zs.option(form.Value, 'udp_pkt_out', _('UDP outgoing packet limit'));
    udpOut.datatype = 'uinteger';
    udpOut.modalonly = true;
    var udpIn = zs.option(form.Value, 'udp_pkt_in', _('UDP incoming packet limit'));
    udpIn.datatype = 'uinteger';
    udpIn.modalonly = true;
    var params = zs.option(form.TextValue, 'params', _('nfqws strategy parameters'));
    params.rows = 4;
    params.modalonly = true;
    params.description = _('Raw nfqws2 args (<code>--lua-desync=...</code>). If this includes its own <code>--filter-tcp/udp</code> it is used verbatim (the fields above are ignored). Put <code>--payload</code> before <code>--lua-desync</code>.');
    // Arg-order guard: warn if --lua-desync precedes --payload in params.
    params.validate = function(sid, value) {
      if (value && /--payload=/.test(value) && value.indexOf('--lua-desync') >= 0 &&
          value.indexOf('--lua-desync') < value.indexOf('--payload=')) {
        return _('--payload must come before --lua-desync, otherwise it will not scope the desync.');
      }
      return true;
    };

    // Wire preset auto-fill via the document-level `widget-change` event
    // LuCI fires when any form widget mutates. `option.onchange` is set
    // for completeness but isn't reliably invoked by ListValue on this
    // LuCI version — the document listener catches every dropdown change.
    var presetFields = {
      protocols: 'protocols',
      tcp_ports: 'tcp_ports',
      udp_ports: 'udp_ports',
      tcp_pkt_out: 'tcp_pkt_out',
      tcp_pkt_in: 'tcp_pkt_in',
      udp_pkt_out: 'udp_pkt_out',
      udp_pkt_in: 'udp_pkt_in',
      params: 'params'
    };
    preset.onchange = function(ev, sectionId, value) {
      applyPresetTo(sectionId, value, presetFields);
    };
    document.addEventListener('widget-change', function(ev) {
      var target = ev.target;
      if (!target || !target.id) return;
      // Match wrapper id: cbid.purewrt.<sid>.preset
      var m = /^cbid\.purewrt\.([^.]+)\.preset$/.exec(target.id);
      if (!m) return;
      var sel = target.querySelector('select');
      if (sel) applyPresetTo(m[1], sel.value, presetFields);
    }, true);

    // ---- Usage + merged Blockcheck (DPI-bypass finder) ----
    var help = m.section(form.NamedSection, 'zapret_help', 'purewrt_zapret_help', _('Usage'));
    help.render = function() {
      return E('div', {}, [
        E('div', { 'class': 'cbi-section purewrt-card' }, [
          E('p', {}, _('Set a routing section Action to Zapret on the Sections / Routing page. Matching OpenWrt-exported rule provider IP/CIDR sets for that section will be sent through zapret instead of mihomo TPROXY.')),
          E('p', {}, _('After saving, run PureWRT Reload/Apply so nftables and purewrt-zapret are regenerated and restarted.'))
        ]),
        renderBlockcheckCard(networks, wanNets, wan6Nets),
        renderStrategyTesterCard(networks, wanNets, wan6Nets, candidates)
      ]);
    };

    return m.render().then(function(root) {
      // Scope each tableSection.render call to its own section wrapper so
      // the cleanup at the top of render() doesn't clobber the other
      // table's header row.
      var profileWrap = root.querySelector('#cbi-purewrt-zapret_profile');
      var strategyWrap = root.querySelector('#cbi-purewrt-zapret_strategy');

      if (profileWrap) {
        tableSection.render(profileWrap, {
          columns: '0 1.4fr 1fr 1.4fr 0.8fr 0.7fr 12rem',
          headers: [ '', _('Name'), _('Mode'), _('Network/Devices'), _('Fwmark'), _('Enable'), '' ],
          showEnable: true,
          filterNode: inWrapper('cbi-purewrt-zapret_profile'),
          titleOf: function(sid) { return _('Profile') + ': ' + profileTitle(sid); },
          summaryOf: profileSummary,
          save: function() {
            return saveChain.run(m, [
              { fn: callZapretRestart, label: _('Zapret restart') }
            ], { onDone: _('Profile saved and zapret restarted.') });
          },
          actions: [
            { label: _('Edit'), kind: 'edit' },
            { label: _('Delete'), kind: 'delete', style: 'remove' }
          ]
        });
      }

      if (strategyWrap) {
        tableSection.render(strategyWrap, {
          columns: '0 1.4fr 1.2fr 1fr 1fr 1.5fr .7fr 0.7fr 12rem',
          headers: [ '', _('Name'), _('Preset'), _('Profile'), _('Protocols'), _('Ports'), _('Queue'), _('Enable'), '' ],
          showEnable: true,
          filterNode: inWrapper('cbi-purewrt-zapret_strategy'),
          titleOf: function(sid) { return _('Strategy') + ': ' + strategyTitle(sid); },
          summaryOf: strategySummary,
          save: function() {
            return saveChain.run(m, [
              { fn: callZapretRestart, label: _('Zapret restart') }
            ], { onDone: _('Strategy saved and zapret restarted.') });
          },
          actions: [
            { label: _('Edit'), kind: 'edit' },
            { label: _('Delete'), kind: 'delete', style: 'remove' }
          ]
        });
      }

      // Inline package version row at the top of the rendered form,
      // mirrors the per-package widgets on the Mihomo + General tabs.
      // No banner unless we actually have a row from apk — silent when
      // the apk index is empty rather than rendering a placeholder.
      if (zapretRow) {
        var pillCls = !zapretRow.installed ? 'purewrt-pill idle'
          : (zapretRow.upgrade_available ? 'purewrt-pill upd' : 'purewrt-pill run');
        var pillText = !zapretRow.installed ? _('not installed')
          : (zapretRow.upgrade_available ? _('upgrade available') : _('current'));
        var pkgRow = E('div', { 'class': 'cbi-section purewrt-card', 'style': 'margin-bottom:1em' }, [
          E('h3', {}, _('Package version (zapret)')),
          E('div', { 'style': 'display:flex;gap:1em;flex-wrap:wrap;align-items:center' }, [
            E('span', {}, _('Installed: ') + (zapretRow.installed || '—')),
            E('span', {}, _('Available: ') + (zapretRow.available || '—')),
            E('span', { 'class': pillCls }, pillText)
          ]),
          E('p', { 'class': 'cbi-section-note', 'style': 'margin-top:.4em' }, _(
            'Apply upgrades from System → Software. Repo index is cached for 1 hour, the Mihomo tab has a Refresh button.'
          ))
        ]);
        root.insertBefore(pkgRow, root.firstChild);
      }

      // Config-derived status summary at the very top (Zapret-page only, no
      // live probe): enabled profiles/strategies + a not-routed warning.
      root.insertBefore(renderZapretStatusBlock(), root.firstChild);
      return root;
    });
  }
});
