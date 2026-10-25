'use strict';
'require view';
'require form';
'require rpc';
'require poll';
'require ui';
'require network';
'require uci';
'require purewrt.styles';
'require purewrt.table_section as tableSection';
'require purewrt.save_chain as saveChain';
'require purewrt.format as fmt';
'require purewrt.naming as naming';

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
var callZapretLibrary = rpc.declare({ object: 'purewrt', method: 'zapret_library', params: ['body'] });
var callZapretCandidates = rpc.declare({ object: 'purewrt', method: 'zapret_candidates', expect: { candidates: [] } });
var callZapretCandidatesRefresh = rpc.declare({ object: 'purewrt', method: 'zapret_candidates_refresh' });
var callZapretStatus = rpc.declare({ object: 'purewrt', method: 'zapret_status' });
var callZapretSweepStart = rpc.declare({ object: 'purewrt', method: 'zapret_strategy_sweep_start', params: [ 'interface', 'sites', 'isp', 'service', 'name', 'download', 'suite' ] });
var callZapretSweepStatus = rpc.declare({ object: 'purewrt', method: 'zapret_strategy_sweep_status', params: [ ] });

// zapretPresets maps candidate name → its object (protocols/ports/pkt/params/
// blobs), populated in render() for library references and previews.
var callZapretClientSwitch = rpc.declare({ object: 'purewrt', method: 'zapret_client_switch', params: ['candidate', 'extra', 'manual'] });
var callZapretClientStart = rpc.declare({ object: 'purewrt', method: 'zapret_client_start', params: ['ip', 'mac', 'interface', 'candidate', 'extra', 'manual'] });
var callZapretClientStatus = rpc.declare({ object: 'purewrt', method: 'zapret_client_status' });
var callZapretClientStop = rpc.declare({ object: 'purewrt', method: 'zapret_client_stop' });
var callClientLeases = rpc.declare({ object: 'luci-rpc', method: 'getDHCPLeases' });
var zapretPresets = {};

// refreshStrategyCandidates is set by renderStrategyTesterCard to a function
// that fetches the latest candidate list from purewrt-lists and rebuilds the
// tester dropdowns in place. The integration-mode "Update strategies" button
// (top of page) calls it — kept as a shared ref so the button can live in a
// different part of the form from the tester closure it mutates.
var refreshStrategyCandidates = null;

// Use the same profile identity as strategy references, not its first device.

function strategyTitle(sid) {
  return naming.displayName(sid, 'zapret_strategy') || _('New strategy');
}




function strategySummary(sid) {
  var items = uci.get('purewrt', sid, 'assignment') || [];
  if (!Array.isArray(items)) items = [items];
  return [strategyTitle(sid), items.map(function(v) { return v.replace('=', ' → '); }).join('; ') || _('No WAN assignments')];
}


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
// the OPTION LABEL is the friendly network name ("wan_b"), the VALUE is the
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

// Blockcheck winners are new library content, not copied routing parameters.
function saveBlockcheckCandidate(params, common, hostsLabel, defaults) {
  var base = 'user_' + (common ? 'bc_common' : 'bc_' + (hostsLabel || 'host'));
  base = base.replace(/[^A-Za-z0-9_]+/g, '_').slice(0, 55);
  var name = base, i = 2;
  while (zapretPresets[name]) name = base + '_' + i++;
  var tcp = params.match(/--filter-tcp=(\S+)/), udp = params.match(/--filter-udp=(\S+)/);
  var protocols = [], tcpPorts = tcp ? tcp[1] : '', udpPorts = udp ? udp[1] : '';
  if (tcp) protocols.push('tcp'); if (udp) protocols.push('udp');
  if (!protocols.length) {
    protocols = defaults.protocols || [];
    tcpPorts = defaults.tcp_ports || ''; udpPorts = defaults.udp_ports || '';
    params = protocols.map(function(p) { return '--filter-' + p + '=' + (p === 'tcp' ? tcpPorts : udpPorts) + ' ' + params; }).join(' --new ');
  }
  var candidate = { name: name, isp: 'common', protocols: protocols, tcp_ports: tcpPorts, udp_ports: udpPorts, params: params, blobs: [] };
  Object.keys(zapretPresets).forEach(function(key) {
    (zapretPresets[key].blobs || []).forEach(function(b) {
      if (params.indexOf('=' + b.name) >= 0 && !candidate.blobs.some(function(x) { return x.name === b.name; })) candidate.blobs.push(b);
    });
  });
  return callZapretLibrary(JSON.stringify({ action: 'save', candidate: candidate })).then(function(r) {
    if (r.error) throw new Error(r.error);
    zapretPresets[name] = candidate;
    return name;
  });
}

// One application owns WAN-to-library references. Updating another WAN does
// not create another application or duplicate strategy parameters.
function stageCandidate(cand, device, displayName) {
  if (!device) throw new Error(_('Select a WAN interface first.'));
  var name = (displayName || cand.name).slice(0, 48);
  var existing = uci.sections('purewrt', 'zapret_strategy').find(function(s) { return naming.nameOf(s, 'zapret_strategy') === name; });
  var sid = existing ? existing['.name'] : uci.add('purewrt', 'zapret_strategy');
  if (!existing) { uci.set('purewrt', sid, 'name', name); uci.set('purewrt', sid, 'enabled', '1'); }
  var assignments = uci.get('purewrt', sid, 'assignment') || [];
  if (!Array.isArray(assignments)) assignments = [assignments];
  assignments = assignments.filter(function(v) { return v.split('=')[0] !== device; });
  assignments.push(device + '=' + cand.name);
  uci.set('purewrt', sid, 'assignment', assignments);
  return name;
}

// renderZapretStatusBlock is a config-derived (no live probe) summary shown at
// the top of the page: enabled profiles/strategies, which routing sections use
// Action=zapret, and a quiet note when a strategy is enabled but nothing routes
// to it (so it silently won't take effect). Not a global DoctorWarning —
// advanced users configure zapret deliberately.
function renderZapretStatusBlock() {
  function flagOn(s) { return s.enabled == null || s.enabled === '1' || s.enabled === 'true' || s.enabled === 'yes' || s.enabled === 'on'; }
  var strategies = uci.sections('purewrt', 'zapret_strategy').filter(flagOn);
  var sections = uci.sections('purewrt', 'section');
  var zapretSections = sections.filter(function(s) { return s.enabled !== '0' && s.action === 'zapret'; });
  var rows = [];
  rows.push(E('div', {}, [
    E('strong', {}, _('Enabled applications: ')),
    strategies.length ? strategies.map(function(s) { return naming.nameOf(s, 'zapret_strategy'); }).join(', ') : _('none')
  ]));
  rows.push(E('div', {}, [
    E('strong', {}, _('Routing sections using Zapret: ')),
    zapretSections.length ? zapretSections.map(function(s) { return naming.nameOf(s, 'section'); }).join(', ') : _('none')
  ]));
  if (strategies.length > 0 && zapretSections.length === 0) {
    rows.push(E('div', { 'class': 'alert-message warning', 'style': 'margin-top:.5em' },
      _('%d zapret strategy(ies) are enabled, but no routing section has Action = Zapret — they will not take effect. Set a section\'s Action to Zapret on the Sections / Routing page.').format(strategies.length)));
  }
  // Live box: filled from the zapret_status rpc (nfqws running? per-instance
  // pid/queue, per-section queued traffic). Refreshed on load + on demand.
  var liveBox = E('div', { 'style': 'margin:.4em 0' }, fmt.spinner(_('Checking nfqws…')));
  var refreshBtn = E('button', { 'class': 'btn cbi-button', 'style': 'margin-top:.4em' }, [ _('Refresh status') ]);
  function renderLive(s) {
    s = s || {};
    var insts = s.instances || [];
    var running = insts.filter(function(i) { return i.running; }).length;
    var kids = [];
    kids.push(E('div', {}, [
      E('strong', {}, _('nfqws: ')),
      fmt.pill(s.running ? _('running') : _('stopped'), s.running ? 'ok' : 'danger'),
      insts.length ? E('span', { 'style': 'margin-left:.5em' }, _('%d/%d instances up').format(running, insts.length)) : '',
      s.uptime_seconds ? E('span', { 'style': 'margin-left:.5em', 'class': 'purewrt-text-dim' }, _('up %s').format(fmt.humanUptime(s.uptime_seconds))) : ''
    ]));
    insts.forEach(function(i) {
      kids.push(E('div', { 'class': i.running ? '' : 'purewrt-text-dim', 'style': 'font-size:.9em' }, [
        '· ' + i.strategy + ' → queue ' + i.queue + ' → ',
        i.running ? ('nfqws PID ' + i.pid) : _('not running')
      ]));
    });
    (s.sections || []).forEach(function(sec) {
      kids.push(E('div', { 'style': 'font-size:.9em' },
        '· ' + sec.section + ': ' + _('%d packets queued').format(sec.packets || 0)));
    });
    if (s.recent_error)
      kids.push(fmt.errorDetails(_('Recent nfqws error'), s.recent_error));
    liveBox.innerHTML = '';
    kids.forEach(function(k) { if (k) liveBox.appendChild(k); });
  }
  function fetchLive() {
    liveBox.innerHTML = ''; liveBox.appendChild(fmt.spinner(_('Checking nfqws…')));
    return callZapretStatus().then(renderLive).catch(function(e) {
      liveBox.innerHTML = '';
      liveBox.appendChild(E('em', { 'class': 'purewrt-text-dim' }, _('Status unavailable: %s').format((e && e.message) || String(e))));
    });
  }
  refreshBtn.addEventListener('click', function(ev) { ev.preventDefault(); fetchLive(); });
  window.setTimeout(fetchLive, 0);
  return E('div', { 'class': 'cbi-section purewrt-card', 'style': 'margin-bottom:1em' }, [
    E('h3', {}, _('Zapret status')),
    liveBox,
    E('div', { 'style': 'display:flex;flex-direction:column;gap:.25em;margin-top:.4em' }, rows),
    refreshBtn
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
      var btn = E('button', { 'class': 'btn cbi-button cbi-button-add' }, [ _('Save to library') ]);
      btn.addEventListener('click', function(ev) {
        ev.preventDefault();
        btn.disabled = true;
        saveBlockcheckCandidate(s.params, s.common, hostsLabel(), protoDefaults()).then(function(name) {
          btn.textContent = _('Saved: %s').format(name);
          ui.addNotification(null, E('p', _('Saved "%s" to the library. Refresh the library, then select it for an application WAN.').format(name)), 'info');
        }).catch(function(e) { btn.disabled = false; ui.addNotification(null, E('p', e.message), 'error'); });
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
    E('p', { 'class': 'purewrt-text-dim' }, _('Runs zapret blockcheck2 against one or more hosts with live output, then lists the working nfqws strategies. One host debugs a single site; 2+ hosts (space-separated) also yields the COMMON strategy that works for all of them. Runs in the background — you can close this tab and come back. Nothing is saved until you click Save to library.')),
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
// Manual end-to-end verification: traffic comes from the chosen LAN client.
// User presets persist independently of the downloaded catalog. Only explicit
// Save/Upload mutates the library; neither changes production routing.
function renderZapretLibrary(candidates, blobs) {
  var select = E('select', { 'class': 'cbi-input-select', style: 'max-width:100%' });
  var edit, remove, preview;
  function selected() { return candidates.find(function(c) { return c.name === select.value; }); }
  function fill() {
    var old = select.value;
    select.innerHTML = '';
    candidates.forEach(function(c) { select.appendChild(E('option', { value: c.name }, '[' + (c.origin || 'catalog') + '] ' + c.name)); });
    if (candidates.some(function(c) { return c.name === old; })) select.value = old;
    var c = selected();
    if (preview) preview.disabled = !c;
    if (edit) edit.disabled = !c || c.origin !== 'user';
    if (remove) remove.disabled = !c || c.origin !== 'user';
  }
  function reload() {
    return Promise.all([callZapretCandidates(), callZapretBlobs()]).then(function(data) {
      candidates.splice.apply(candidates, [0, candidates.length].concat(data[0] || []));
      blobs.splice.apply(blobs, [0, blobs.length].concat(data[1] || []));
      zapretPresets = {};
      candidates.forEach(function(c) { zapretPresets[c.name] = c; });
      document.dispatchEvent(new CustomEvent('purewrt-candidates-updated'));
    });
  }
  function request(body) {
    return callZapretLibrary(JSON.stringify(body)).then(function(r) { if (r.error) throw new Error(r.error); return r; });
  }
  function field(label, control) { return E('div', { style: 'margin:.6em 0' }, [E('label', { style: 'display:block;margin-bottom:.25em' }, label), control]); }
  function editor(source, editing) {
    var original = editing ? source.name : '';
    var c = JSON.parse(JSON.stringify(source || { name: '', protocols: ['tcp'], tcp_ports: '443', params: '--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5' }));
    var name = E('input', { 'class': 'cbi-input-text', type: 'text', maxlength: 59, value: c.name ? c.name.replace(/^user_/, '') + (editing ? '' : '_copy') : '', placeholder: _('Name') });
    var tcp = E('input', { type: 'checkbox', checked: (c.protocols || []).indexOf('tcp') >= 0 });
    var udp = E('input', { type: 'checkbox', checked: (c.protocols || []).indexOf('udp') >= 0 });
    var tcpPorts = E('input', { 'class': 'cbi-input-text', value: c.tcp_ports || '', placeholder: '443' });
    var udpPorts = E('input', { 'class': 'cbi-input-text', value: c.udp_ports || '', placeholder: '443,50000-65535' });
    var params = E('textarea', { 'class': 'cbi-input-textarea', rows: 8, style: 'width:100%;font-family:monospace' }, c.params || '');
    var blobRows = E('div'), rows = [], error = E('p', { 'class': 'alert-message warning', style: 'display:none;white-space:pre-wrap' });
    function showError(e) { error.textContent = e.message || String(e); error.style.display = ''; }
    function addBlob(ref) {
      ref = ref || {};
      var alias = E('input', { 'class': 'cbi-input-text', value: ref.name || '', placeholder: _('Alias, e.g. user_tls') });
      var file = E('select', { 'class': 'cbi-input-select', style: 'max-width:100%' });
      file.appendChild(E('option', { value: '' }, _('Choose a blob file')));
      var seen = {};
      blobs.forEach(function(b) {
        var filename = b.path.split('/').pop();
        if (!seen[filename]) { file.appendChild(E('option', { value: filename }, filename)); seen[filename] = true; }
      });
      if (ref.file && !seen[ref.file]) file.appendChild(E('option', { value: ref.file }, ref.file));
      if (ref.hex) file.appendChild(E('option', { value: '__hex__' }, _('Inline hex from imported strategy')));
      file.value = ref.hex ? '__hex__' : (ref.file || '');
      var del = E('button', { 'class': 'btn cbi-button' }, _('Remove'));
      var row = { alias: alias, file: file, ref: ref };
      var node = E('div', { style: 'display:flex;flex-wrap:wrap;gap:.4em;margin:.4em 0' }, [alias, file, del]);
      row.node = node; rows.push(row); blobRows.appendChild(node);
      del.addEventListener('click', function(ev) { ev.preventDefault(); rows.splice(rows.indexOf(row), 1); node.remove(); });
    }
    (c.blobs || []).forEach(addBlob);
    var add = E('button', { 'class': 'btn cbi-button' }, _('Add blob reference'));
    add.addEventListener('click', function(ev) { ev.preventDefault(); addBlob(); });
    var uploadAlias = E('input', { 'class': 'cbi-input-text', placeholder: _('New blob alias, e.g. user_tls') });
    var uploadFile = E('input', { type: 'file', accept: '.bin' });
    var upload = E('button', { 'class': 'btn cbi-button' }, _('Upload blob'));
    upload.addEventListener('click', function(ev) {
      ev.preventDefault();
      var f = uploadFile.files && uploadFile.files[0];
      if (!f || !/\.bin$/i.test(f.name) || !f.size || f.size > 65536) { showError(new Error(_('Choose a nonempty .bin file, up to 64 KiB.'))); return; }
      upload.disabled = true;
      var reader = new FileReader();
      reader.onerror = function() { upload.disabled = false; showError(new Error(_('Unable to read file'))); };
      reader.onload = function() {
        request({ action: 'upload_blob', name: uploadAlias.value.trim(), data: String(reader.result).split(',')[1] }).then(function(ref) {
          blobs.push({ name: ref.file.replace(/\.bin$/, ''), path: '/etc/purewrt/blobs/' + ref.file });
          addBlob(ref);
          uploadFile.value = '';
        }).catch(showError).finally(function() { upload.disabled = false; });
      };
      reader.readAsDataURL(f);
    });
    var save = E('button', { 'class': 'btn cbi-button cbi-button-positive' }, _('Validate and save'));
    save.addEventListener('click', function(ev) {
      ev.preventDefault(); error.style.display = 'none'; save.disabled = true;
      var out = Object.assign({}, c, { name: 'user_' + name.value.trim(), origin: 'user', isp: c.isp || 'common', protocols: [], tcp_ports: tcpPorts.value.trim(), udp_ports: udpPorts.value.trim(), params: params.value.trim(), blobs: [] });
      if (tcp.checked) out.protocols.push('tcp'); if (udp.checked) out.protocols.push('udp');
      rows.forEach(function(row) {
        var ref = { name: row.alias.value.trim() };
        if (row.file.value === '__hex__') ref.hex = row.ref.hex;
        else { ref.file = row.file.value; if (ref.file === row.ref.file && row.ref.sha256) ref.sha256 = row.ref.sha256; }
        out.blobs.push(ref);
      });
      request({ action: 'save', original_name: original, candidate: out }).then(reload).then(function() {
        ui.hideModal(); select.value = out.name; fill();
        ui.addNotification(null, E('p', _('Strategy saved to your local library. It is now available in the testers; routing has not changed.')), 'info');
      }).catch(showError).finally(function() { save.disabled = false; });
    });
    ui.showModal(editing ? _('Edit user strategy') : _('New user strategy'), [
      field(_('Name'), name), field(_('Protocols'), E('div', {}, [E('label', {}, [tcp, ' TCP ']), E('label', {}, [udp, ' UDP'])])),
      field(_('TCP ports'), tcpPorts), field(_('UDP ports'), udpPorts), field(_('nfqws parameters'), params),
      E('p', {}, _('Include --filter-tcp/udp in the parameters. Port fields describe the matching scope when saved for routing. Built-in fake_default_tls/http/quic need no blob reference.')),
      field(_('Blob aliases and files'), blobRows), add,
      E('details', {}, [E('summary', {}, _('Upload custom blob')), field(_('Alias'), uploadAlias), uploadFile, ' ', upload]), error,
      E('div', { 'class': 'right' }, [E('button', { 'class': 'btn', click: ui.hideModal }, _('Cancel')), ' ', save])
    ]);
  }
  function button(label, fn) { var b = E('button', { 'class': 'btn cbi-button', style: 'margin-right:.4em' }, label); b.addEventListener('click', function(ev) { ev.preventDefault(); fn(); }); return b; }
  preview = button(_('Preview'), function() {
    var c = selected(); if (!c) return;
    function code(text) { return E('pre', { style: 'white-space:pre-wrap;overflow-wrap:anywhere;max-height:45vh;overflow:auto' }, text); }
    var refs = (c.blobs || []).map(function(b) {
      return b.name + ': ' + (b.hex || b.file || '') + (b.sha256 ? '\n  SHA256: ' + b.sha256 : '');
    }).join('\n');
    ui.showModal(_('Strategy preview'), [
      field(_('Name'), E('span', {}, c.name)),
      field(_('Source'), E('span', {}, c.origin || 'catalog')),
      field(_('Protocols'), E('span', {}, (c.protocols || []).join(' / ').toUpperCase())),
      field(_('TCP ports'), E('span', {}, c.tcp_ports || '—')),
      field(_('UDP ports'), E('span', {}, c.udp_ports || '—')),
      field(_('nfqws parameters'), code(c.params || '')),
      field(_('Blob references'), refs ? code(refs) : E('span', {}, _('No explicit blob references'))),
      E('div', { 'class': 'right' }, [E('button', { 'class': 'btn', click: ui.hideModal }, _('Close'))])
    ]);
  });
  var add = button(_('New'), function() { editor(null, false); });
  var copy = button(_('Duplicate'), function() { if (selected()) editor(selected(), false); });
  edit = button(_('Edit'), function() { if (selected() && selected().origin === 'user') editor(selected(), true); });
  remove = button(_('Delete'), function() {
    var c = selected(); if (!c || c.origin !== 'user') return;
    ui.showModal(_('Delete user strategy'), [E('p', {}, _('Delete %s from the local library? Saved routing sections are not changed.').format(c.name)), E('div', { 'class': 'right' }, [E('button', { 'class': 'btn', click: ui.hideModal }, _('Cancel')), button(_('Delete'), function() {
      request({ action: 'delete', original_name: c.name }).then(reload).then(ui.hideModal).catch(function(e) { ui.addNotification(null, E('p', e.message), 'error'); });
    })])]);
  });
  var importFile = E('input', { type: 'file', accept: '.json,application/json', style: 'display:none' });
  importFile.addEventListener('change', function() {
    var f = importFile.files && importFile.files[0]; if (!f) return;
    if (f.size > 262144) { ui.addNotification(null, E('p', _('Import is limited to 256 KiB.')), 'error'); return; }
    var reader = new FileReader();
    reader.onload = function() { try { var c = JSON.parse(reader.result); if (!c || typeof c.name !== 'string' || typeof c.params !== 'string' || !Array.isArray(c.protocols)) throw new Error(_('Import one strategy object with name, protocols, params and optional blobs.')); editor(c, false); } catch(e) { ui.addNotification(null, E('p', e.message), 'error'); } importFile.value = ''; };
    reader.onerror = function() { importFile.value = ''; ui.addNotification(null, E('p', _('Unable to read file')), 'error'); };
    reader.readAsText(f);
  });
  var importBtn = button(_('Import JSON'), function() { importFile.click(); });
  var exportBtn = button(_('Export JSON'), function() {
    var c = selected(); if (!c) return;
    var url = URL.createObjectURL(new Blob([JSON.stringify(c, null, 2)], { type: 'application/json' }));
    var a = E('a', { href: url, download: c.name + '.json' }); a.click(); setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
  });
  var refresh = button(_('Refresh library'), function() { reload().catch(function(e) { ui.addNotification(null, E('p', e.message), 'error'); }); });
  select.addEventListener('change', fill); document.addEventListener('purewrt-candidates-updated', fill); fill();
  return E('div', { 'class': 'cbi-section purewrt-card' }, [E('h3', {}, _('Strategy library')),
    E('p', {}, _('Duplicate a catalog preset or user strategy, edit its parameters and blobs, then test your copy. User entries survive catalog updates. JSON exports reference blob files; custom files must be uploaded separately.')),
    select, E('p', {}, [preview, add, copy, edit, remove, importBtn, exportBtn, refresh, importFile])]);
}

function renderClientTesterCard(networks, wanNets, wan6Nets, candidates, leases) {
  var client = E('select', { 'class': 'cbi-input-select' }, [ E('option', { value: '' }, _('Choose a LAN client')) ]);
  (leases || []).forEach(function(l) {
    if (l.ipaddr && l.macaddr) client.appendChild(E('option', { value: l.ipaddr, 'data-mac': l.macaddr }, (l.hostname || l.ipaddr) + ' (' + l.ipaddr + ')'));
  });
  var wan = buildWanSelect(networks, wanNets, wan6Nets);
  var service = E('input', { 'class': 'cbi-input-text', type: 'text', maxlength: 64, placeholder: _('Application name, e.g. Discord or YouTube') });
  var primary = E('select', { 'class': 'cbi-input-select' });
  var manual = E('textarea', { 'class': 'cbi-input-textarea', rows: 6, maxlength: 16384, style: 'width:100%;font-family:monospace', placeholder: '--filter-tcp=443 --lua-desync=fake:blob=fake_default_tls:tcp_md5' });
  var manualBox = E('div', { style: 'display:none' }, [manual, E('p', {}, _('Paste nfqws2 strategy parameters, not a shell command. Include --filter-tcp/udp; combine profiles with --new. Built-in blobs and inline hex are supported. For custom blob files, use the Strategy library. Nothing is saved until Add to routing strategies.'))]);
  function manualCandidate(params) {
    var c = { name: 'user_manual_test', params: (params || '').trim().split(/\s+/).join(' '), protocols: [], blobs: [] };
    ['tcp', 'udp'].forEach(function(p) {
      var ports = c.params.split(' ').filter(function(v) { return v.indexOf('--filter-' + p + '=') === 0; }).map(function(v) { return v.split('=')[1]; });
      if (ports.length) { c.protocols.push(p); c[p + '_ports'] = ports.join(','); }
    });
    return c;
  }
  var paramsPreview = E('pre', { style: 'white-space:pre-wrap;max-height:12em;overflow:auto' });
  var extra = E('select', { 'class': 'cbi-input-select' });
  function candidate(name) { if (name === '__manual__') return manualCandidate(manual.value); return name === '__direct__' ? { name: name, protocols: ['tcp', 'udp'], params: _('Direct baseline: no packet modification') } : candidates.find(function(c) { return c.name === name; }); }
  function fillExtra() {
    var prev = extra.value, c = candidate(primary.value);
    extra.innerHTML = ''; extra.appendChild(E('option', { value: '' }, _('None / candidate already combines protocols')));
    if (primary.value !== '__manual__' && c && c.protocols && c.protocols.length === 1) candidates.filter(function(x) {
      return x.protocols && x.protocols.length === 1 && x.protocols[0] !== c.protocols[0];
    }).forEach(function(x) { extra.appendChild(E('option', { value: x.name }, x.name + ' [' + x.protocols.join(', ') + ']')); });
    if (Array.prototype.some.call(extra.options, function(x) { return x.value === prev; })) extra.value = prev;
    previewParams();
  }
  function previewParams() {
    manualBox.style.display = primary.value === '__manual__' ? '' : 'none';
    var a = candidate(primary.value), b = candidate(extra.value);
    paramsPreview.textContent = (a ? a.params : '') + (b ? ' --new ' + b.params : '');
  }
  extra.addEventListener('change', previewParams);
  manual.addEventListener('input', previewParams);
  function fillCandidates() {
    primary.innerHTML = '';
    primary.appendChild(E('option', { value: '__direct__' }, _('Direct baseline (no strategy)')));
    primary.appendChild(E('option', { value: '__manual__' }, _('Manual strategy (paste parameters)')));
    candidates.forEach(function(c) { primary.appendChild(E('option', { value: c.name }, c.name + ' [' + (c.protocols || []).join(', ') + ']')); });
    fillExtra();
  }
  primary.addEventListener('change', fillExtra); fillCandidates();
  document.addEventListener('purewrt-candidates-updated', function() {
    var p = primary.value, e = extra.value;
    fillCandidates(); primary.value = p; fillExtra(); extra.value = e; previewParams();
    updateRotationButtons();
  });
  var status = E('p', {}, _('No client test running.'));
  var counters = E('pre', { style: 'white-space:pre-wrap' });
  var active = null, starting = false, switching = false, saving = false, activePair = null;
  function stageResult(row) {
    var a = row.candidate === '__manual__' ? manualCandidate(row.manual) : candidate(row.candidate), b = candidate(row.extra);
    if (row.candidate === '__direct__') throw new Error(_('A baseline is not a strategy.'));
    if (!a || (row.extra && !b)) throw new Error(_('Candidate is no longer available.'));
    var label = (row.name || '').trim();
    var requestedName = label.replace(/[^A-Za-z0-9_-]+/g, '_').replace(/^_+|_+$/g, '');
    if (requestedName && !/^[A-Za-z_]/.test(requestedName)) requestedName = 'test_' + requestedName;
    requestedName = requestedName.slice(0, 48);
    if (label && !requestedName) throw new Error(_('Use at least one Latin letter or number for the test name.'));
    if (requestedName && !/^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(requestedName))
      throw new Error(_('Use up to 48 letters, numbers, underscores or hyphens; start with a letter or underscore.'));
    var strategyName = requestedName || (a.name + (b ? '_' + b.name : '')).slice(0, 48);
    var blobs = [];
    (a.blobs || []).concat(b ? b.blobs || [] : []).forEach(function(ref) {
      var existing = blobs.find(function(x) { return x.name === ref.name; });
      if (existing && (existing.file !== ref.file || existing.hex !== ref.hex))
        throw new Error(_('The combined strategies use conflicting blob aliases.'));
      if (!existing) blobs.push(ref);
    });
    var combo = Object.assign({}, a, { name: strategyName,
      params: a.params + (b ? ' --new ' + b.params : ''),
      protocols: (a.protocols || []).concat(b ? b.protocols || [] : []),
      tcp_ports: a.tcp_ports || (b && b.tcp_ports) || '', udp_ports: a.udp_ports || (b && b.udp_ports) || '',
      blobs: blobs });
    ['tcp_pkt_out', 'tcp_pkt_in', 'udp_pkt_out', 'udp_pkt_in'].forEach(function(key) {
      combo[key] = Math.max(a[key] || 0, b ? b[key] || 0 : 0);
    });
    function addReference(entry) {
      var name = stageCandidate(entry, row.wan, strategyName);
      return uci.save().then(function() {
        ui.addNotification(null, E('p', _('Routing strategy "%s" now references "%s". Its assignment uses the tested WAN. Reload the page, select the application in a routing section, then Save & Apply.').format(name, entry.name)), 'info');
      });
    }
    if (!b && row.candidate !== '__manual__') return addReference(a);
    // A combined test needs one reusable library entry. Reuse an exact pair
    // already in the library rather than creating another copy.
    var match = candidates.find(function(c) { return c.params === combo.params && JSON.stringify(c.blobs || []) === JSON.stringify(combo.blobs || []); });
    if (match) return addReference(match);
    combo.name = 'user_' + strategyName.replace(/^user_/, '').slice(0, 59);
    return callZapretLibrary(JSON.stringify({ action: 'save', candidate: combo })).then(function(r) {
      if (r.error) throw new Error(r.error);
      candidates.push(combo); zapretPresets[combo.name] = combo;
      document.dispatchEvent(new CustomEvent('purewrt-candidates-updated'));
      return addReference(combo);
    });
  }
  var start = E('button', { 'class': 'btn cbi-button cbi-button-action' }, _('Start five-minute test'));
  var change = E('button', { 'class': 'btn cbi-button cbi-button-action' }, _('Switch strategy'));
  var stop = E('button', { 'class': 'btn cbi-button' }, _('Stop and restore'));
  var stage = E('button', { 'class': 'btn cbi-button cbi-button-positive' }, _('Add to routing strategies'));
  stage.addEventListener('click', function(ev) {
    ev.preventDefault();
    if (!active || !active.candidate || saving) return;
    var tested = { candidate: active.candidate, extra: active.extra || '', wan: active.interface, name: service.value, manual: active.manual || '' };
    saving = true; stage.disabled = true;
    Promise.resolve().then(function() { return stageResult(tested); })
      .catch(function(e) { ui.addNotification(null, E('p', e.message), 'error'); })
      .finally(function() { saving = false; refresh(); });
  });
  var rotationButtons = [];
  function syncActivePair() {
    if (!active || !active.running) return;
    primary.value = active.candidate;
    if (active.candidate === '__manual__') manual.value = active.manual || '';
    fillExtra();
    extra.value = active.extra || '';
    previewParams();
  }
  function rotationChoices(select) {
    var current = candidate(primary.value);
    return Array.prototype.map.call(select.options, function(o) { return o.value; }).filter(function(name) {
      if (!name || name === '__direct__' || name === '__manual__') return false;
      if (primary.value === '__manual__') return false;
      if (select !== primary || !current || primary.value === '__direct__') return true;
      var next = candidate(name);
      // Keep the other protocol fixed, including when no extra is selected.
      return next && (next.protocols || []).slice().sort().join(',') === (current.protocols || []).slice().sort().join(',');
    });
  }
  function updateRotationButtons() {
    rotationButtons.forEach(function(b) {
      b.button.disabled = starting || switching || (active && active.running && active.phase !== 'testing') || rotationChoices(b.select).length < 2;
    });
  }
  function switchSelected() {
    if (!active || !active.running || switching || !primary.value) return;
    switching = true; change.disabled = true;
    primary.disabled = extra.disabled = true;
    updateRotationButtons();
    return callZapretClientSwitch(primary.value, extra.value, primary.value === '__manual__' ? manual.value : '').then(function(r) {
      if (r.result !== 'ok') throw new Error(r.output || r.result || _('Unable to switch strategy'));
    }).catch(function(e) { syncActivePair(); ui.addNotification(null, E('p', e.message), 'error'); })
      .finally(function() { switching = false; refresh(); });
  }
  function rotatingSelect(select) {
    var buttons = [-1, 1].map(function(direction) {
      var button = E('button', { 'class': 'btn cbi-button', style: 'margin-left:.4em' }, direction < 0 ? _('Previous') : _('Next'));
      rotationButtons.push({ button: button, select: select });
      button.addEventListener('click', function(ev) {
        ev.preventDefault();
        if (starting || switching || (active && active.running && active.phase !== 'testing')) return;
        // Rotate the actually running pair, not an unapplied dropdown edit.
        syncActivePair();
        var choices = rotationChoices(select);
        if (choices.length < 2) return;
        var index = choices.indexOf(select.value);
        select.value = choices[index < 0 ? (direction > 0 ? 0 : choices.length - 1) : (index + direction + choices.length) % choices.length];
        if (select === primary) fillExtra(); else previewParams();
        updateRotationButtons();
        switchSelected();
      });
      return button;
    });
    return E('div', {}, [select, buttons[0], buttons[1]]);
  }
  var primaryControl = rotatingSelect(primary), extraControl = rotatingSelect(extra);
  primary.addEventListener('change', updateRotationButtons);
  extra.addEventListener('change', updateRotationButtons);
  function refresh() {
    return callZapretClientStatus().then(function(s) {
      active = s;
      var pair = s.running ? s.candidate + '\n' + (s.extra || '') + '\n' + (s.manual || '') : null;
      if (pair !== activePair && !switching) { syncActivePair(); activePair = pair; }
      updateRotationButtons();
      var running = !!s.running;
      start.disabled = running || starting;
      stop.disabled = !running && !starting && !s.error;
      [client, wan].forEach(function(x) { x.disabled = running || starting; });
      [primary, extra, manual].forEach(function(x) { x.disabled = starting || switching || (running && s.phase !== 'testing'); });
      change.disabled = !running || s.phase !== 'testing' || switching;
      change.textContent = switching ? _('Switching…') : _('Switch strategy');
      service.disabled = saving;
      stage.textContent = saving ? _('Saving…') : _('Add to routing strategies');
      stage.disabled = saving || !s.candidate || s.candidate === '__direct__' || starting || switching || s.phase === 'preparing';
      status.textContent = s.phase === 'preparing' && running ? _('Preparing strategy…') : running ? _('Testing %s via %s — %s seconds remaining. Restart the application, then test login/chat and voice.').format(s.ip, s.interface, Math.max(0, s.expires - Math.floor(Date.now()/1000))) + ' [' + s.candidate + (s.extra ? ' + ' + s.extra : '') + ']' :
        (starting ? _('Starting test…') : (s.error || _('Stopped. Normal routing restored.')));
      counters.textContent = (s.counters || '') + (running && s.error ? '\n' + s.error : '');
    }).catch(function(e) { status.textContent = e.message; });
  }
  start.addEventListener('click', function(ev) {
    ev.preventDefault();
    var opt = client.options[client.selectedIndex];
    if (!client.value || !primary.value) { ui.addNotification(null, E('p', _('Select a client and strategy.')), 'warning'); return; }
    starting = true; start.disabled = true;
    callZapretClientStart(client.value, opt.getAttribute('data-mac'), wan.value, primary.value, extra.value, primary.value === '__manual__' ? manual.value : '').then(function(r) {
      if (r.result !== 'started') throw new Error(r.result || _('Unable to start test'));
      window.setTimeout(function() { starting = false; refresh(); }, 2000);
    }).catch(function(e) { starting = false; ui.addNotification(null, E('p', e.message), 'error'); refresh(); });
  });
  change.addEventListener('click', function(ev) { ev.preventDefault(); switchSelected(); });
  stop.addEventListener('click', function(ev) {
    ev.preventDefault();
    stop.disabled = true;
    callZapretClientStop().then(function(r) {
      if (r.result !== 'ok') throw new Error(r.output || r.result || _('Unable to restore client routing'));
      window.setTimeout(refresh, 1500);
    }).catch(function(e) {
      ui.addNotification(null, E('p', e.message), 'error');
      refresh();
    });
  });
  function field(label, node) { return E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title' }, label), E('div', { 'class': 'cbi-value-field' }, [node])]); }
  refresh(); poll.add(refresh, 2);
  return E('div', { 'class': 'cbi-section purewrt-card' }, [
    E('h3', {}, _('Test with a LAN client')),
    E('p', {}, _('Temporarily bypasses PureWRT proxy routing for the selected client and sends internet TCP/UDP traffic through the candidate on one WAN. Local access and router DNS stay available. IPv6 forwarding is blocked for this client during the IPv4 test. Stop or the five-minute timeout restores routing, even if you close this page.')),
    field(_('What are you testing?'), service), field(_('Client'), client), field(_('WAN interface'), wan),
    field(_('Strategy'), primaryControl), manualBox, field(_('Additional TCP/UDP strategy'), extraControl),
    E('details', {}, [E('summary', {}, _('Candidate parameters')), paramsPreview]),
    E('p', {}, [start, ' ', change, ' ', stop, ' ', stage]), status, counters,
    E('p', {}, _('Counters confirm traffic reached the test queue, not that the application works. Switch strategy keeps client routing and the original timeout unchanged. Previous/Next wraps through candidates for the same protocol and switches immediately during a test, keeping the other strategy fixed. Reconnect or restart the application to test new connections.'))
  ]);
}

function renderStrategyTesterCard(networks, wanNets, wan6Nets, candidates) {
  var sites = E('input', { 'class': 'cbi-input-text', 'style': 'width:100%;max-width:36em', 'placeholder': 'redirector.googlevideo.com telegram.org discord.com (blank = defaults)' });
  var wan = buildWanSelect(networks, wanNets, wan6Nets);
  // ISP filter ("common" first) + Service filter ("generic" first, with a
  // leading "All services"). Generic/untagged candidates are wildcards —
  // matched in every service scope (mirrors the backend serviceMatches rule).
  // Built via re-callable helpers so "Update from purewrt-lists" can rebuild
  // the dropdowns in place after fetching a fresh candidate list.
  var ispSel = E('select', { 'class': 'cbi-input-select' });
  var serviceSel = E('select', { 'class': 'cbi-input-select' });
  var candSel = E('select', { 'class': 'cbi-input-select' });
  function distinctValues(key, first) {
    var out = [];
    candidates.forEach(function(c) { var v = c[key] || first; if (out.indexOf(v) < 0) out.push(v); });
    out.sort(function(a, b) { return a === first ? -1 : b === first ? 1 : a.localeCompare(b); });
    return out;
  }
  function fillSelect(sel, values, leadingLabel) {
    var prev = sel.value;
    sel.innerHTML = '';
    if (leadingLabel !== undefined) sel.appendChild(E('option', { 'value': '' }, leadingLabel));
    values.forEach(function(v) { sel.appendChild(E('option', { 'value': v }, v)); });
    if (prev) sel.value = prev; // preserve selection across a refresh when still present
  }
  function serviceMatches(candService, want) {
    if (!want) return true;
    var s = candService || 'generic';
    return s === 'generic' || s === want;
  }
  function rebuildFilters() {
    fillSelect(ispSel, distinctValues('isp', 'common'));
    fillSelect(serviceSel, distinctValues('service', 'generic'), _('All services'));
  }
  function rebuildCandidates() {
    candSel.innerHTML = '';
    var isp = ispSel.value;
    var svc = serviceSel.value;
    candidates.filter(function(c) { return (c.isp || 'common') === isp && serviceMatches(c.service, svc); })
      .forEach(function(c) { candSel.appendChild(E('option', { 'value': c.name }, c.name)); });
  }
  ispSel.addEventListener('change', rebuildCandidates);
  serviceSel.addEventListener('change', rebuildCandidates);
  rebuildFilters();
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
        var sn = stageCandidate(cand, wan.value);
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
  // Both buttons run through the sweep bg-job (start + poll). A single full
  // nfqws probe can take 30-60 s — longer than LuCI's rpc XHR timeout — so the
  // old synchronous single-test call ("XHR request timed out"). "Test selected"
  // is just a sweep narrowed to one candidate via the name filter.
  function startSweep(nameFilter, label) {
    stopPolling();
    resultsBox.innerHTML = ''; resultsBox.appendChild(fmt.spinner(label));
    return callZapretSweepStart(wan.value, (sites.value || '').trim(), ispSel.value, serviceSel.value, nameFilter, dlVal(), suiteVal()).then(function(r) {
      if (r && (r.result === 'started' || r.result === 'busy')) return pollSweep();
      ui.addNotification(null, E('p', _('Test failed to start.')), 'danger');
    }).catch(function(e) { stopPolling(); ui.addNotification(null, E('p', e.message), 'danger'); });
  }
  var testBtn = E('button', { 'class': 'btn cbi-button cbi-button-action' }, [ _('Test selected') ]);
  testBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    return startSweep(candSel.value, _('Testing %s…').format(candSel.value));
  });
  var sweepBtn = E('button', { 'class': 'btn cbi-button cbi-button-apply', 'style': 'margin-left:.5em' }, [ _('Test all') ]);
  sweepBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    return startSweep('', _('Testing all %s candidates — this takes a while…').format(serviceSel.value || ispSel.value));
  });
  // Register the candidate-refresh for the integration-mode "Update strategies"
  // button (top of page). Fetches the latest list from purewrt-lists, mutates
  // `candidates` in place (so zapretPresets/Apply see fresh params), and
  // rebuilds these dropdowns — no page reload, unsaved form edits survive.
  refreshStrategyCandidates = function() {
    return callZapretCandidatesRefresh().then(function(r) {
      if (r && r.result === 'failed')
        throw new Error(_('fetch from purewrt-lists failed (check default_lists_base_url + connectivity)'));
      return callZapretCandidates();
    }).then(function(fresh) {
      fresh = fresh || [];
      candidates.length = 0;
      fresh.forEach(function(c) { candidates.push(c); });
      zapretPresets = {};
      candidates.forEach(function(c) { if (c && c.name) zapretPresets[c.name] = c; });
      rebuildFilters();
      rebuildCandidates();
      document.dispatchEvent(new CustomEvent('purewrt-candidates-updated'));
      return candidates.length;
    });
  };
  document.addEventListener('purewrt-candidates-updated', function() { rebuildFilters(); rebuildCandidates(); });
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
    row(_('Service'), serviceSel),
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
      callZapretCandidates().catch(function() { return []; }),
      callClientLeases().catch(function() { return {}; })
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
    // "Show compiled NFQWS2_OPT" is a read-only summary of all enabled
    // strategies as one upstream-format nfqws2 command line. PureWRT actually
    // runs nfqws per-instance from its own env file (/etc/init.d/purewrt-zapret);
    // this is a human-readable overview, not a file written anywhere.
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
    // Fetch the latest strategy candidate list from purewrt-lists and refresh
    // the tester dropdowns in place (via the ref the tester card registers).
    var updateCands = st.option(form.Button, '_update_candidates', _('Update strategies'));
    updateCands.inputstyle = 'action';
    updateCands.description = _('Fetch the latest strategy candidates from purewrt-lists and refresh the tester dropdowns.');
    updateCands.onclick = function() {
      if (!refreshStrategyCandidates)
        return ui.addNotification(null, E('p', _('Strategy tester not loaded.')), 'warning');
      return refreshStrategyCandidates().then(function(n) {
        ui.addNotification(null, E('p', _('Loaded %d strategy candidate(s) from purewrt-lists.').format(n)), 'info');
      }).catch(function(e) {
        ui.addNotification(null, fmt.errorDetails(_('Could not update candidates from purewrt-lists'), (e && e.message) || String(e)), 'danger');
      });
    };

    // Application editor: one library strategy selector per WAN device.
    var deviceLabels = {}, choices = [];
    networks.forEach(function(net) {
      var device = wanDeviceOf(net), name = net.getName && net.getName();
      if (device && device !== 'lo') { choices.push(device); deviceLabels[device] = name + ' (' + device + ')'; }
    });
    devices.forEach(function(d) { var name = d.getName && d.getName(); if (name && name !== 'lo') choices.push(name); });
    uci.sections('purewrt', 'zapret_strategy').forEach(function(app) {
      var assignments = app.assignment || []; if (!Array.isArray(assignments)) assignments = [assignments];
      assignments.forEach(function(v) { choices.push(v.split('=')[0]); });
    });
    choices = choices.filter(function(v, i) { return v && choices.indexOf(v) === i; }).sort();
    var zs = m.section(form.TypedSection, 'zapret_strategy', _('Zapret applications'));
    zs.addremove = true; zs.anonymous = false;
    zs.sectiontitle = strategyTitle;
    naming.installPrefixedAdd(zs, 'zapret_strategy', function(name) { return name.length > 48 ? _('Use at most 48 characters.') : null; });
    var enabled = zs.option(form.Flag, 'enabled', _('Enabled')); enabled.default = '1';
    zs.description = _('Assign a library strategy only to the WANs this application uses.');
    var assignments = zs.option(form.Value, 'assignment', _('WAN assignments'));
    var assignmentRows = {};
    assignments.renderWidget = function(sid, optionId, cfgvalue) {
      var rows = [], list = E('div', { style: 'display:grid;gap:.6em;width:100%' });
      assignmentRows[sid] = rows;
      function changed() { list.dispatchEvent(new CustomEvent('widget-change', { bubbles: true })); }
      function addRow(value) {
        var parts = (value || '').split('=');
        var wan = E('select', { 'class': 'cbi-input-select', style: 'width:100%;min-width:0', 'aria-label': _('WAN interface') });
        wan.appendChild(E('option', { value: '' }, _('Choose a WAN')));
        choices.forEach(function(device) { wan.appendChild(E('option', { value: device }, deviceLabels[device] || device)); });
        wan.value = parts[0] || '';
        var strategy = E('select', { 'class': 'cbi-input-select', style: 'width:100%;min-width:0', 'aria-label': _('Library strategy') });
        strategy.appendChild(E('option', { value: '' }, _('Choose a strategy')));
        candidates.forEach(function(c) { strategy.appendChild(E('option', { value: c.name }, c.name)); });
        if (parts[1] && !candidates.some(function(c) { return c.name === parts[1]; })) strategy.appendChild(E('option', { value: parts[1] }, parts[1] + ' (' + _('missing') + ')'));
        strategy.value = parts[1] || '';
        var remove = E('button', { type: 'button', 'class': 'btn cbi-button cbi-button-remove', 'aria-label': _('Remove assignment'), title: _('Remove assignment') }, '×');
        var row = { wan: wan, strategy: strategy };
        var node = E('div', { style: 'display:flex;gap:.5em;align-items:center;flex-wrap:wrap' }, [
          E('div', { style: 'flex:1 1 9em;min-width:0' }, wan),
          E('span', { 'aria-hidden': 'true' }, '→'),
          E('div', { style: 'flex:1 1 9em;min-width:0' }, strategy), remove
        ]);
        rows.push(row); list.appendChild(node);
        wan.addEventListener('change', changed); strategy.addEventListener('change', changed);
        remove.addEventListener('click', function(ev) { ev.preventDefault(); rows.splice(rows.indexOf(row), 1); node.remove(); changed(); });
      }
      var values = cfgvalue || []; if (!Array.isArray(values)) values = [values];
      values.forEach(addRow);
      var add = E('button', { type: 'button', 'class': 'btn cbi-button cbi-button-add', style: 'margin-top:.7em' }, _('Add WAN'));
      add.addEventListener('click', function(ev) { ev.preventDefault(); addRow(''); changed(); });
      return E('div', { style: 'width:100%;max-width:54rem' }, [list, add]);
    };
    assignments.formvalue = function(sid) {
      if (!assignmentRows[sid]) return uci.get('purewrt', sid, 'assignment') || [];
      return assignmentRows[sid].map(function(row) { return row.wan.value + '=' + row.strategy.value; });
    };
    assignments.parse = function(sid) {
      var values = this.formvalue(sid), seen = {};
      if (enabled.formvalue(sid) !== '0' && !values.length) return Promise.reject(new Error(_('Add at least one WAN assignment.')));
      for (var i = 0; i < values.length; i++) {
        var parts = values[i].split('=');
        if (!parts[0] || !parts[1]) return Promise.reject(new Error(_('Choose a WAN and strategy for every assignment.')));
        if (seen[parts[0]]) return Promise.reject(new Error(_('Each WAN can appear only once in an application.')));
        seen[parts[0]] = true;
      }
      uci.set('purewrt', sid, 'assignment', values);
      return Promise.resolve();
    };

    // ---- Usage + merged Blockcheck (DPI-bypass finder) ----
    var help = m.section(form.NamedSection, 'zapret_help', 'purewrt_zapret_help', _('Usage'));
    help.render = function() {
      return E('div', {}, [
        E('div', { 'class': 'cbi-section purewrt-card' }, [
          E('p', {}, _('Set a routing section Action to Zapret on the Sections / Routing page. Matching OpenWrt-exported rule provider IP/CIDR sets for that section will be sent through zapret instead of mihomo TPROXY.')),
          E('p', {}, _('After saving, run PureWRT Reload/Apply so nftables and purewrt-zapret are regenerated and restarted.'))
        ]),
        renderZapretLibrary(candidates, availBlobs),
        renderBlockcheckCard(networks, wanNets, wan6Nets),
        renderStrategyTesterCard(networks, wanNets, wan6Nets, candidates),
        renderClientTesterCard(networks, wanNets, wan6Nets, candidates, (data[9] || {}).dhcp_leases || [])
      ]);
    };

    return m.render().then(function(root) {
      // Scope each tableSection.render call to its own section wrapper so
      // the cleanup at the top of render() doesn't clobber the other
      // table's header row.
      var strategyWrap = root.querySelector('#cbi-purewrt-zapret_strategy');

      if (strategyWrap) {
        tableSection.render(strategyWrap, {
          columns: '0 1.2fr 4fr .7fr 12rem',
          headers: [ '', _('Application'), _('WAN → Library strategy'), _('Enable'), '' ],
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
