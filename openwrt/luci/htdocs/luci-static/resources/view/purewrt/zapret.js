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

var callZapretCheck = rpc.declare({ object: 'purewrt', method: 'zapret_check', params: [ 'domain', 'interface', 'scan', 'repeats', 'http', 'tls12', 'tls13', 'http3', 'https_get' ] });
var callZapretCheckStart = rpc.declare({ object: 'purewrt', method: 'zapret_check_start', params: [ 'domain', 'interface', 'scan', 'repeats', 'http', 'tls12', 'tls13', 'http3', 'https_get' ] });
var callZapretCheckStatus = rpc.declare({ object: 'purewrt', method: 'zapret_check_status', params: [ ] });
var callZapretCompiledOpt = rpc.declare({ object: 'purewrt', method: 'zapret_compiled_opt', expect: { output: '' } });
var callZapretRestart = rpc.declare({ object: 'purewrt', method: 'zapret_restart' });
var callZapretAutotune = rpc.declare({ object: 'purewrt', method: 'zapret_autotune', params: [ 'hosts' ], expect: { output: '' } });
var callZapretAutotuneStart = rpc.declare({ object: 'purewrt', method: 'zapret_autotune_start', params: [ 'hosts' ] });
var callZapretAutotuneStatus = rpc.declare({ object: 'purewrt', method: 'zapret_autotune_status', params: [ ] });

var ZAPRET_PRESETS = {
  youtube_tcp: { protocols: [ 'tcp' ], tcp_ports: '443', udp_ports: '', tcp_pkt_out: '15', tcp_pkt_in: '6', udp_pkt_out: '0', udp_pkt_in: '0', fake_dir: '/usr/lib/zapret/fake', params: '--filter-tcp=443 --payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls --lua-desync=multisplit' },
  youtube_quic: { protocols: [ 'udp' ], tcp_ports: '', udp_ports: '443', tcp_pkt_out: '0', tcp_pkt_in: '0', udp_pkt_out: '9', udp_pkt_in: '0', fake_dir: '/usr/lib/zapret/fake', params: '--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6' },
  googlevideo_tcp: { protocols: [ 'tcp' ], tcp_ports: '443', udp_ports: '', tcp_pkt_out: '15', tcp_pkt_in: '6', udp_pkt_out: '0', udp_pkt_in: '0', fake_dir: '/usr/lib/zapret/fake', params: '--filter-tcp=443 --payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls --lua-desync=multisplit' },
  discord_voice_udp: { protocols: [ 'udp' ], tcp_ports: '', udp_ports: '443,50000-65535', tcp_pkt_out: '0', tcp_pkt_in: '0', udp_pkt_out: '9', udp_pkt_in: '3', fake_dir: '/usr/lib/zapret/fake', params: '--filter-udp=443,50000-65535 --dpi-desync=fake --dpi-desync-repeats=6' },
  rkn_https: { protocols: [ 'tcp' ], tcp_ports: '443,2053,2083,2087,2096,8443', udp_ports: '', tcp_pkt_out: '15', tcp_pkt_in: '6', udp_pkt_out: '0', udp_pkt_in: '0', fake_dir: '/usr/lib/zapret/fake', params: '--filter-tcp=443,2053,2083,2087,2096,8443 --payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls --lua-desync=multisplit' },
  udp_games: { protocols: [ 'udp' ], tcp_ports: '', udp_ports: '1024-65535', tcp_pkt_out: '0', tcp_pkt_in: '0', udp_pkt_out: '6', udp_pkt_in: '2', fake_dir: '/usr/lib/zapret/fake', params: '--filter-udp=1024-65535 --dpi-desync=fake --dpi-desync-repeats=3' }
};

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
  var data = ZAPRET_PRESETS[presetKey];
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

function profileTitle(sid) {
  return uci.get('purewrt', sid, 'name') || sid || _('New profile');
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

// renderAutotuneCard drives the multi-host autotune wizard. Runs in the
// background via zapret_autotune_start / zapret_autotune_status — same
// fire-and-forget pattern as the manual blockcheck card. The user can close
// the tab during a multi-minute scan and come back to see the final result.
function renderAutotuneCard() {
  var hostsInput = E('input', { 'class': 'cbi-input-text', 'style': 'width:100%;max-width:36em', 'placeholder': 'rutracker.org youtube.com' });
  var runBtn = E('button', { 'class': 'btn cbi-button cbi-button-apply' }, [ _('Run autotune') ]);
  var reloadBtn = E('button', { 'class': 'btn cbi-button cbi-button-neutral', 'style': 'display:none;margin-left:.5em' }, [ _('Reload page to pick up new strategies') ]);
  reloadBtn.addEventListener('click', function(ev) { ev.preventDefault(); location.reload(); });
  var out = E('pre', { 'style': 'white-space:pre-wrap;max-height:32em;overflow:auto;font-family:monospace;font-size:.85em;background:#1a1a1a;padding:.5em;border-radius:4px;margin-top:.5em' });
  var pollTimer = null;
  var lastNotifiedOk = false;

  function stopPolling() {
    if (pollTimer) {
      window.clearTimeout(pollTimer);
      pollTimer = null;
    }
  }
  function renderStatus(r) {
    var text = r.output || '';
    out.textContent = text || _('Running zapret autotune...');
    out.scrollTop = out.scrollHeight;
  }
  function handleCompletion(r) {
    if (r.rc === '0') {
      if (!lastNotifiedOk) {
        ui.addNotification(null, E('p', _('Autotune complete. New strategies written to UCI — reload the page to see them.')), 'info');
        lastNotifiedOk = true;
      }
      reloadBtn.style.display = '';
    } else if (r.rc && r.rc !== '0') {
      ui.addNotification(null, E('p', _('Autotune exited with rc=%s. See output above.').format(r.rc)), 'warning');
    }
  }
  function pollStatus() {
    return callZapretAutotuneStatus().then(function(r) {
      renderStatus(r);
      if (r.running === 1 || r.running === true) {
        pollTimer = window.setTimeout(pollStatus, 1500);
      } else {
        handleCompletion(r);
      }
    }).catch(function(e) {
      stopPolling();
      ui.addNotification(null, E('p', e.message), 'danger');
    });
  }
  // Same reattach-on-load pattern as blockcheck: if a previous run already
  // finished we still want to render its output instead of a blank box.
  function attachRunningCheck() {
    return callZapretAutotuneStatus().then(function(r) {
      if (r.running === 1 || r.running === true) {
        renderStatus(r);
        pollTimer = window.setTimeout(pollStatus, 1500);
      } else if (r.rc !== undefined && r.rc !== null && r.rc !== '' && (r.output || '').length > 0) {
        renderStatus(r);
        lastNotifiedOk = true; // don't re-notify on simple page revisit
        if (r.rc === '0') reloadBtn.style.display = '';
      } else {
        out.textContent = '';
      }
    }).catch(function(e) {
      ui.addNotification(null, E('p', e.message), 'danger');
    });
  }
  window.setTimeout(attachRunningCheck, 0);

  runBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    var raw = (hostsInput.value || '').trim();
    if (!raw) {
      ui.addNotification(null, E('p', _('Enter at least one canary host before running autotune.')), 'warning');
      return;
    }
    var hosts = raw.split(/\s+/);
    stopPolling();
    lastNotifiedOk = false;
    reloadBtn.style.display = 'none';
    out.textContent = _('Starting zapret autotune for %d host(s)...').format(hosts.length);
    return callZapretAutotuneStart(hosts).then(function(r) {
      if (r && r.result === 'busy') {
        ui.addNotification(null, E('p', _('An autotune is already running. Showing its current output.')), 'warning');
        return pollStatus();
      }
      if (r && r.result === 'started') {
        return pollStatus();
      }
      ui.addNotification(null, E('p', _('Autotune failed to start: %s').format(r && (r.error || r.result) || 'unknown')), 'danger');
      out.textContent = '';
    }).catch(function(e) {
      stopPolling();
      ui.addNotification(null, E('p', e.message), 'danger');
    });
  });

  return E('div', { 'class': 'cbi-section purewrt-card' }, [
    E('h3', {}, _('Autotune — multi-host blockcheck')),
    E('p', { 'class': 'purewrt-text-dim' }, _('Drives blockcheck2.sh against multiple canary hosts, parses winning <code>--lua-desync</code> combos, and writes them as <code>zapret_strategy</code> sections. Pick 2+ hosts that you know are blocked locally — the wizard prefers the COMMON intersection across all hosts for the safest strategy.')),
    E('div', { 'style': 'display:flex;gap:.75em;align-items:center;flex-wrap:wrap;margin-top:.5em' }, [
      E('label', { 'style': 'min-width:8em' }, _('Canary hosts')),
      hostsInput,
      runBtn,
      reloadBtn
    ]),
    E('p', { 'class': 'purewrt-text-dim', 'style': 'margin-top:.5em' }, _('Whitespace-separated list of domains. Runs in the background — blockcheck takes 3–10 minutes per host; you can close this tab and come back to see results.')),
    out
  ]);
}

// renderManualBlockcheckCard returns the single-host blockcheck wizard card.
// Distinct from autotune: this one is interactive (shows raw output live),
// runs against one host at a time, and lets the user toggle protocols.
function renderManualBlockcheckCard(devices) {
  var input = E('input', { 'class': 'cbi-input-text', 'placeholder': 'rutracker.org' });
  var wan = E('select', { 'class': 'cbi-input-select' });
  var hasWAN = false;
  (devices || []).forEach(function(dev) {
    var name = dev.getName && dev.getName();
    if (name && name !== 'lo') {
      wan.appendChild(E('option', { 'value': name }, name));
      hasWAN = true;
    }
  });
  if (!hasWAN)
    wan.appendChild(E('option', { 'value': 'wan' }, 'wan'));
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
  var parsed = E('textarea', { 'class': 'cbi-input-textarea', 'style': 'width:100%;min-height:6em', 'readonly': 'readonly' });
  var out = E('pre', { 'style': 'white-space:pre-wrap;max-height:32em;overflow:auto;font-family:monospace;font-size:.85em;background:#1a1a1a;padding:.5em;border-radius:4px' });
  var pollTimer = null;
  function checked(v) { return v.checked ? '1' : '0'; }
  function parseStrategies(text) {
    var marker = 'PureWRT parsed working strategies:';
    var idx = text.indexOf(marker);
    if (idx < 0) return '';
    return text.substring(idx + marker.length).replace(/^\s+/, '').replace(/^\[[0-9]+\]\s*/gm, '');
  }
  function stopPolling() {
    if (pollTimer) {
      window.clearTimeout(pollTimer);
      pollTimer = null;
    }
  }
  function renderStatus(r) {
    var text = r.output || '';
    out.textContent = text || _('Running zapret strategy check...');
    out.scrollTop = out.scrollHeight;
    parsed.value = parseStrategies(text);
  }
  function pollStatus() {
    return callZapretCheckStatus().then(function(r) {
      renderStatus(r);
      if (r.running === 1 || r.running === true)
        pollTimer = window.setTimeout(pollStatus, 1500);
      else if (r.rc && r.rc !== '0')
        ui.addNotification(null, E('p', _('Zapret strategy check failed. See output above.')), 'danger');
    }).catch(function(e) {
      stopPolling();
      ui.addNotification(null, E('p', e.message), 'danger');
    });
  }
  // attachRunningCheck reattaches to whatever the backend currently has:
  //   - running:1 → resume polling (existing behavior)
  //   - running:0 with rc set + output → completed run, show its result so
  //     a user who started a long scan, closed the tab, and came back later
  //     still sees the final summary instead of an empty view
  //   - running:0 with no rc → never run / cleared, leave fields empty
  // The "rc" field comes from /tmp/purewrt-zapret-check.status which the
  // background job writes on exit. If status file is missing rpcd returns
  // rc as empty string, which is how we detect "no prior run to show".
  function attachRunningCheck() {
    return callZapretCheckStatus().then(function(r) {
      if (r.running === 1 || r.running === true) {
        renderStatus(r);
        pollTimer = window.setTimeout(pollStatus, 1500);
      } else if (r.rc !== undefined && r.rc !== null && r.rc !== '' && (r.output || '').length > 0) {
        renderStatus(r);
        if (r.rc !== '0')
          ui.addNotification(null, E('p', _('Last zapret strategy check exited with rc=%s. See output above.').format(r.rc)), 'warning');
      } else {
        parsed.value = '';
        out.textContent = '';
      }
    }).catch(function(e) {
      ui.addNotification(null, E('p', e.message), 'danger');
    });
  }
  window.setTimeout(attachRunningCheck, 0);
  var checkBtn = E('button', { 'class': 'btn cbi-button cbi-button-action' }, [ _('Check strategy') ]);
  checkBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    stopPolling();
    parsed.value = '';
    out.textContent = _('Running zapret strategy check...');
    return callZapretCheckStart(input.value, wan.value, scan.value, repeats.value, checked(http), checked(tls12), checked(tls13), checked(http3), checked(httpsGet)).then(function(r) {
      if (r.result === 'busy') {
        ui.addNotification(null, E('p', _('Another zapret strategy check is already running. Showing its current output.')), 'warning');
      } else if (r.result !== 'started') {
        return callZapretCheck(input.value, wan.value, scan.value, repeats.value, checked(http), checked(tls12), checked(tls13), checked(http3), checked(httpsGet)).then(function(syncResult) {
          var text = syncResult.output || JSON.stringify(syncResult, null, 2);
          out.textContent = text;
          parsed.value = parseStrategies(text);
        });
      }
      return pollStatus();
    }).catch(function(e) {
      stopPolling();
      ui.addNotification(null, E('p', e.message), 'danger');
    });
  });
  var copyBtn = E('button', { 'class': 'btn cbi-button cbi-button-neutral' }, [ _('Copy parsed strategies') ]);
  copyBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    if (parsed.value)
      navigator.clipboard.writeText(parsed.value);
  });
  var row = function(label, control) {
    return E('div', { 'style': 'display:flex;gap:.75em;align-items:center;margin:.35em 0' }, [
      E('label', { 'style': 'min-width:8em' }, label),
      control
    ]);
  };
  return E('div', { 'class': 'cbi-section purewrt-card' }, [
    E('h3', {}, _('Manual blockcheck — single host')),
    E('p', { 'class': 'purewrt-text-dim' }, _('Runs zapret blockcheck2 against one host with live output. Use this when autotune\'s batch run isn\'t needed, or to debug a single failing site. The check runs in the background — you can close this tab and come back later to see the final result.')),
    row(_('Domain'), input),
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
    E('div', { 'style': 'margin:.5em 0' }, [ checkBtn ]),
    E('h4', {}, _('Parsed working strategies')),
    parsed,
    E('div', { 'style': 'margin:.35em 0' }, [ copyBtn ]),
    out
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
      callApkUpdates('0').catch(function() { return []; })
    ]);
  },

  render: function(data) {
    var zapretInstalled = !!(data && data[2]);
    if (!zapretInstalled) {
      return renderNotInstalledPlaceholder();
    }
    var devices = (data && data[1]) || [];
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

    // ---- Autotune wizard (custom-render so it doesn't depend on UCI) ----
    var autotuneSec = m.section(form.NamedSection, 'autotune_view', 'purewrt_autotune_view', _('Autotune'));
    autotuneSec.render = renderAutotuneCard;

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

    // ---- Strategies (folded into a table after m.render) ----
    var zs = m.section(form.TypedSection, 'zapret_strategy', _('Zapret strategies'));
    zs.addremove = true;
    zs.anonymous = false;
    zs.sectiontitle = strategyTitle;
    zs.option(form.Flag, 'enabled', _('Enabled'));
    zs.option(form.Value, 'name', _('Name'));
    var preset = zs.option(form.ListValue, 'preset', _('Preset'));
    preset.value('custom', _('custom'));
    preset.value('youtube_tcp', _('YouTube TCP'));
    preset.value('youtube_quic', _('YouTube QUIC'));
    preset.value('googlevideo_tcp', _('googlevideo TCP'));
    preset.value('discord_voice_udp', _('Discord/STUN voice UDP'));
    preset.value('rkn_https', _('RKN/common HTTPS'));
    preset.value('udp_games', _('UDP games / broad UDP'));
    preset.description = _('Selecting a preset overwrites protocols, ports, packet limits, fake directory, and nfqws parameters. Use custom for manual tuning.');
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
    var fakeDir = zs.option(form.Value, 'fake_dir', _('Fake payload directory'));
    fakeDir.placeholder = '/usr/libexec/zapret/files/fake';
    fakeDir.modalonly = true;
    var params = zs.option(form.TextValue, 'params', _('nfqws strategy parameters'));
    params.rows = 4;
    params.modalonly = true;

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
      fake_dir: 'fake_dir',
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

    // ---- Usage + manual single-host blockcheck ----
    var help = m.section(form.NamedSection, 'zapret_help', 'purewrt_zapret_help', _('Usage'));
    help.render = function() {
      return E('div', {}, [
        E('div', { 'class': 'cbi-section purewrt-card' }, [
          E('p', {}, _('Set a routing section Action to Zapret on the Sections / Routing page. Matching OpenWrt-exported rule provider IP/CIDR sets for that section will be sent through zapret instead of mihomo TPROXY.')),
          E('p', {}, _('After saving, run PureWRT Reload/Apply so nftables and purewrt-zapret are regenerated and restarted.'))
        ]),
        renderManualBlockcheckCard(devices)
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
      return root;
    });
  }
});
