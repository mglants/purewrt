'use strict';
'require view';
'require rpc';
'require ui';
'require purewrt.update_async as updateAsync';
'require purewrt.net_check_async as netCheckAsync';
'require purewrt.manual_rule_modal as manualModal';
'require purewrt.format as fmt';
'require purewrt.styles';

var callStatus = rpc.declare({ object: 'purewrt', method: 'status' });
var callReload = rpc.declare({ object: 'purewrt', method: 'reload' });
var callDisable = rpc.declare({ object: 'purewrt', method: 'disable' });
var callCheck = rpc.declare({ object: 'purewrt', method: 'check', params: [ 'domain' ] });

// Wave-2 diagnostic rpcd methods. Each returns parsed JSON; no wrapping.
var callDoctorWarnings = rpc.declare({ object: 'purewrt', method: 'doctor_warnings' });
var callInspectIPv6 = rpc.declare({ object: 'purewrt', method: 'inspect_ipv6' });
var callFlushDnsSets = rpc.declare({ object: 'purewrt', method: 'flush_dns_sets' });
var callResolversProbe = rpc.declare({ object: 'purewrt', method: 'resolvers_probe' });
var callMihomoStatus = rpc.declare({ object: 'purewrt', method: 'mihomo_status' });

// Health check panel — fires the cheap, side-effect-free checks in parallel and
// renders each as a spinner → coloured verdict chip as it settles, plus an
// aggregate banner. net-check is deliberately excluded (slow + burns quota); it
// keeps its own button below. Reuses fmt.pill / styles purewrt-pill-* + banners
// and the same 'spinning' class the zapret sweep uses. No new rpcd/ACL.
//
// Each check's verdict(res) → { state: 'ok'|'warn'|'danger'|'info', detail, more }
// where `more` (optional) is the raw payload shown behind a <details>.
var HEALTH_CHECKS = [
  { key: 'service', label: _('Service'), run: callStatus, verdict: function(r) {
    var enabled = r && (r.enabled === true || r.enabled === 'true' || r.status === 'ok');
    return { state: enabled ? 'ok' : 'warn', detail: enabled ? _('enabled') : _('not fully applied'),
      more: JSON.stringify(r, null, 2) };
  } },
  { key: 'mihomo', label: _('Mihomo'), run: callMihomoStatus, verdict: function(r) {
    var up = r && (r.running === true || r.running === 1);
    return { state: up ? 'ok' : 'danger', detail: up ? (r.version || _('running')) : _('not running'),
      more: JSON.stringify(r, null, 2) };
  } },
  { key: 'resolvers', label: _('DNS resolvers'), run: callResolversProbe, verdict: function(r) {
    var entries = (r && r.entries) || [];
    var okN = entries.filter(function(e) { return e.ok; }).length;
    var any = r && (r.any_endpoint_ok || r.ok || okN > 0);
    return { state: any ? 'ok' : 'danger',
      detail: entries.length ? _('%d/%d reachable').format(okN, entries.length) : _('no endpoints'),
      more: JSON.stringify(r, null, 2) };
  } },
  { key: 'warnings', label: _('Bypass warnings'), run: callDoctorWarnings, verdict: function(r) {
    var w = (r && r.warnings) || (Array.isArray(r) ? r : []);
    return { state: w.length ? 'warn' : 'ok',
      detail: w.length ? _('%d warning(s)').format(w.length) : _('none'),
      more: w.length ? w.join('\n') : '' };
  } },
  { key: 'ipv6', label: _('IPv6 path'), run: callInspectIPv6, verdict: function(r) {
    var w = (r && r.warnings) || [];
    return { state: w.length ? 'warn' : 'ok', detail: (r && r.mode) || 'auto',
      more: JSON.stringify(r, null, 2) };
  } }
];

// worstState folds per-check states into the aggregate banner verdict.
function worstHealthState(states) {
  if (states.indexOf('danger') >= 0) return 'danger';
  if (states.indexOf('warn') >= 0) return 'warn';
  return 'ok';
}

function renderHealthPanel() {
  var banner = E('div', { 'class': 'purewrt-banner purewrt-banner-muted', 'style': 'margin:.5em 0' },
    _('Click "Run all" to check service, mihomo, DNS resolvers, bypass warnings and IPv6 in parallel.'));
  // One row per check; the status cell is swapped from spinner to chip in place.
  var rows = {};
  var cells = {};
  HEALTH_CHECKS.forEach(function(c) {
    var cell = E('span', {}, '—');
    cells[c.key] = cell;
    rows[c.key] = E('div', { 'style': 'display:flex;gap:.75em;align-items:center;padding:.3em 0;border-bottom:1px solid #333' }, [
      E('strong', { 'style': 'flex:0 0 12em' }, c.label),
      E('div', { 'style': 'flex:1 1 auto' }, cell)
    ]);
  });
  var runBtn = E('button', { 'class': 'btn cbi-button cbi-button-action' }, [ _('Run all') ]);
  runBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    runBtn.disabled = true;
    banner.className = 'purewrt-banner purewrt-banner-muted';
    banner.textContent = _('Running checks…');
    HEALTH_CHECKS.forEach(function(c) {
      cells[c.key].innerHTML = E('em', { 'class': 'purewrt-text-dim spinning' }, _('checking…')).outerHTML;
    });
    var settled = HEALTH_CHECKS.map(function(c) {
      return Promise.resolve().then(c.run).then(function(r) {
        var v = c.verdict(r) || { state: 'info', detail: '' };
        renderCell(cells[c.key], v);
        return v.state;
      }).catch(function(e) {
        renderCell(cells[c.key], { state: 'danger', detail: _('check failed'), more: (e && e.message) || String(e) });
        return 'danger';
      });
    });
    Promise.all(settled).then(function(states) {
      var worst = worstHealthState(states);
      var okN = states.filter(function(s) { return s === 'ok'; }).length;
      banner.className = 'purewrt-banner purewrt-banner-' + (worst === 'ok' ? 'ok' : worst === 'warn' ? 'warn' : 'danger');
      banner.textContent = _('%d/%d checks OK').format(okN, states.length);
      runBtn.disabled = false;
    });
  });
  function renderCell(cell, v) {
    var variant = v.state === 'ok' ? 'ok' : v.state === 'warn' ? 'warn' : v.state === 'danger' ? 'danger' : 'info';
    cell.innerHTML = '';
    cell.appendChild(fmt.pill(v.state, variant));
    if (v.detail) cell.appendChild(E('span', { 'style': 'margin-left:.5em' }, v.detail));
    if (v.more) cell.appendChild(fmt.errorDetails('', v.more));
  }
  return E('div', { 'class': 'cbi-section purewrt-card' }, [
    E('h3', {}, _('Health check')),
    banner,
    E('div', {}, Object.keys(rows).map(function(k) { return rows[k]; })),
    E('div', { 'style': 'margin-top:.5em' }, [ runBtn ])
  ]);
}
// Blocking heuristics moved to its dedicated "What's Blocked Now" page.
// DNS leak check removed: the Site check tool below resolves a single
// domain and reports "first A in nftset: true/false" using the same
// dual-set (static + dns_) lookup as the leak check did across multiple
// canaries — so anything the leak panel used to surface is now visible by
// running Site check on the same domain, without the multi-canary CPU cost.

function renderTable(headers, rows) {
  var thead = E('tr', {}, headers.map(function(h) { return E('th', { 'class': 'left' }, h); }));
  var tbody = rows.map(function(r) {
    return E('tr', {}, r.map(function(c) {
      if (c && c.nodeType) return E('td', {}, c);
      return E('td', {}, String(c == null ? '' : c));
    }));
  });
  return E('table', { 'class': 'table cbi-section-table' }, [ E('thead', {}, thead) ].concat(tbody.map(function(t) { return t; })));
}

function renderWarnings(warnings) {
  if (!warnings || warnings.length === 0)
    return E('p', { 'style': 'color:#5cb85c' }, _('No bypass warnings — config looks healthy.'));
  return E('ul', {}, warnings.map(function(w) {
    return E('li', { 'style': 'color:#d9534f' }, w);
  }));
}

function renderIPv6(p) {
  var rows = [
    [ _('Mode'), p.mode || 'auto' ],
    [ _('Has global v6 address'), p.global_address ? '✓' : '✗' ],
    [ _('Default v6 route'), p.default_route ? '✓' : '✗' ],
    [ _('SLAAC RA seen'), p.slaac_seen ? '✓' : '✗' ]
  ];
  var tbl = renderTable([ _('Field'), _('Value') ], rows);
  var warns = E('div', {});
  if (p.warnings && p.warnings.length > 0) {
    warns.appendChild(E('h4', {}, _('Warnings')));
    warns.appendChild(E('ul', {}, p.warnings.map(function(w) { return E('li', { 'style': 'color:#d9534f' }, w); })));
  }
  return E('div', {}, [ tbl, warns ]);
}

function netCheckMark(s) { return ({ ok: '✓', fail: '✗', warn: '!', na: '·' })[s] || s; }

function renderNetCheck(r) {
  if (!r) return E('p', {}, _('No result.'));
  var color = r.verdict === 'ok' ? '#5cb85c' : (r.verdict === 'degraded' ? '#f0ad4e' : '#d9534f');
  var children = [
    E('p', { 'style': 'font-weight:bold;color:' + color }, _('Mode %s — verdict: %s').format(r.mode || '?', (r.verdict || '?').toUpperCase()))
  ];
  if (r.diagnosis) children.push(E('p', {}, '→ ' + r.diagnosis));
  var layerRows = (r.layers || []).map(function(l) { return [ netCheckMark(l.status) + ' ' + l.name, l.detail || '' ]; });
  children.push(renderTable([ _('Layer'), _('Detail') ], layerRows));
  if (r.nodes && r.nodes.length) {
    var nodeRows = r.nodes.map(function(n) {
      return [ n.verdict, Math.round(n.down_kbps) + ' / ' + Math.round(n.up_kbps) + ' kbps', (n.delay_ms || 0) + ' ms', n.node ];
    });
    children.push(E('h4', {}, _('Per-node throughput (worst first)')));
    children.push(renderTable([ _('Verdict'), _('Down / Up'), _('Delay'), _('Node') ], nodeRows));
  }
  if (r.warnings && r.warnings.length) {
    children.push(E('h4', {}, _('Config warnings')));
    children.push(E('ul', {}, r.warnings.map(function(w) { return E('li', { 'style': 'color:#d9534f' }, w); })));
  }
  return E('div', {}, children);
}

return view.extend({
  render: function() {
    var domain = E('input', { 'class': 'cbi-input-text', 'placeholder': 'chatgpt.com' });
    var out = E('pre', {});
    var warningsOut = E('div', {});
    var ipv6Out = E('div', {});
    var netCheckOut = E('div', {});

    return callStatus().then(function(res) {
      out.textContent = JSON.stringify(res, null, 2);
      return E('div', { 'class': 'cbi-map' }, [
        E('h2', _('PureWRT Diagnostics')),

        renderHealthPanel(),

        E('div', { 'class': 'cbi-section' }, [
          E('h3', _('Quick actions')),
          E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': function(){ return callStatus().then(function(r){ out.textContent = JSON.stringify(r, null, 2); }); } }, _('Refresh status')),
          E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': function(){
            // Update providers then immediately apply — used to be two
            // separate clicks. Async helper avoids the 30s ubus timeout on
            // cold subscription downloads. Surfaces backend output on
            // failure so the user sees *why* it failed.
            out.textContent = _('Update started — polling for completion…');
            return updateAsync.run({ onProgress: function(p) {
              out.textContent = _('Updating… %ds elapsed').format(Math.round(p.elapsedMs / 1000)) +
                '\n' + (p.output || '').slice(-2000);
            } }).then(function(r){
              out.textContent = (r.output || '').slice(-2000);
              if (!r.ok) {
                ui.addNotification(null, fmt.errorDetails(_('Update failed (rc=%s)').format(r.rc), r.output), 'danger');
                return;
              }
              return callReload().then(function(r2) {
                if (r2 && r2.result === 'failed') {
                  ui.addNotification(null, fmt.errorDetails(_('Apply failed'), r2.output), 'danger');
                } else {
                  ui.addNotification(null, E('p', _('Providers updated and PureWRT reloaded.')), 'info');
                }
              });
            }, function(err) {
              ui.addNotification(null, E('p', _('Provider update timed out: %s').format(err && err.message ? err.message : String(err))), 'danger');
            });
          } }, _('Update providers')),
          E('button', { 'class': 'btn cbi-button cbi-button-apply', 'click': function(){
            return callReload().then(function(r){
              out.textContent = JSON.stringify(r, null, 2);
              if (r && r.result === 'failed') {
                ui.addNotification(null, fmt.errorDetails(_('Apply failed'), r.output), 'danger');
              } else {
                ui.addNotification(null, E('p', _('PureWRT reloaded.')), 'info');
              }
            });
          } }, _('Generate & Apply')),
          E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': function(){
            // Empties the dynamic dns_* nftables sets (the resolved-IP routing
            // membership). They repopulate from dnsmasq on the next client
            // query — but cached clients won't re-query until their DNS TTL
            // lapses, so traffic to already-cached domains falls direct in the
            // meantime. Confirm before clearing.
            ui.showModal(_('Flush DNS routing lists?'), [
              E('p', _('Clears the dynamically-resolved IP sets used for per-section routing. They refill as clients make fresh DNS queries; domains still in a client DNS cache route direct until that cache expires.')),
              E('div', { 'class': 'right' }, [
                E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')),
                ' ',
                E('button', { 'class': 'btn cbi-button cbi-button-negative', 'click': function() {
                  ui.hideModal();
                  return callFlushDnsSets().then(function(r){
                    out.textContent = JSON.stringify(r, null, 2);
                    ui.addNotification(null, E('p', _('Flushed %s dynamic DNS list(s).').format((r && typeof r.count !== 'undefined') ? r.count : '?')), 'info');
                  });
                } }, _('Flush'))
              ])
            ]);
          } }, _('Flush DNS lists')),
          E('button', { 'class': 'btn cbi-button cbi-button-remove', 'click': function(){
            // Disable rips out PureWRT-managed routing/DNS. Easy to misclick,
            // hard to undo without re-applying — confirm modal is cheap
            // insurance.
            ui.showModal(_('Disable PureWRT?'), [
              E('p', _('This removes all PureWRT-managed nftables rules and DNS overrides. The router reverts to direct/mwan3 routing. Re-enable by clicking Generate & Apply later.')),
              E('div', { 'class': 'right' }, [
                E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')),
                ' ',
                E('button', { 'class': 'btn cbi-button cbi-button-negative', 'click': function() {
                  ui.hideModal();
                  return callDisable().then(function(r){
                    out.textContent = JSON.stringify(r, null, 2);
                    ui.addNotification(null, E('p', _('PureWRT disabled.')), 'info');
                  });
                } }, _('Disable'))
              ])
            ]);
          } }, _('Disable'))
        ]),

        E('div', { 'class': 'cbi-section' }, [
          E('h3', _('Connectivity test')),
          E('p', {}, _('Drives a real download/upload through the proxy and isolates the failing layer (mihomo / node / routing / WAN). Unlike url-test it catches nodes that answer probes but can\'t carry data. Per-node sweeps every node individually — slower, uses more bandwidth.')),
          E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': function(ev) {
            var btn = ev.target; btn.disabled = true;
            netCheckOut.innerHTML = ''; netCheckOut.appendChild(fmt.spinner(_('Running connectivity test…')));
            return netCheckAsync.run({}).then(function(r) {
              btn.disabled = false; netCheckOut.innerHTML = ''; netCheckOut.appendChild(renderNetCheck(r.report));
            }, function(e) {
              btn.disabled = false; netCheckOut.innerHTML = '';
              ui.addNotification(null, E('p', e.message), 'danger');
            });
          } }, _('Run test')),
          ' ',
          E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': function(ev) {
            var btn = ev.target; btn.disabled = true;
            netCheckOut.innerHTML = ''; netCheckOut.appendChild(fmt.spinner(_('Probing every node — this takes a while…')));
            return netCheckAsync.run({ perNode: true }).then(function(r) {
              btn.disabled = false; netCheckOut.innerHTML = ''; netCheckOut.appendChild(renderNetCheck(r.report));
            }, function(e) {
              btn.disabled = false; netCheckOut.innerHTML = '';
              ui.addNotification(null, E('p', e.message), 'danger');
            });
          } }, _('Per-node test')),
          netCheckOut
        ]),

        E('div', { 'class': 'cbi-section' }, [
          E('h3', _('Bypass warnings')),
          E('p', {}, _('Surfaces censorship-bypass misconfigurations: missing DNS hijack, disabled DoT/DoH3/DoQ block, no DoH bootstrap, expiring subscriptions, missing dnsmasq-full.')),
          E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': function(){
            warningsOut.innerHTML = ''; warningsOut.appendChild(fmt.spinner(_('Checking…')));
            return callDoctorWarnings().then(function(r){
              // rpcd returns { ubus_rpc_session?, ...the JSON array }; if it's an array directly use it, else .warnings.
              var warnings = Array.isArray(r) ? r : (r && r.warnings ? r.warnings : []);
              warningsOut.innerHTML = ''; warningsOut.appendChild(renderWarnings(warnings));
            });
          } }, _('Run check')),
          warningsOut
        ]),

        E('div', { 'class': 'cbi-section' }, [
          E('h3', _('IPv6 path')),
          E('p', {}, _('Inspects the live kernel state vs the configured IPv6 routing mode; flags common silent leaks (mode=off but v6 default route present, mode=on but no v6 addr).')),
          E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': function(){
            ipv6Out.innerHTML = ''; ipv6Out.appendChild(fmt.spinner(_('Inspecting…')));
            return callInspectIPv6().then(function(r){
              ipv6Out.innerHTML = ''; ipv6Out.appendChild(renderIPv6(r || {}));
            });
          } }, _('Inspect IPv6')),
          ipv6Out
        ]),

        E('div', { 'class': 'cbi-section' }, [
          E('h3', _('Site check')),
          domain,
          E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': function(){ out.innerHTML = ''; out.appendChild(fmt.spinner(_('Checking %s…').format(domain.value || 'chatgpt.com'))); return callCheck(domain.value || 'chatgpt.com').then(function(r){ out.textContent = r.output || JSON.stringify(r, null, 2); }); } }, _('Check domain')),
          ' ',
          // After a site check, you usually already know whether the
          // domain needs routing. This CTA jumps straight into the manual
          // rule provider picker prefilled with the domain — one less
          // page hop than going to Rule Providers and pasting it.
          E('button', {
            'class': 'btn cbi-button cbi-button-action',
            'title': _('Open the manual rule provider picker prefilled with this domain so you can route it through a proxy/direct/reject section.'),
            'click': function() {
              var d = (domain.value || '').trim();
              if (!d) {
                ui.addNotification(null, E('p', _('Enter a domain first.')), 'warning');
                return;
              }
              manualModal.openManualPicker({ entry: d });
            }
          }, [ '+ ', _('Add to manual rule provider') ])
        ]),

        E('h3', _('Raw output')),
        out
      ]);
    });
  }
});
