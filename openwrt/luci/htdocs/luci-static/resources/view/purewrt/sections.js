'use strict';
'require view';
'require form';
'require uci';
'require rpc';
'require ui';
'require purewrt.table_section as tableSection';
'require purewrt.vpn_modal as vpnModal';
'require purewrt.format as fmt';

var callReload = rpc.declare({ object: 'purewrt', method: 'reload' });
var callLeases = rpc.declare({ object: 'luci-rpc', method: 'getDHCPLeases' });
var callProxyGroups = rpc.declare({ object: 'purewrt', method: 'proxy_groups', expect: { items: [] } });

// proxyMemberLabel mirrors the mihomo page: name (Nms) / name (dead) / name.
function proxyMemberLabel(mem) {
  if (!mem.alive && mem.delay === 0) return mem.name + ' (' + _('dead') + ')';
  if (mem.delay > 0) return mem.name + ' (' + mem.delay + ' ms)';
  return mem.name;
}

// ---- Devices: per-LAN-device routing (merged from the former Devices tab) ----
// MAC-based assignment of LAN devices to a routing section. Rows come from
// DHCP leases + static dhcp hosts + saved purewrt `device` sections; the
// generator emits `ether saddr` matches (survive DHCP churn, cover IPv6,
// directly-attached L2 only).

function devNormMac(mac) { return String(mac || '').toLowerCase(); }
function deviceSectionID(mac) { return 'dev_' + devNormMac(mac).replace(/:/g, ''); }

// EXCLUDE is the synthetic target meaning "bypass purewrt entirely". For a
// device it maps to a `device` section with exclude=1; for a CIDR it maps to
// the `bypass` section's source_cidr lists.
var EXCLUDE = '__exclude__';

// targetChoices — every enabled section + the Exclude option. Used by both the
// device and IP/CIDR add-modals.
function targetChoices() {
  var out = [];
  uci.sections('purewrt', 'section').forEach(function(s) {
    if ((s.enabled || '1') !== '1') return;
    out.push([ s['.name'], s['.name'] + (s.action ? ' (' + s.action + ')' : '') ]);
  });
  out.push([ EXCLUDE, _('Exclude from purewrt (bypass)') ]);
  return out;
}
function targetLabel(t) { return t === EXCLUDE ? _('excluded (bypass)') : t; }

// targetSelect — an inline dropdown for editing a row's routing target
// (sections + Exclude). Preserves a stale target (deleted/disabled section) as
// a labelled option so it isn't silently changed on render.
function targetSelect(current, onChange) {
  var choices = targetChoices();
  var known = choices.some(function(c) { return c[0] === current; });
  var opts = choices.map(function(c) {
    var o = E('option', { 'value': c[0] }, c[1]);
    if (c[0] === current) o.selected = true;
    return o;
  });
  if (!known && current) {
    var o = E('option', { 'value': current }, current + ' ' + _('(unavailable)'));
    o.selected = true;
    opts.unshift(o);
  }
  var sel = E('select', { 'class': 'cbi-input-select' }, opts);
  sel.addEventListener('change', function() { onChange(sel.value); });
  return sel;
}

// bypassSID resolves the `config bypass` section id (named 'bypass' by default).
function bypassSID() {
  var id = '';
  uci.sections('purewrt', 'bypass').forEach(function(b) { if (!id) id = b['.name']; });
  return id || 'bypass';
}

// managedDeviceRows — ONLY devices deliberately added (saved purewrt `device`
// sections), deduped by MAC. Opt-in list; not the full LAN dump.
function managedDeviceRows() {
  var byMac = {};
  uci.sections('purewrt', 'device').forEach(function(d) {
    var mac = devNormMac(d.mac);
    if (!mac) return;
    byMac[mac] = {
      mac: mac,
      name: d.name || '',
      target: (String(d.exclude) === '1' || d.exclude === true) ? EXCLUDE : (d.section || ''),
      enabled: (d.enabled || '1') === '1'
    };
  });
  return Object.keys(byMac).sort().map(function(k) { return byMac[k]; });
}

// knownDevices — MAC → {hostname, ip} from DHCP leases + static hosts, for the
// add-device picker.
function knownDevices(leases) {
  var m = {};
  (leases || []).forEach(function(l) { var mac = devNormMac(l.macaddr); if (mac) m[mac] = { hostname: l.hostname || '', ip: l.ipaddr || '' }; });
  uci.sections('dhcp', 'host').forEach(function(h) { var mac = devNormMac(h.mac); if (mac && !m[mac]) m[mac] = { hostname: h.name || '', ip: h.ip || '' }; });
  return m;
}

var MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;
function precedenceNote() {
  return _('Precedence: excluded devices/CIDRs bypass purewrt entirely (checked first); then device (MAC) assignments; then IP/CIDR assignments; then destination rules. A device matched by MAC always wins over one matched by IP/CIDR, regardless of section priority.');
}

// deviceSectionsForMac returns the ids of every purewrt `device` section whose
// mac matches — used to purge duplicates/legacy sections on (re)assign/remove.
function deviceSectionsForMac(mac) {
  var ids = [];
  uci.sections('purewrt', 'device').forEach(function(d) { if (devNormMac(d.mac) === mac) ids.push(d['.name']); });
  return ids;
}

// buildDevicesSection — opt-in managed-device list. Every edit STAGES a UCI
// change (add/remove/reassign device sections); the page's standard Save &
// Apply commits it with LuCI's normal change diff, and purewrt reloads via its
// procd config trigger (fingerprint-gated). No bespoke save button.
function buildDevicesSection(leases) {
  var known = knownDevices(leases);
  var body = E('div');
  // Resolve a display name from live leases/DHCP first (a hand-typed MAC still
  // shows its current hostname), then the stored snapshot, then the MAC.
  function displayName(mac, stored) { var k = known[mac]; return (k && k.hostname) || stored || mac; }

  function renderRows() {
    body.innerHTML = '';
    var rows = managedDeviceRows();
    var table = E('table', { 'class': 'table cbi-section-table' }, [
      E('tr', { 'class': 'tr table-titles' }, [
        E('th', { 'class': 'th' }, _('Device')), E('th', { 'class': 'th' }, _('MAC')),
        E('th', { 'class': 'th' }, _('Routing target')), E('th', { 'class': 'th' }, _('Enabled')), E('th', { 'class': 'th' }, '')
      ])
    ]);
    if (!rows.length)
      table.appendChild(E('tr', { 'class': 'tr' }, E('td', { 'class': 'td', 'colspan': 5 }, E('em', {}, _('No managed devices — click “Add device”.')))));
    rows.forEach(function(row) {
      var sid = deviceSectionID(row.mac);
      var en = E('input', { 'type': 'checkbox' }); en.checked = row.enabled;
      en.addEventListener('change', function() { uci.set('purewrt', sid, 'enabled', en.checked ? '1' : '0'); });
      var sel = targetSelect(row.target, function(v) {
        if (v === EXCLUDE) { uci.set('purewrt', sid, 'exclude', '1'); uci.unset('purewrt', sid, 'section'); }
        else { uci.set('purewrt', sid, 'section', v); uci.unset('purewrt', sid, 'exclude'); }
        renderRows();
      });
      var rm = E('button', { 'class': 'btn cbi-button cbi-button-remove' }, _('Remove'));
      rm.addEventListener('click', function(ev) { ev.preventDefault(); deviceSectionsForMac(row.mac).forEach(function(id) { uci.remove('purewrt', id); }); renderRows(); });
      var dn = displayName(row.mac, row.name);
      table.appendChild(E('tr', { 'class': 'tr' }, [
        E('td', { 'class': 'td' }, dn || E('em', {}, _('(unknown)'))),
        E('td', { 'class': 'td', 'style': 'font-family:monospace' }, row.mac),
        E('td', { 'class': 'td' }, sel),
        E('td', { 'class': 'td' }, en),
        E('td', { 'class': 'td' }, rm)
      ]));
    });
    body.appendChild(table);
  }
  renderRows();

  var addBtn = E('button', { 'class': 'btn cbi-button cbi-button-action' }, [ '+ ', _('Add device') ]);
  addBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    var have = {}; managedDeviceRows().forEach(function(r) { have[r.mac] = true; });
    var picker = E('select', { 'class': 'cbi-input-select' });
    picker.appendChild(E('option', { 'value': '' }, _('— pick a known device —')));
    Object.keys(known).sort().forEach(function(mac) {
      if (have[mac]) return;
      var d = known[mac];
      picker.appendChild(E('option', { 'value': mac }, (d.hostname || _('(unknown)')) + ' — ' + mac + (d.ip ? ' (' + d.ip + ')' : '')));
    });
    var macInput = E('input', { 'class': 'cbi-input-text', 'placeholder': 'aa:bb:cc:dd:ee:ff' });
    picker.addEventListener('change', function() { if (picker.value) macInput.value = picker.value; });
    var tgt = E('select', { 'class': 'cbi-input-select' }, targetChoices().map(function(c) { return E('option', { 'value': c[0] }, c[1]); }));
    ui.showModal(_('Add device'), [
      E('div', { 'class': 'cbi-value' }, [ E('label', { 'class': 'cbi-value-title' }, _('Known device')), E('div', { 'class': 'cbi-value-field' }, picker) ]),
      E('div', { 'class': 'cbi-value' }, [ E('label', { 'class': 'cbi-value-title' }, _('MAC address')), E('div', { 'class': 'cbi-value-field' }, macInput) ]),
      E('div', { 'class': 'cbi-value' }, [ E('label', { 'class': 'cbi-value-title' }, _('Route to')), E('div', { 'class': 'cbi-value-field' }, tgt) ]),
      E('div', { 'class': 'right' }, [
        E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
        E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': function() {
          var mac = devNormMac((macInput.value || '').trim());
          if (!MAC_RE.test(mac)) { ui.addNotification(null, E('p', _('Enter a valid MAC address (aa:bb:cc:dd:ee:ff).')), 'warning'); return; }
          if (have[mac]) { ui.addNotification(null, E('p', _('That device is already managed.')), 'warning'); return; }
          ui.hideModal();
          var sid = deviceSectionID(mac);
          deviceSectionsForMac(mac).forEach(function(id) { uci.remove('purewrt', id); }); // drop any legacy/dupes
          uci.add('purewrt', 'device', sid);
          uci.set('purewrt', sid, 'mac', mac);
          uci.set('purewrt', sid, 'name', displayName(mac, ''));
          uci.set('purewrt', sid, 'enabled', '1');
          if (tgt.value === EXCLUDE) uci.set('purewrt', sid, 'exclude', '1');
          else uci.set('purewrt', sid, 'section', tgt.value);
          renderRows();
        } }, _('Add'))
      ])
    ]);
  });

  return E('div', { 'class': 'cbi-section' }, [
    E('h3', {}, _('Devices')),
    E('div', { 'class': 'cbi-section-descr' }, _('Opt-in per-device routing (MAC-based; directly-attached LAN only — clients behind a downstream router share its MAC). Add a device to route it through a section or exclude it from purewrt. Unlisted devices use default routing. Changes are staged — review + commit with Save & Apply.')),
    body,
    E('div', { 'style': 'margin-top:.5em' }, [ addBtn ])
  ]);
}

// cidrKey / cidrTargetSID map a mapping row to the UCI list it lives in.
function cidrKey(family) { return family === 6 ? 'source_cidr6' : 'source_cidr4'; }
function cidrTargetSID(target) {
  if (target !== EXCLUDE) return target;
  var id = bypassSID();
  if (!uci.get('purewrt', id)) uci.add('purewrt', 'bypass', id); // ensure the bypass section exists
  return id;
}
function cidrListRemove(cidr, family, target) {
  var sid = cidrTargetSID(target), key = cidrKey(family);
  var list = (uci.get('purewrt', sid, key) || []).filter(function(c) { return c !== cidr; });
  if (list.length) uci.set('purewrt', sid, key, list); else uci.unset('purewrt', sid, key);
}
function cidrListAdd(cidr, family, target) {
  var sid = cidrTargetSID(target), key = cidrKey(family);
  var list = (uci.get('purewrt', sid, key) || []).slice();
  if (list.indexOf(cidr) < 0) list.push(cidr);
  uci.set('purewrt', sid, key, list);
}

// buildCIDRSection — dedicated "IP/CIDR → section (or exclude)" mapping. Rows
// come from every section's source_cidr4/6 + the bypass section's. Edits STAGE
// UCI list changes (committed via the page's standard Save & Apply). One target
// per CIDR (re-adding reassigns).
function buildCIDRSection() {
  var body = E('div');

  function cidrRows() {
    var rows = [];
    uci.sections('purewrt', 'section').forEach(function(s) {
      if ((s.enabled || '1') !== '1') return;
      (s.source_cidr4 || []).forEach(function(c) { rows.push({ cidr: c, family: 4, target: s['.name'] }); });
      (s.source_cidr6 || []).forEach(function(c) { rows.push({ cidr: c, family: 6, target: s['.name'] }); });
    });
    var bsid = bypassSID();
    (uci.get('purewrt', bsid, 'source_cidr4') || []).forEach(function(c) { rows.push({ cidr: c, family: 4, target: EXCLUDE }); });
    (uci.get('purewrt', bsid, 'source_cidr6') || []).forEach(function(c) { rows.push({ cidr: c, family: 6, target: EXCLUDE }); });
    return rows;
  }

  function renderRows() {
    body.innerHTML = '';
    var rows = cidrRows();
    var table = E('table', { 'class': 'table cbi-section-table' }, [
      E('tr', { 'class': 'tr table-titles' }, [
        E('th', { 'class': 'th' }, _('IP / CIDR')), E('th', { 'class': 'th' }, _('Family')),
        E('th', { 'class': 'th' }, _('Routing target')), E('th', { 'class': 'th' }, '')
      ])
    ]);
    if (!rows.length)
      table.appendChild(E('tr', { 'class': 'tr' }, E('td', { 'class': 'td', 'colspan': 4 }, E('em', {}, _('No IP/CIDR mappings — click “Add IP/CIDR”.')))));
    rows.forEach(function(row) {
      var rm = E('button', { 'class': 'btn cbi-button cbi-button-remove' }, _('Remove'));
      rm.addEventListener('click', function(ev) { ev.preventDefault(); cidrListRemove(row.cidr, row.family, row.target); renderRows(); });
      var sel = targetSelect(row.target, function(v) {
        if (v === row.target) return;
        cidrListRemove(row.cidr, row.family, row.target);
        cidrListAdd(row.cidr, row.family, v);
        renderRows();
      });
      table.appendChild(E('tr', { 'class': 'tr' }, [
        E('td', { 'class': 'td', 'style': 'font-family:monospace' }, row.cidr),
        E('td', { 'class': 'td' }, 'IPv' + row.family),
        E('td', { 'class': 'td' }, sel),
        E('td', { 'class': 'td' }, rm)
      ]));
    });
    body.appendChild(table);
  }
  renderRows();

  var addBtn = E('button', { 'class': 'btn cbi-button cbi-button-action' }, [ '+ ', _('Add IP/CIDR') ]);
  addBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    var cidrInput = E('input', { 'class': 'cbi-input-text', 'placeholder': '10.0.0.0/24 or 2001:db8::/48' });
    var tgt = E('select', { 'class': 'cbi-input-select' }, targetChoices().map(function(c) { return E('option', { 'value': c[0] }, c[1]); }));
    ui.showModal(_('Add IP/CIDR mapping'), [
      E('div', { 'class': 'cbi-value' }, [ E('label', { 'class': 'cbi-value-title' }, _('IP or CIDR')), E('div', { 'class': 'cbi-value-field' }, cidrInput) ]),
      E('div', { 'class': 'cbi-value' }, [ E('label', { 'class': 'cbi-value-title' }, _('Route to')), E('div', { 'class': 'cbi-value-field' }, tgt) ]),
      E('div', { 'class': 'right' }, [
        E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
        E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': function() {
          var cidr = (cidrInput.value || '').trim().toLowerCase();
          var valid = fmt.validateCIDR(cidr);
          if (valid !== true) { ui.addNotification(null, E('p', valid), 'warning'); return; }
          var family = cidr.indexOf(':') >= 0 ? 6 : 4;
          ui.hideModal();
          // One target per CIDR — re-adding reassigns (purge any existing entry
          // for this CIDR across every target first).
          cidrRows().forEach(function(r) { if (r.cidr === cidr) cidrListRemove(r.cidr, r.family, r.target); });
          cidrListAdd(cidr, family, tgt.value);
          renderRows();
        } }, _('Add'))
      ])
    ]);
  });

  return E('div', { 'class': 'cbi-section' }, [
    E('h3', {}, _('IP / CIDR routing')),
    E('div', { 'class': 'cbi-section-descr' }, _('Route source IPs/CIDRs through a section or exclude them from purewrt entirely. Each IP/CIDR maps to exactly one target. Changes are staged — review + commit with Save & Apply.')),
    body,
    E('div', { 'style': 'margin-top:.5em' }, [ addBtn ])
  ]);
}

function sectionTitle(sid) {
  return uci.get('purewrt', sid, 'proxy_group') || sid || _('New routing section');
}

function vpnTitle(section) {
  return section.name || section['.name'];
}

function routingSummary(sid) {
  var action = uci.get('purewrt', sid, 'action') || 'proxy';
  var vpns = (uci.get('purewrt', sid, 'vpns') || []);
  var target = action === 'proxy'
    ? (uci.get('purewrt', sid, 'tproxy_port') || '-') + (vpns.length ? ' vpn:' + vpns.join(',') : '')
    : (action === 'zapret' ? ((uci.get('purewrt', sid, 'zapret_strategy') || []).join(', ') || '-') : '-');
  return [
    sectionTitle(sid),
    action,
    target,
    uci.get('purewrt', sid, 'priority') || '1000'
  ];
}

return view.extend({
  load: function() {
    return Promise.all([
      uci.load('purewrt'),
      uci.load('dhcp').catch(function() { return null; }),
      callLeases().catch(function() { return { dhcp_leases: [] }; }),
      callProxyGroups().catch(function() { return []; })
    ]);
  },

  render: function(data) {
    var leases = (data && data[2] && (data[2].dhcp_leases || data[2].leases)) || [];
    // Live proxy-group membership from mihomo, keyed by owning section, so each
    // proxy section can show which servers its filter/exclude actually selects.
    var groupsBySection = {};
    ((data && data[3]) || []).forEach(function(g) {
      if (g && g.section) groupsBySection[g.section] = g;
    });
    var m = new form.Map('purewrt', _('PureWRT Sections / Routing'));

    m.handleSaveApply = function(ev, mode) {
      return m.save(null, mode).then(function() {
        return callReload();
      }).then(function() {
        ui.addNotification(null, E('p', _('Routing sections saved and PureWRT applied')), 'info');
      });
    };

    var s = m.section(form.TypedSection, 'section', _('Routing sections'));
    s.addremove = true;
    s.anonymous = false;
    s.sectiontitle = sectionTitle;

    // Soft warning before removing the catch-all section. The `common` section
    // provides the `Common` proxy group that the generated `MATCH,Common`
    // catch-all targets; without it the catch-all degrades to DIRECT (unmatched
    // traffic goes unproxied). Non-blocking — inform, don't trap (the generator
    // handles the fallback safely either way).
    var origRemove = s.handleRemove;
    s.handleRemove = function(section_id, ev) {
      var pg = uci.get('purewrt', section_id, 'proxy_group');
      if (section_id !== 'common' && pg !== 'Common')
        return origRemove.call(s, section_id, ev);
      return new Promise(function(resolve) {
        ui.showModal(_('Delete the catch-all section?'), [
          E('p', _('“%s” provides the Common proxy group that the catch-all (MATCH) routes to. With it removed, all unmatched traffic falls back to DIRECT (unproxied) — the router stays online but those flows bypass the proxy.').format(section_id)),
          E('div', { 'class': 'right' }, [
            E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')),
            ' ',
            E('button', { 'class': 'btn cbi-button cbi-button-negative', 'click': function(ev2) {
              ui.hideModal();
              resolve(origRemove.call(s, section_id, ev2));
            } }, _('Delete anyway'))
          ])
        ]);
      });
    };

    var enabled = s.option(form.Flag, 'enabled', _('Enabled'));
    enabled.rmempty = false;
    var action = s.option(form.ListValue, 'action', _('Action'));
    action.value('proxy', _('Proxy — route via mihomo'));
    action.value('direct', _('Direct — no proxy'));
    action.value('reject', _('Reject — drop traffic'));
    action.value('zapret', _('Zapret — DPI bypass'));
    action.rmempty = false;
    var tproxy = s.option(form.Value, 'tproxy_port', _('TPROXY port'));
    tproxy.retain = true;
    tproxy.depends('action', 'proxy');
    var proxyGroup = s.option(form.Value, 'proxy_group', _('Mihomo proxy group'));
    proxyGroup.retain = true;
    proxyGroup.depends('action', 'proxy');
    var proxyGroupType = s.option(form.ListValue, 'proxy_group_type', _('Proxy group type'));
    proxyGroupType.value('select', _('Select — pick a node manually'));
    proxyGroupType.value('url-test', _('URL-test — auto-pick fastest'));
    proxyGroupType.value('load-balance', _('Load-balance — spread across nodes'));
    proxyGroupType.default = 'url-test';
    proxyGroupType.rmempty = false;
    proxyGroupType.retain = true;
    proxyGroupType.depends('action', 'proxy');
    var proxyFilter = s.option(form.Value, 'proxy_filter', _('Proxy filter'));
    proxyFilter.retain = true;
    proxyFilter.depends('action', 'proxy');
    proxyFilter.description = _('Mihomo regex include filter applied across all proxy providers for this section group. Empty includes all proxies.');
    var proxyExcludeFilter = s.option(form.Value, 'proxy_exclude_filter', _('Proxy exclude-filter'));
    proxyExcludeFilter.retain = true;
    proxyExcludeFilter.depends('action', 'proxy');
    proxyExcludeFilter.description = _('Mihomo regex exclude filter applied after the include filter.');
    // Read-only preview of the proxy servers mihomo actually selected for this
    // section's group (filter + exclude-filter resolved at runtime). Reflects
    // the APPLIED config — edits show after Save + reload. Section id == name,
    // which is how proxy_groups maps a group back to its owning section.
    var matchedNodes = s.option(form.DummyValue, '_matched_nodes', _('Matched proxy nodes (live)'));
    matchedNodes.depends('action', 'proxy');
    matchedNodes.cfgvalue = function() { return null; };
    matchedNodes.renderWidget = function(section_id) {
      var g = groupsBySection[section_id];
      if (!g || !g.members || !g.members.length) {
        return E('em', { 'class': 'cbi-section-note' },
          _('Unavailable — apply the config and ensure mihomo is running.'));
      }
      var chips = g.members.map(function(mem) {
        var isNow = (mem.name === g.now);
        return E('span', {
          'style': 'display:inline-block;margin:0 .4em .3em 0;padding:.1em .45em;border-radius:.3em;'
            + 'background:rgba(127,127,127,.15)' + (isNow ? ';font-weight:bold' : '')
        }, proxyMemberLabel(mem) + (isNow ? ' ◀' : ''));
      });
      return E('div', {}, [
        E('div', {}, chips),
        E('div', { 'class': 'cbi-section-note' },
          _('%d node(s) selected by the current filter — reflects the applied config (edits show after Save + reload).').format(g.members.length))
      ]);
    };
    var proxyStrategy = s.option(form.ListValue, 'proxy_strategy', _('Load-balance strategy'));
    proxyStrategy.value('sticky-sessions', _('Sticky — same node per src/dst'));
    proxyStrategy.value('consistent-hashing', _('Hashing — node by destination'));
    proxyStrategy.value('round-robin', _('Round-robin — rotate nodes'));
    proxyStrategy.default = 'sticky-sessions';
    proxyStrategy.rmempty = false;
    proxyStrategy.retain = true;
    proxyStrategy.depends('proxy_group_type', 'load-balance');
    var proxyHealthURL = s.option(form.Value, 'proxy_health_check_url', _('Proxy group health-check URL'));
    proxyHealthURL.placeholder = 'https://www.gstatic.com/generate_204';
    proxyHealthURL.description = _('Mihomo url used by url-test and load-balance groups. Empty uses the PureWRT default.');
    proxyHealthURL.retain = true;
    proxyHealthURL.depends('proxy_group_type', 'url-test');
    proxyHealthURL.depends('proxy_group_type', 'load-balance');
    var proxyHealthInterval = s.option(form.Value, 'proxy_health_check_interval', _('Proxy group health-check interval'));
    proxyHealthInterval.placeholder = '300';
    proxyHealthInterval.datatype = 'uinteger';
    proxyHealthInterval.description = _('Mihomo health-check interval in seconds for url-test and load-balance groups. Empty or 0 uses the PureWRT default.');
    proxyHealthInterval.retain = true;
    proxyHealthInterval.depends('proxy_group_type', 'url-test');
    proxyHealthInterval.depends('proxy_group_type', 'load-balance');
    var manualProxyGroup = s.option(form.Flag, 'user_overridden_proxy_group', _('Manual proxy group settings'));
    manualProxyGroup.description = _('When enabled, subscription auto-import will not overwrite group type, filter, exclude-filter, or load-balance strategy for this section.');
    manualProxyGroup.rmempty = false;
    manualProxyGroup.retain = true;
    manualProxyGroup.depends('action', 'proxy');
    var priority = s.option(form.Value, 'priority', _('Routing order'));
    priority.datatype = 'integer';
    priority.description = _('Lower value has higher precedence and is emitted earlier in nftables routing rules.');
    // Source CIDRs are edited in the dedicated "IP / CIDR routing" table below,
    // not per-section here, so `source_cidr4/6` intentionally have no options.
    var udp = s.option(form.ListValue, 'udp_mode', _('UDP mode'));
    udp.value('proxy');
    udp.value('block_quic');
    udp.value('tcp_only');
    udp.retain = true;
    udp.depends('action', 'proxy');
    s.option(form.Flag, 'ipv4_enabled', _('IPv4'));
    s.option(form.Flag, 'ipv6_enabled', _('IPv6'));
    // VPN members: VPN interfaces added to this section's mihomo proxy pool
    // (alongside subscription nodes). mihomo routes the section through the
    // pool with its group type/strategy + url-test failover across the VPNs.
    var vpns = s.option(form.DynamicList, 'vpns', _('VPN members'));
    vpns.depends('action', 'proxy');
    vpns.rmempty = true;
    vpns.description = _('VPN interfaces this section routes through (pooled with any subscription nodes, url-test failover). Define VPNs with "Manage VPNs".');
    (uci.sections('purewrt', 'vpn') || []).forEach(function(section) {
      var name = vpnTitle(section);
      if (name) vpns.value(name, name + (section.interface ? ' (' + section.interface + ')' : ''));
    });
    // Inline "Manage VPNs" button opens the VPN modal to define interfaces.
    // On save we reload (UCI is committed by the modal) so the option list
    // repopulates — VPN definitions change rarely, so the reload is fine.
    var origVpnsRender = vpns.renderWidget.bind(vpns);
    vpns.renderWidget = function(section_id, option_id, cfgvalue) {
      var widget = origVpnsRender.call(this, section_id, option_id, cfgvalue);
      var addBtn = E('button', { 'class': 'btn cbi-button cbi-button-action', 'style': 'margin-left:.5em;white-space:nowrap' }, [ '+ ', _('Manage VPNs') ]);
      addBtn.addEventListener('click', function(ev) {
        ev.preventDefault();
        vpnModal.openVPNManager({ onClose: function() { location.reload(); } });
      });
      return E('div', { 'style': 'display:flex;align-items:center;flex-wrap:wrap;gap:.25em' }, [ widget, addBtn ]);
    };

    var zapretStrategies = s.option(form.DynamicList, 'zapret_strategy', _('Zapret strategies'));
    zapretStrategies.depends('action', 'zapret');
    zapretStrategies.description = _('One or more Zapret strategies applied to this routing section. Configure strategy details on the Zapret page.');
    uci.sections('purewrt', 'zapret_strategy').forEach(function(section) {
      var name = section.name || section['.name'];

      if (name)
        zapretStrategies.value(name, name);
    });

    return m.render().then(function(root) {
      tableSection.render(root, {
        columns: '5rem 0 2fr 1fr 1fr 1fr 12rem',
        headers: [ '', '', _('Name'), _('Action'), _('Target'), _('Priority'), '' ],
        draggable: true,
        titleOf: sectionTitle,
        summaryOf: routingSummary,
        save: function() { return m.save().then(callReload); },
        actions: [
          { label: _('Edit'), kind: 'edit' },
          { label: _('Delete'), kind: 'delete', style: 'remove' }
        ]
      });
      // Page order: Routing sections → IP/CIDR routing → Devices, with a
      // shared precedence note.
      root.appendChild(E('div', { 'class': 'cbi-section-descr', 'style': 'margin-top:1em' }, precedenceNote()));
      root.appendChild(buildCIDRSection());
      root.appendChild(buildDevicesSection(leases));
      return root;
    });
  }
});
