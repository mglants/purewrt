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

function collectDeviceRows(leases) {
  var rows = {};
  (leases || []).forEach(function(l) {
    var mac = devNormMac(l.macaddr);
    if (!mac) return;
    rows[mac] = { mac: mac, hostname: l.hostname || '', ip: l.ipaddr || '', online: true, isStatic: false, section: '', enabled: true };
  });
  uci.sections('dhcp', 'host').forEach(function(h) {
    var mac = devNormMac(h.mac);
    if (!mac) return;
    if (!rows[mac]) rows[mac] = { mac: mac, hostname: h.name || '', ip: h.ip || '', online: false, isStatic: true, section: '', enabled: true };
    else rows[mac].isStatic = true;
  });
  uci.sections('purewrt', 'device').forEach(function(d) {
    var mac = devNormMac(d.mac);
    if (!mac) return;
    if (!rows[mac]) rows[mac] = { mac: mac, hostname: d.name || '', ip: '', online: false, isStatic: false, section: '', enabled: true };
    rows[mac].section = d.section || '';
    rows[mac].enabled = (d.enabled || '1') === '1';
    if (!rows[mac].hostname && d.name) rows[mac].hostname = d.name;
  });
  return Object.keys(rows).sort().map(function(k) { return rows[k]; });
}

function deviceSectionChoices() {
  var out = [ [ '', _('(unassigned — default routing)') ] ];
  uci.sections('purewrt', 'section').forEach(function(s) {
    if ((s.enabled || '1') !== '1') return;
    out.push([ s['.name'], s['.name'] + (s.action ? ' (' + s.action + ')' : '') ]);
  });
  return out;
}

// buildDevicesSection renders the devices table + its own Save & Apply
// (devices are dynamic lease-derived rows, not form.Map sections, so they
// carry a self-contained save like the old Devices tab).
function buildDevicesSection(leases) {
  var rows = collectDeviceRows(leases);
  var choices = deviceSectionChoices();

  var table = E('table', { 'class': 'table cbi-section-table' }, [
    E('tr', { 'class': 'tr table-titles' }, [
      E('th', { 'class': 'th' }, _('Device')),
      E('th', { 'class': 'th' }, _('MAC')),
      E('th', { 'class': 'th' }, _('IPv4')),
      E('th', { 'class': 'th' }, _('Lease')),
      E('th', { 'class': 'th' }, _('Routing section')),
      E('th', { 'class': 'th' }, _('Enabled'))
    ])
  ]);
  if (!rows.length) {
    table.appendChild(E('tr', { 'class': 'tr' }, E('td', { 'class': 'td', 'colspan': 6 }, E('em', {}, _('No known LAN devices — no DHCP leases and no saved assignments.')))));
  }
  rows.forEach(function(row) {
    var badge = !row.online ? fmt.pill(_('offline'), 'muted') : (row.isStatic ? fmt.pill(_('static'), 'info') : fmt.pill(_('dynamic'), 'ok'));
    var sel = E('select', { 'class': 'cbi-input-select' }, choices.map(function(ch) {
      var o = E('option', { 'value': ch[0] }, ch[1]);
      if (ch[0] === row.section) o.selected = true;
      return o;
    }));
    var en = E('input', { 'type': 'checkbox' });
    en.checked = row.enabled;
    row._sel = sel;
    row._en = en;
    table.appendChild(E('tr', { 'class': 'tr' }, [
      E('td', { 'class': 'td' }, row.hostname || E('em', {}, _('(unknown)'))),
      E('td', { 'class': 'td', 'style': 'font-family:monospace' }, row.mac),
      E('td', { 'class': 'td', 'style': 'font-family:monospace' }, row.ip || '—'),
      E('td', { 'class': 'td' }, badge),
      E('td', { 'class': 'td' }, sel),
      E('td', { 'class': 'td' }, en)
    ]));
  });

  var saveBtn = E('button', { 'class': 'btn cbi-button cbi-button-apply', 'click': function(ev) {
    ev.preventDefault();
    // Only write (and apply) when something actually differs from the saved
    // UCI — a no-op uci.apply() fails with ubus "No data received" (code 5).
    var changed = false;
    rows.forEach(function(row) {
      var section = row._sel.value;
      var enabled = row._en.checked ? '1' : '0';
      var sid = deviceSectionID(row.mac);
      var exists = uci.get('purewrt', sid);
      if (!section) {
        if (exists) { uci.remove('purewrt', sid); changed = true; }
        return;
      }
      if (!exists) {
        uci.add('purewrt', 'device', sid);
        changed = true;
      } else if (uci.get('purewrt', sid, 'section') !== section ||
                 (uci.get('purewrt', sid, 'enabled') || '1') !== enabled) {
        changed = true;
      }
      uci.set('purewrt', sid, 'name', row.hostname || row.mac);
      uci.set('purewrt', sid, 'mac', row.mac);
      uci.set('purewrt', sid, 'section', section);
      uci.set('purewrt', sid, 'enabled', enabled);
    });
    if (!changed) {
      ui.addNotification(null, E('p', _('No device assignment changes to apply.')), 'info');
      return;
    }
    ev.target.disabled = true;
    uci.save()
      .then(function() { return uci.apply(); })
      .then(function() { return callReload(); })
      .then(function() {
        ui.addNotification(null, E('p', _('Device assignments saved and PureWRT applied')), 'info');
        ev.target.disabled = false;
      })
      .catch(function(err) {
        ui.addNotification(null, E('p', _('Save failed: ') + err), 'error');
        ev.target.disabled = false;
      });
  } }, _('Save & Apply devices'));

  return E('div', { 'class': 'cbi-section' }, [
    E('h3', {}, _('Devices')),
    E('div', { 'class': 'cbi-section-descr' }, _(
      'Route individual LAN devices through a section without writing CIDRs. Matching is MAC-based (survives DHCP renewals, covers IPv6) and only works for devices directly attached to this router’s LAN — clients behind a downstream router share its MAC.'
    )),
    table,
    E('div', { 'style': 'margin-top:.5em' }, [ saveBtn ])
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
    var source4 = s.option(form.DynamicList, 'source_cidr4', _('Source IPv4/CIDR routed by this section'));
    source4.description = _('LAN/client source IPv4 addresses or CIDRs. Traffic from these sources uses this section action even without destination rule providers.');
    var source6 = s.option(form.DynamicList, 'source_cidr6', _('Source IPv6/CIDR routed by this section'));
    source6.description = _('LAN/client source IPv6 addresses or CIDRs. Ignored when IPv6 is disabled or low-resource mode is active.');
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
        vpnModal.openVPNModal({ onSave: function() { location.reload(); } });
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
      root.appendChild(buildDevicesSection(leases));
      return root;
    });
  }
});
