'use strict';
'require view';
'require form';
'require uci';
'require rpc';
'require ui';
'require purewrt.table_section as tableSection';
'require purewrt.update_async as updateAsync';
'require purewrt.save_chain as saveChain';
'require purewrt.format as fmt';

var callReload = rpc.declare({ object: 'purewrt', method: 'reload' });
var callSubscriptionExpiry = rpc.declare({ object: 'purewrt', method: 'subscription_expiry' });
var callConfigState = rpc.declare({ object: 'purewrt', method: 'config_state' });

// humanAgo lives in purewrt.format — shared with general.js and
// statistics.js. Used by the last-applied indicator at the top of the page.
var humanAgo = fmt.humanAgo;

// configBanner shows when the live mihomo config was last regenerated and
// flags when the saved UCI is newer than the applied generation (dirty).
// Hidden when both timestamps are zero (fresh install, nothing applied yet).
function configBanner(state) {
  if (!state) return null;
  var applied = Number(state.applied_unix || 0);
  var dirty = !!state.dirty;
  if (!applied && !dirty) return null;
  var bg = dirty ? '#f0ad4e' : '#5cb85c';
  var parts = [];
  if (applied) parts.push(_('Last applied: %s ago').format(humanAgo(applied)));
  if (dirty) parts.push(_('Config has unapplied changes — click Save & Apply to push them.'));
  return E('div', {
    'style': 'background:' + bg + ';color:white;padding:0.5em 1em;border-radius:4px;margin-bottom:1em'
  }, parts.join(' · '));
}

// humanBytes turns a raw byte count into a 1-decimal MiB/GiB/TiB string —
// matches what `subscription-userinfo` panels typically present in their
// own UI so the LuCI banner reads naturally.
function humanBytes(n) {
  n = Number(n || 0);
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KiB';
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MiB';
  if (n < 1024 * 1024 * 1024 * 1024) return (n / 1024 / 1024 / 1024).toFixed(2) + ' GiB';
  return (n / 1024 / 1024 / 1024 / 1024).toFixed(2) + ' TiB';
}

// expiryBanner renders a yellow/red header strip listing any subscription
// that's expiring within 7 days, already expired, OR ≥80% of its quota
// consumed. Pulls from the subscription_expiry rpcd which parses each
// subscription's persisted Metadata.SubExpire / SubUsedBytes /
// SubTotalBytes (extracted from the subscription-userinfo response
// header in Wave 1.3).
function expiryBanner(entries) {
  if (!entries || !entries.length) return null;
  var needs = [];
  entries.forEach(function(e) { if (e.needs_attention) needs.push(e); });
  if (!needs.length) return null;
  var anyExpired = needs.some(function(e) { return e.expire_unix && (e.days_remaining || 0) <= 0; });
  var anyExhausted = needs.some(function(e) { return (e.quota_percent || 0) >= 95; });
  var color = (anyExpired || anyExhausted) ? '#d9534f' : '#f0ad4e';
  var lines = needs.map(function(e) {
    var parts = [ E('strong', {}, e.name), ' — ' ];
    if (e.expire_unix) {
      var d = Number(e.days_remaining || 0);
      parts.push(d <= 0
        ? _('expired %d day(s) ago').format(Math.abs(Math.floor(d)))
        : _('expires in %d day(s)').format(Math.ceil(d)));
    } else {
      parts.push(_('quota warning'));
    }
    if (e.total_bytes) {
      parts.push(' · ');
      parts.push(_('quota %s%% used (%s / %s)').format(
        (e.quota_percent || 0).toFixed(1),
        humanBytes(e.used_bytes),
        humanBytes(e.total_bytes)
      ));
    }
    return E('li', {}, parts);
  });
  var titleKey = anyExpired ? _('Subscription expired')
    : anyExhausted ? _('Subscription quota nearly exhausted')
    : _('Subscription needs attention');
  return E('div', {
    'style': 'background:' + color + ';color:white;padding:1em;border-radius:4px;margin-bottom:1em'
  }, [
    E('strong', {}, titleKey),
    E('ul', { 'style': 'margin:0.5em 0 0 1.5em' }, lines)
  ]);
}

// quotaCellFor returns a short table-cell label like "13.2 GiB / 100 GiB
// (13%)" for the given expiry entry, or "-" when the panel didn't send
// subscription-userinfo. Used to add a "Quota" column to the subscriptions
// table without forcing the user to drill into the banner.
function quotaCellFor(entry) {
  if (!entry || !entry.total_bytes) return '-';
  return _('%s / %s (%s%%)').format(
    humanBytes(entry.used_bytes),
    humanBytes(entry.total_bytes),
    (entry.quota_percent || 0).toFixed(0)
  );
}

// expiryCellFor renders a short label like "in 13d" / "expired 2d ago" /
// "-". Used to add an "Expires" column to the subscriptions table.
function expiryCellFor(entry) {
  if (!entry || !entry.expire_unix) return '-';
  var d = Number(entry.days_remaining || 0);
  if (d <= 0) return _('expired %d d ago').format(Math.abs(Math.floor(d)));
  return _('in %d d').format(Math.ceil(d));
}

function sectionTitle(sid) {
  return uci.get('purewrt', sid, 'name') || sid || _('New subscription');
}

function updateSubscriptions() {
  ui.addNotification(null, E('p', _('Updating providers — this may take a minute on first run.')), 'info');
  return updateAsync.run().then(function(r) {
    if (!r.ok) {
      ui.addNotification(null, fmt.errorDetails(_('Provider update failed (rc=%s)').format(r.rc), r.output), 'danger');
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
}

// expiryByName indexes the rpcd payload so subscriptionSummary can pull
// per-row quota/expiry without re-fetching. Populated in render() before
// the summaries are computed.
var expiryByName = {};

function subscriptionSummary(sid) {
  var name = uci.get('purewrt', sid, 'name') || sid;
  var ent = expiryByName[name];
  return [
    sectionTitle(sid),
    uci.get('purewrt', sid, 'mode') || 'auto',
    uci.get('purewrt', sid, 'preset_if_no_rules') || 'minimal',
    expiryCellFor(ent),
    quotaCellFor(ent),
    uci.get('purewrt', sid, 'auto_apply') === '1' ? _('Yes') : _('No')
  ];
}

return view.extend({
  load: function() {
    return Promise.all([
      uci.load('purewrt'),
      callSubscriptionExpiry().catch(function() { return []; }),
      callConfigState().catch(function() { return null; })
    ]).then(function(r) {
      // rpcd now wraps subscription_expiry as {"entries": [...]} so ubus
      // accepts it; the Array fallback covers older shims and the empty
      // {} that LuCI's rpc layer returns when a call silently fails.
      var raw = r[1];
      var entries = Array.isArray(raw) ? raw : (raw && Array.isArray(raw.entries) ? raw.entries : []);
      return { expiry: entries, state: r[2] };
    });
  },

  render: function(data) {
    var m = new form.Map('purewrt', _('PureWRT Proxy Subscriptions'));
    var expiry = Array.isArray(data && data.expiry) ? data.expiry : [];
    var state = data && data.state;
    expiryByName = {};
    expiry.forEach(function(e) { expiryByName[e.name] = e; });

    var st = m.section(form.NamedSection, 'settings', 'main', _('Update transport'));
    var updateViaProxy = st.option(form.Flag, 'update_via_proxy', _('Update via proxy'));
    updateViaProxy.default = '0';
    updateViaProxy.rmempty = false;
    var updateProxy = st.option(form.Value, 'update_proxy_url', _('Update proxy URL'));
    updateProxy.default = 'http://127.0.0.1:7890';
    updateProxy.rmempty = false;
    updateProxy.retain = true;
    updateProxy.depends('update_via_proxy', '1');

    var autoUpdate = st.option(form.Flag, 'auto_update_enabled', _('Automatic provider updates'));
    autoUpdate.default = '1';
    autoUpdate.rmempty = false;
    var cron = st.option(form.Value, 'auto_update_cron', _('Update cron schedule'));
    cron.default = '17 */6 * * *';
    cron.rmempty = false;
    cron.retain = true;
    cron.depends('auto_update_enabled', '1');
    var reloadAfterUpdate = st.option(form.Flag, 'reload_after_update', _('Apply only when downloads changed'));
    reloadAfterUpdate.default = '1';
    reloadAfterUpdate.rmempty = false;
    reloadAfterUpdate.retain = true;
    reloadAfterUpdate.depends('auto_update_enabled', '1');

    var s = m.section(form.TypedSection, 'subscription', _('Subscriptions'));
    // Inline-add row is intentionally removed: the Setup Wizard owns the
    // "add subscription" flow now (it includes the preview step + initial
    // import which the inline add can't replicate). Delete/edit still work.
    s.addremove = false;
    s.anonymous = false;
    s.sectiontitle = sectionTitle;

    s.option(form.Flag, 'enabled', _('Enabled'));
    s.option(form.Value, 'name', _('Name'));
    s.option(form.Value, 'url', _('URL'));

    var mode = s.option(form.ListValue, 'mode', _('Import mode'));
    mode.value('auto', _('Auto'));
    mode.value('proxy_only', _('Proxy nodes only'));
    mode.value('rules_only', _('Rules only'));
    mode.value('advanced', _('Advanced manual'));

    var preset = s.option(form.ListValue, 'preset_if_no_rules', _('Preset if no rules'));
    preset.value('minimal', _('Minimal'));
    preset.value('balanced', _('Balanced'));
    preset.value('manual', _('Advanced manual'));
    preset.value('import', _('Import rules from another URL'));

    var lowRules = s.option(form.Flag, 'import_rules_on_low_resource', _('Import rules on low-resource routers'));
    lowRules.description = _('Advanced override. By default low-resource routers import only proxy nodes from subscriptions and skip subscription rule-providers/rules.');
    lowRules.default = '0';
    lowRules.rmempty = false;
    lowRules.retain = true;

    var interval = s.option(form.Value, 'interval', _('Update interval'));
    interval.datatype = 'uinteger';
    s.option(form.Flag, 'auto_apply', _('Auto apply'));

    var userAgent = s.option(form.Value, 'user_agent', _('User-Agent override'));
    userAgent.default = 'mihomo-purewrt';
    s.option(form.DynamicList, 'header', _('Extra HTTP header'));
    var mirror = s.option(form.DynamicList, 'mirror', _('Mirror URLs'));
    mirror.description = _('Alternate URLs tried after the primary fails. Each retry round cycles through primary + mirrors in order before backing off.');
    var pin = s.option(form.Value, 'pin_sha256', _('TLS pin (SPKI SHA-256)'));
    pin.placeholder = 'sha256/<64 hex chars>,sha256/...';
    pin.description = _('Comma-separated SubjectPublicKeyInfo SHA-256 hashes. The handshake fails unless one matches a cert in the peer chain. Defeats panel MITM.');
    var supHWID = s.option(form.Flag, 'suppress_hwid', _('Suppress HWID fingerprint'));
    supHWID.default = '0';
    supHWID.description = _('Disable router-derived HWID and device-name injection (URL query + HTTP headers) for this subscription. Use when the panel operator isn\'t fully trusted, or to keep downloads indistinguishable across devices.');

    return m.render().then(function(root) {
      // Stack banners top-down: VPN reminder + expiry first (most urgent),
      // then config-state. The Add-via-wizard CTA goes ABOVE all banners
      // so it remains visible regardless of how many banners are stacked.
      var cb = configBanner(state);
      if (cb) {
        if (root && root.firstChild) root.insertBefore(cb, root.firstChild);
        else root.appendChild(cb);
      }
      var banner = expiryBanner(expiry);
      if (banner) {
        if (root && root.firstChild) root.insertBefore(banner, root.firstChild);
        else root.appendChild(banner);
      }
      if (uci.get('purewrt', 'settings', 'wizard_vpn_pending') === '1') {
        var vpnBanner = E('div', { 'class': 'purewrt-banner purewrt-banner-warn' }, [
          E('strong', {}, _('VPN routing pending: ')),
          _('the wizard noted you plan to configure a VPN. '),
          E('a', { 'href': window.location.pathname.replace(/\/subscriptions\/?$/, '/vpn'), 'style': 'color:white;text-decoration:underline' }, _('Open VPN Routing'))
        ]);
        if (root && root.firstChild) root.insertBefore(vpnBanner, root.firstChild);
        else root.appendChild(vpnBanner);
      }
      var wizardCta = E('div', { 'style': 'margin:0 0 1em' }, [
        E('button', {
          'class': 'btn cbi-button cbi-button-action',
          'click': function(ev) {
            ev.preventDefault();
            var base = window.location.pathname.replace(/\/subscriptions\/?$/, '/wizard');
            window.location = base + '?step=2';
          }
        }, [ _('+ Add subscription via wizard') ])
      ]);
      if (root && root.firstChild) root.insertBefore(wizardCta, root.firstChild);
      else root.appendChild(wizardCta);
      return tableSection.render(root, {
        // Row layout, 9 grid columns: spacer, Name, Mode, Preset, Expires,
        // Quota, Auto-apply (from summaryOf), Enable (from showEnable),
        // Actions. The Quota column is wider to fit "13.2 GiB / 100 GiB
        // (13%)". The Auto-apply cell used to silently overflow because
        // the columns/headers arrays only declared 8 slots while
        // subscriptionSummary returned 6 cells — including Auto-apply —
        // which combined with showEnable (+1) and the actions SPAN (+1)
        // gave 9 children. Result: the actions SPAN wrapped to an
        // implicit second grid row and rendered at x=4 outside the
        // content card. Adding the missing column matches the children.
        columns: '0 1.5fr 0.8fr 0.8fr 0.8fr 1.4fr 0.8fr 0.8fr 18rem',
        headers: [ '', _('Name'), _('Mode'), _('Preset'), _('Expires'), _('Quota'), _('Auto-apply'), _('Enable'), '' ],
        showEnable: true,
        titleOf: sectionTitle,
        summaryOf: subscriptionSummary,
        // Save chains through update + reload so adding/editing a subscription
        // doesn't require the user to manually click Update Providers and
        // then Apply on the Diagnostics page. Uses the async update helper
        // because cold subscription downloads can exceed ubus's 30s call
        // timeout — start the job, poll status until done, then reload.
        save: function() {
          return saveChain.run(m, [
            { fn: function() { return updateAsync.run(); }, label: _('Provider update') },
            { fn: callReload, label: _('Apply') },
          ], {
            onSaving: _('Saved. Updating providers in background — this may take a minute on first run.'),
            onDone:   _('Subscription saved, providers refreshed, PureWRT applied.'),
          });
        },
        filterNode: function(node) { return node.getAttribute('data-section-id') !== 'settings'; },
        actions: [
          { label: _('Update'), style: 'apply', onclick: function() { return updateSubscriptions(); } },
          { label: _('Edit'), kind: 'edit' },
          { label: _('Delete'), kind: 'delete', style: 'remove' }
        ]
      });
    });
  }
});
