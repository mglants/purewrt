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
'require purewrt.naming as naming';

var callUpdateProxyProvider = rpc.declare({ object: 'purewrt', method: 'update_proxy_provider', params: [ 'name' ] });
var callReload = rpc.declare({ object: 'purewrt', method: 'reload' });

function sectionTitle(sid) {
  return naming.displayName(sid, 'proxy_provider') || _('New proxy provider');
}

function updateProxyProvider(sid) {
  var name = sectionTitle(sid);
  return callUpdateProxyProvider(name).then(function() {
    ui.addNotification(null, E('p', _('Proxy provider updated and mihomo restarted')), 'info');
  });
}

function providerSummary(sid) {
  var path = uci.get('purewrt', sid, 'path') || uci.get('purewrt', sid, 'url') || '-';
  return [
    sectionTitle(sid),
    uci.get('purewrt', sid, 'type') || '-',
    path,
    uci.get('purewrt', sid, 'health_check') === '1' ? _('Yes') : _('No')
  ];
}

return view.extend({
  load: function() {
    return uci.load('purewrt');
  },

  render: function() {
    var m = new form.Map('purewrt', _('PureWRT Proxy Providers'));
    var s = m.section(form.TypedSection, 'proxy_provider', _('Proxy providers'));
    s.addremove = true;
    // Named sections: the id is the type-prefixed name (pp_<name>); the Go
    // parser strips the prefix. One name, no separate field to drift.
    s.anonymous = false;
    s.sectiontitle = sectionTitle;
    naming.installPrefixedAdd(s, 'proxy_provider', function(name) {
      if (name === 'default')
        return _('"default" is reserved by mihomo; pick another name');
      return null;
    });

    var enabled = s.option(form.Flag, 'enabled', _('Enabled'));
    enabled.default = '1'; // Go side treats an absent option as enabled

    var type = s.option(form.ListValue, 'type', _('Type'));
    type.value('http', _('HTTP'));
    type.value('file', _('File'));

    var ppURL = s.option(form.Value, 'url', _('URL'));
    ppURL.validate = fmt.validateHTTPURL;
    s.option(form.Value, 'path', _('Local path'));

    var interval = s.option(form.Value, 'interval', _('Update interval'));
    interval.datatype = 'uinteger';

    s.option(form.Flag, 'health_check', _('Health check'));
    s.option(form.Value, 'health_check_url', _('Health check URL'));
    var hci = s.option(form.Value, 'health_check_interval', _('Health check interval'));
    hci.datatype = 'uinteger';

    s.option(form.Value, 'mwan3_policy', _('mwan3 policy'));
    s.option(form.Value, 'user_agent', _('User-Agent override'));
    s.option(form.DynamicList, 'header', _('Extra HTTP header'));
    var mirror = s.option(form.DynamicList, 'mirror', _('Mirror URLs'));
    mirror.description = _('Alternate URLs tried after the primary fails. Each retry round cycles through primary + mirrors in order before backing off.');
    var pin = s.option(form.Value, 'pin_sha256', _('TLS pin (SPKI SHA-256)'));
    pin.placeholder = 'sha256/<64 hex chars>,sha256/...';
    pin.description = _('Comma-separated SubjectPublicKeyInfo SHA-256 hashes. The handshake fails unless one matches a cert in the peer chain.');
    var supHWID = s.option(form.Flag, 'suppress_hwid', _('Suppress HWID fingerprint'));
    supHWID.default = '0';
    supHWID.description = _('Disable router-derived HWID/device-name injection (URL + headers) for this provider.');

    var update = s.option(form.Button, '_update', _('Update this provider'));
    update.inputstyle = 'apply';
    update.onclick = function(ev, sectionId) {
      return updateProxyProvider(sectionId);
    };

    return m.render().then(function(root) {
      return tableSection.render(root, {
        columns: '0 1.5fr 1fr 2.5fr 1fr 1fr 18rem',
        headers: [ '', _('Name'), _('Type'), _('Source'), _('Health'), _('Enable'), '' ],
        showEnable: true,
        titleOf: sectionTitle,
        summaryOf: providerSummary,
        // Save-chains through update + reload — proxy providers have a URL
        // like subscriptions do, so adding/editing one requires a download
        // (`update`) and a regen (`reload`) before the change takes effect.
        // Uses the async update helper so cold-cache downloads that exceed
        // ubus's 30s call timeout still complete cleanly.
        save: function() {
          return saveChain.run(m, [
            { fn: function() { return updateAsync.run(); }, label: _('Provider update') },
            { fn: callReload, label: _('Apply') },
          ], {
            onSaving: _('Saved. Updating providers in background — this may take a minute on first run.'),
            onDone:   _('Proxy provider saved and applied.'),
          });
        },
        actions: [
          { label: _('Update'), style: 'apply', onclick: function(sid) { return updateProxyProvider(sid); } },
          { label: _('Edit'), kind: 'edit' },
          { label: _('Delete'), kind: 'delete', style: 'remove' }
        ]
      });
    });
  }
});
