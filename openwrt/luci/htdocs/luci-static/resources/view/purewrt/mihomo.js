'use strict';
'require view';
'require rpc';
'require ui';
'require uci';

// PureWRT Mihomo tab — one focused place for everything mihomo:
//   - runtime status (running / version / uptime / connections)
//   - apk update-available hints for purewrt + mihomo-alpha + zapret
//   - real binary install from GitHub releases (alpha or stable channel)
//   - generated mihomo.yaml preview
//   - user mixin editor with deep-merge into the generated base
//
// Most rpcd methods are stateless GETs that fall through to a cached
// CLI invocation. The one async path is mihomo_install_release_start /
// _status — that runs a binary download + service restart in the bg.

var callStatus              = rpc.declare({ object: 'purewrt', method: 'mihomo_status' });
var callCheckUpdate         = rpc.declare({ object: 'purewrt', method: 'mihomo_check_update_channel', params: [ 'channel' ] });
var callInstallStart        = rpc.declare({ object: 'purewrt', method: 'mihomo_install_release_start', params: [ 'channel' ] });
var callInstallStatus       = rpc.declare({ object: 'purewrt', method: 'mihomo_install_release_status' });
var callRevertPackage       = rpc.declare({ object: 'purewrt', method: 'mihomo_revert_package' });
var callAutoUpdate          = rpc.declare({ object: 'purewrt', method: 'mihomo_auto_update' });
var callMixinGet            = rpc.declare({ object: 'purewrt', method: 'mihomo_mixin_get' });
var callMixinSet            = rpc.declare({ object: 'purewrt', method: 'mihomo_mixin_set', params: [ 'body' ] });
var callMixinPreview        = rpc.declare({ object: 'purewrt', method: 'mihomo_mixin_preview', params: [ 'body' ], expect: { output: '' } });
// expect.updates unwraps the {updates:[...]} envelope that the rpcd
// dispatcher adds. ubus rejects top-level JSON arrays so the response
// has to live inside an object; the LuCI side gets the array back
// transparently via this expect.
var callApkUpdates          = rpc.declare({ object: 'purewrt', method: 'apk_updates_available', params: [ 'force' ], expect: { updates: [] } });
var callMihomoConfig        = rpc.declare({ object: 'purewrt', method: 'mihomo_config', expect: { output: '' } });
var callReload              = rpc.declare({ object: 'purewrt', method: 'reload' });
var callProxyGroups         = rpc.declare({ object: 'purewrt', method: 'proxy_groups', expect: { items: [] } });
var callProxySelect         = rpc.declare({ object: 'purewrt', method: 'proxy_select', params: [ 'group', 'node' ] });
var callProxyDelayTest      = rpc.declare({ object: 'purewrt', method: 'proxy_delay_test', params: [ 'group' ] });

// Inject the same dark monospace pre styling we use on the Logs page —
// the generated-config and mixin-preview blocks share the visual.
var STYLE_ID = 'purewrt-mihomo-style';
function ensureStyles() {
  if (document.getElementById(STYLE_ID)) return;
  var s = document.createElement('style');
  s.id = STYLE_ID;
  s.textContent = [
    '.purewrt-mihomo-yaml {',
    '  max-height: 30em; overflow-y: auto; overflow-x: auto;',
    '  background: #0d1117; color: #c9d1d9;',
    '  padding: .6em .8em; margin: 0;',
    '  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;',
    '  font-size: .82em; line-height: 1.45;',
    '  border-radius: 6px; border: 1px solid #30363d;',
    '  white-space: pre;',
    '}',
    '.purewrt-mixin-textarea {',
    '  width: 100%; min-height: 18em;',
    '  background: #0d1117; color: #c9d1d9;',
    '  padding: .6em .8em;',
    '  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;',
    '  font-size: .82em; line-height: 1.45;',
    '  border-radius: 6px; border: 1px solid #30363d;',
    '}',
    '.purewrt-statgrid { display: grid; grid-template-columns: max-content 1fr; gap: .3em .8em; margin: .2em 0; }',
    '.purewrt-statgrid dt { color: #8b949e; font-weight: normal; }',
    '.purewrt-statgrid dd { margin: 0; font-family: ui-monospace, "SF Mono", Menlo, monospace; }',
    '.purewrt-pill { display: inline-block; padding: .1em .55em; border-radius: 10px; font-size: .8em; }',
    '.purewrt-pill.run { background: #2ea043; color: #fff; }',
    '.purewrt-pill.stop { background: #f85149; color: #fff; }',
    '.purewrt-pill.idle { background: #21262d; color: #8b949e; }',
    '.purewrt-pill.upd { background: #f0b06b; color: #0d1117; }',
    // proxy-group node chips: all members shown, active highlighted
    '.purewrt-mihomo-node-grid { display: flex; flex-wrap: wrap; gap: .4em; margin-top: .35em; }',
    '.purewrt-mihomo-node { display: inline-flex; align-items: center; gap: .4em; padding: .25em .6em; border: 1.5px solid #555; border-radius: 6px; background: rgba(255,255,255,.05); font-family: ui-monospace, Menlo, monospace; font-size: .85em; }',
    '.purewrt-mihomo-node-active { border-color: #2ea043; box-shadow: 0 0 0 1px #2ea043 inset; }',
    '.purewrt-mihomo-node-idle { border-color: #555; opacity: .82; }',
    '.purewrt-mihomo-node-sel { cursor: pointer; }',
    '.purewrt-mihomo-node-sel:hover { border-color: #00a8e8; }',
    '.purewrt-mihomo-node-dead { color: #f85149; border-style: dashed; }',
    ''
  ].join('\n');
  document.head.appendChild(s);
}

function fmtUptime(s) {
  if (!s || s <= 0) return '—';
  var d = Math.floor(s / 86400); s -= d * 86400;
  var h = Math.floor(s / 3600); s -= h * 3600;
  var m = Math.floor(s / 60); s -= m * 60;
  if (d > 0) return d + 'd ' + h + 'h';
  if (h > 0) return h + 'h ' + m + 'm';
  if (m > 0) return m + 'm ' + Math.floor(s) + 's';
  return Math.floor(s) + 's';
}

// dashboardURL builds the metacubexd URL from UCI + the current
// browser-visible host (the IP/hostname the user typed into LuCI is by
// definition reachable from their browser; dashboard_listen is usually
// 0.0.0.0:9090 which isn't directly addressable). Keep in sync with
// general.js's openDashboard — same shape, same hash params.
function dashboardURL() {
  var listen = uci.get('purewrt', 'settings', 'dashboard_listen') || '0.0.0.0:9090';
  var port = '9090';
  if (listen.indexOf(':') >= 0) port = listen.split(':').pop();
  var name = uci.get('purewrt', 'settings', 'dashboard_name') || 'metacubexd';
  var secret = uci.get('purewrt', 'settings', 'secret') || '';
  var host = window.location.hostname || '192.168.1.1';
  var proto = window.location.protocol.replace(':', '') || 'http';
  var params = [
    'hostname=' + encodeURIComponent(host),
    'port=' + encodeURIComponent(port),
    (proto === 'https' ? 'https=1' : 'http=1')
  ];
  if (secret) params.push('secret=' + encodeURIComponent(secret));
  return proto + '://' + host + ':' + port + '/ui/' + encodeURIComponent(name) + '/#/setup?' + params.join('&');
}

function renderStatusSection(status) {
  var pill;
  if (status.running) {
    pill = E('span', { 'class': 'purewrt-pill run' }, _('running'));
  } else {
    pill = E('span', { 'class': 'purewrt-pill stop' }, _('stopped'));
  }
  var rows = [
    [ _('Status'), pill ],
    [ _('Version'), status.version || _('—') ],
    [ _('PID'), status.pid ? String(status.pid) : '—' ],
    [ _('Uptime'), fmtUptime(status.uptime_seconds) ],
    [ _('Active connections'), String(status.connections || 0) ],
    [ _('DNS mode'), status.dns_mode || '—' ],
    [ _('External controller'), status.external_controller || '—' ],
    [ _('Binary'), (status.mihomo_bin || '—') + ' (' + (status.binary_source || 'unknown') + ')' ]
  ];
  var grid = E('dl', { 'class': 'purewrt-statgrid' });
  rows.forEach(function(r) {
    grid.appendChild(E('dt', {}, r[0]));
    grid.appendChild(E('dd', {}, r[1]));
  });

  // Dashboard button row — disabled when dashboard is explicitly off or mihomo
  // is not running (in either case the metacubexd page would fail to
  // connect). Lives in the Status section so the button sits next to
  // the version/connection counters it complements. Unset dashboard_enabled
  // means the backend default (true) applies, so treat absent as on.
  var dashboardEnabled = uci.get('purewrt', 'settings', 'dashboard_enabled') !== '0';
  var dashBtn = E('button', {
    'class': 'btn cbi-button cbi-button-action',
    'style': 'margin-top:.6em'
  }, '🖥 ' + _('Open Dashboard'));
  if (!dashboardEnabled) {
    dashBtn.disabled = true;
    dashBtn.title = _('Dashboard disabled — toggle dashboard_enabled in Settings.');
  } else if (!status.running) {
    dashBtn.disabled = true;
    dashBtn.title = _('Mihomo is not running — start the service before opening the dashboard.');
  } else {
    dashBtn.addEventListener('click', function(ev) {
      ev.preventDefault();
      window.open(dashboardURL(), '_blank', 'noopener');
    });
  }

  var children = [ grid, dashBtn ];
  if (status.error) {
    children.push(E('p', { 'class': 'alert-message warning', 'style': 'margin-top:.5em;padding:.4em .8em' }, status.error));
  }
  return E('div', { 'class': 'cbi-section' }, [
    E('h3', {}, _('Status')),
    E('div', { 'data-role': 'mihomo-status-body' }, children)
  ]);
}

// Per-package update row — one definition reused across the Mihomo /
// General / Zapret views (each filters to its own package). Compact
// grid-style layout (matches the Status section) so a single package's
// info doesn't get a full-fledged table.
function renderPackageUpdate(updates, name) {
  var container = E('div', { 'data-role': 'updates-body' });
  var row = (updates || []).find(function(u) { return u && u.name === name; });
  if (!row) {
    container.appendChild(E('p', { 'class': 'cbi-section-note' }, _('Package %s not found in apk index.').format(name)));
    return container;
  }
  var pill;
  if (!row.installed) {
    pill = E('span', { 'class': 'purewrt-pill idle' }, _('not installed'));
  } else if (row.upgrade_available) {
    pill = E('span', { 'class': 'purewrt-pill upd' }, _('upgrade available'));
  } else {
    pill = E('span', { 'class': 'purewrt-pill run' }, _('current'));
  }
  var rows = [
    [ _('Package'), name ],
    [ _('Installed'), row.installed || '—' ],
    [ _('Available'), row.available || '—' ],
    [ _('Status'), pill ]
  ];
  var grid = E('dl', { 'class': 'purewrt-statgrid' });
  rows.forEach(function(r) {
    grid.appendChild(E('dt', {}, r[0]));
    grid.appendChild(E('dd', {}, r[1]));
  });
  container.appendChild(grid);
  return container;
}

function renderUpgradeSection(checkResult, currentChannel) {
  var channelSel = E('select', { 'class': 'cbi-input-select' });
  ['alpha', 'stable'].forEach(function(ch) {
    var attrs = { 'value': ch };
    if (ch === currentChannel) attrs.selected = 'selected';
    channelSel.appendChild(E('option', attrs, ch));
  });
  var infoOut = E('div', { 'data-role': 'release-info', 'style': 'margin:.5em 0' });
  var progressOut = E('div', { 'data-role': 'install-progress', 'style': 'margin-top:.5em' });

  function renderInfo(info) {
    infoOut.innerHTML = '';
    if (!info) return;
    if (info.error) {
      infoOut.appendChild(E('p', { 'class': 'alert-message warning' }, info.error));
      return;
    }
    var grid = E('dl', { 'class': 'purewrt-statgrid' });
    [
      [ _('Latest tag'), info.Version || info.version || '—' ],
      [ _('Asset'), info.AssetName || info.asset_name || '—' ],
      [ _('Asset size'), info.Size ? (Math.round(info.Size / 1024 / 1024 * 10) / 10) + ' MB' : '—' ],
      [ _('Published'), info.PublishedAt || info.published_at || '—' ],
      [ _('Currently installed'), info.CurrentVersion || info.current_version || _('unknown') ],
    ].forEach(function(r) {
      grid.appendChild(E('dt', {}, r[0]));
      grid.appendChild(E('dd', {}, r[1]));
    });
    infoOut.appendChild(grid);
  }
  renderInfo(checkResult);

  var refreshBtn = E('button', { 'class': 'btn cbi-button cbi-button-action' }, '↻ ' + _('Check selected channel'));
  refreshBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    refreshBtn.disabled = true;
    callCheckUpdate(channelSel.value).then(function(r) {
      renderInfo(r);
    }, function(err) {
      renderInfo({ error: String(err) });
    }).finally(function() { refreshBtn.disabled = false; });
  });

  var installBtn = E('button', { 'class': 'btn cbi-button cbi-button-apply' }, '⬇ ' + _('Download and install'));
  installBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    if (!confirm(_('Install the latest %s mihomo binary? PureWRT will download, verify the SHA256, atomically place the binary in <workdir>/mihomo-bin/, update the UCI binary path, and restart the mihomo service.').format(channelSel.value))) return;
    installBtn.disabled = true;
    progressOut.innerHTML = '';
    progressOut.appendChild(E('p', {}, '⏳ ' + _('Starting install of channel %s…').format(channelSel.value)));
    callInstallStart(channelSel.value).then(function() {
      var deadline = Date.now() + 5 * 60 * 1000;
      function poll() {
        if (Date.now() > deadline) {
          progressOut.innerHTML = '';
          progressOut.appendChild(E('p', { 'class': 'alert-message warning' }, _('Timed out waiting for install. Check the rpc log for details.')));
          installBtn.disabled = false;
          return;
        }
        callInstallStatus().then(function(s) {
          if (Number(s && s.running) === 1) {
            progressOut.innerHTML = '';
            progressOut.appendChild(E('p', {}, _('⏳ Install running… (tail %d chars)').format((s.log || '').length)));
            window.setTimeout(poll, 2000);
            return;
          }
          progressOut.innerHTML = '';
          if (s.rc === '0' && s.report) {
            progressOut.appendChild(E('p', { 'class': 'alert-message info' },
              _('✅ Installed %s v%s — service %s').format(s.report.channel, s.report.version,
                s.report.warmed_up ? _('warmed up') : _('starting, refresh status in a few seconds'))));
            window.setTimeout(refreshAll, 1500);
          } else {
            progressOut.appendChild(E('p', { 'class': 'alert-message warning' },
              _('❌ Install failed (rc=%s). Log:').format(s.rc) ));
            progressOut.appendChild(E('pre', { 'class': 'purewrt-mihomo-yaml' }, s.log || ''));
          }
          installBtn.disabled = false;
        });
      }
      window.setTimeout(poll, 500);
    }, function(err) {
      progressOut.innerHTML = '';
      progressOut.appendChild(E('p', { 'class': 'alert-message warning' }, _('Start failed: %s').format(String(err))));
      installBtn.disabled = false;
    });
  });

  var revertBtn = E('button', { 'class': 'btn' }, _('Revert to package binary'));
  revertBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    if (!confirm(_('Revert UCI mihomo_bin to /usr/bin/mihomo and restart the service?'))) return;
    revertBtn.disabled = true;
    callRevertPackage().then(function() {
      ui.addNotification(null, E('p', _('Reverted to the package-installed mihomo binary.')), 'info');
      window.setTimeout(refreshAll, 1500);
    }, function(err) {
      ui.addNotification(null, E('p', _('Revert failed: %s').format(String(err))), 'danger');
    }).finally(function() { revertBtn.disabled = false; });
  });

  // Auto-update row. The cron entry runs `purewrt mihomo-auto-update`
  // on a UCI-driven schedule; both fields edit straight into UCI via
  // the standard purewrt config. Toggling and saving is up to the
  // standard Settings page — we just expose the current state + a
  // fire-now button so users can validate the wiring without waiting
  // for the next cron tick.
  var autoEnabled = uci.get('purewrt', 'settings', 'mihomo_auto_update_enabled') === '1';
  var autoCron    = uci.get('purewrt', 'settings', 'mihomo_auto_update_cron') || '23 4 * * *';
  // Auto-update channel is its own UCI option (mihomo_channel) — distinct
  // from the transient dropdown above which only scopes the manual
  // Check/Install/Revert buttons. Keeping the two independent means
  // poking at the manual upgrade UI doesn't silently retarget the cron job.
  var autoChannel = uci.get('purewrt', 'settings', 'mihomo_channel') || 'alpha';
  var autoChannelSel = E('select', { 'class': 'cbi-input-select' });
  ['alpha', 'stable'].forEach(function(ch) {
    var opts = { 'value': ch };
    if (ch === autoChannel) opts.selected = 'selected';
    autoChannelSel.appendChild(E('option', opts, ch));
  });
  var autoCheckbox = E('input', { 'type': 'checkbox', 'class': 'cbi-input-checkbox', 'id': 'purewrt-mihomo-auto-enable' });
  if (autoEnabled) autoCheckbox.checked = true;
  var autoCronInput = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'style': 'width:14em;font-family:monospace', 'value': autoCron });
  var autoSaveBtn = E('button', { 'class': 'btn cbi-button cbi-button-apply' }, '💾 ' + _('Save schedule'));
  autoSaveBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    autoSaveBtn.disabled = true;
    uci.set('purewrt', 'settings', 'mihomo_auto_update_enabled', autoCheckbox.checked ? '1' : '0');
    uci.set('purewrt', 'settings', 'mihomo_auto_update_cron', autoCronInput.value || '23 4 * * *');
    uci.set('purewrt', 'settings', 'mihomo_channel', autoChannelSel.value);
    uci.save().then(function() {
      return uci.apply();
    }).then(function() {
      // uci.apply() restarts affected services, which triggers our
      // init.d/purewrt's install_cron() and rewrites /etc/crontabs/root.
      ui.addNotification(null, E('p', _('Auto-update schedule saved. Cron entry refreshed.')), 'info');
    }, function(err) {
      ui.addNotification(null, E('p', _('Save failed: %s').format(String(err))), 'danger');
    }).finally(function() { autoSaveBtn.disabled = false; });
  });
  var autoRunBtn = E('button', { 'class': 'btn' }, '▶ ' + _('Run now'));
  autoRunBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    autoRunBtn.disabled = true;
    callAutoUpdate().then(function(r) {
      var msg = r ? (_('Auto-update result: %s').format(r.action || '?')
              + (r.latest_version ? ' (' + (r.current_version || '?') + ' → ' + r.latest_version + ')' : '')
              + (r.error ? ' — ' + r.error : ''))
            : _('Auto-update returned no result');
      ui.addNotification(null, E('p', msg), r && r.error ? 'warning' : 'info');
      window.setTimeout(refreshAll, 1500);
    }, function(err) {
      ui.addNotification(null, E('p', _('Auto-update failed: %s').format(String(err))), 'danger');
    }).finally(function() { autoRunBtn.disabled = false; });
  });

  return E('div', { 'class': 'cbi-section' }, [
    E('h3', {}, _('Upgrade mihomo from GitHub')),
    E('p', { 'class': 'cbi-section-note' }, _(
      'Downloads the latest release from github.com/MetaCubeX/mihomo, verifies SHA256, installs to <workdir>/mihomo-bin/ (apk-managed /usr/bin/mihomo is never overwritten), and restarts the service. If the new binary fails to respond on /version within 10s the install auto-reverts to the package binary so a bad release doesn\'t take the proxy down.'
    )),
    E('div', { 'style': 'display:flex;align-items:center;gap:.5em;flex-wrap:wrap' }, [
      E('label', {}, _('Channel:')), channelSel, refreshBtn, installBtn, revertBtn
    ]),
    infoOut,
    progressOut,
    E('div', { 'class': 'cbi-section-node', 'style': 'border-top:1px solid #30363d;margin-top:.8em;padding-top:.6em' }, [
      E('strong', {}, _('Auto-update')),
      E('p', { 'class': 'cbi-section-note' }, _(
        'Runs `purewrt mihomo-auto-update` on a cron schedule. Compares the asset-derived version (alpha channel uses the commit hash from the asset filename, not the always-"Prerelease-Alpha" tag) and installs only when something changed. Bad releases auto-revert to /usr/bin/mihomo.'
      )),
      E('div', { 'style': 'display:flex;align-items:center;gap:.5em;flex-wrap:wrap;margin-top:.3em' }, [
        E('label', { 'for': 'purewrt-mihomo-auto-enable', 'style': 'display:flex;align-items:center;gap:.3em' }, [ autoCheckbox, _('Enabled') ]),
        E('label', {}, _('Channel:')), autoChannelSel,
        E('label', {}, _('Cron:')), autoCronInput,
        autoSaveBtn, autoRunBtn
      ])
    ])
  ]);
}

function renderGeneratedConfigSection(yaml) {
  var pre = E('pre', { 'class': 'purewrt-mihomo-yaml' }, yaml || _('(no generated config yet — run Apply first)'));
  var copyBtn = E('button', { 'class': 'btn', 'style': 'font-size:.85em' }, '⧉ ' + _('copy'));
  copyBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    if (navigator.clipboard) navigator.clipboard.writeText(yaml || '');
    ui.addNotification(null, E('p', _('Copied generated config.')), 'info');
  });
  var refreshBtn = E('button', { 'class': 'btn', 'style': 'font-size:.85em' }, '↻ ' + _('reload'));
  refreshBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    callMihomoConfig().then(function(r) {
      pre.textContent = r || _('(no generated config yet — run Apply first)');
    });
  });
  return E('div', { 'class': 'cbi-section' }, [
    E('h3', {}, _('Generated config')),
    E('div', { 'style': 'display:flex;gap:.4em;margin:.3em 0' }, [ copyBtn, refreshBtn ]),
    pre
  ]);
}

function renderMixinSection(info) {
  var textarea = E('textarea', {
    'class': 'purewrt-mixin-textarea',
    'placeholder': _(
      '# Mixin: deep-merged into generated mihomo.yaml on apply.\n' +
      '# Maps merge recursively, plain arrays replace.\n' +
      '# Prefix a key with `purewrt-` to PREPEND its items to the base array:\n' +
      '#\n' +
      '#   purewrt-proxies:\n' +
      '#     - name: my-extra\n' +
      '#       type: ss\n' +
      '#       server: ...\n' +
      '#\n' +
      '#   purewrt-rules:\n' +
      '#     - "DOMAIN,example.com,DIRECT"\n' +
      '#\n' +
      '# Plain `proxies:` / `rules:` would replace the generated lists entirely.'
    )
  }, info.body || '');
  var saveBtn = E('button', { 'class': 'btn cbi-button cbi-button-apply' }, '💾 ' + _('Save mixin'));
  var previewBtn = E('button', { 'class': 'btn cbi-button cbi-button-action' }, '👁 ' + _('Preview merged result'));
  var enableNote = E('p', { 'class': 'cbi-section-note', 'style': 'margin:.4em 0' },
    info.enabled
      ? _('Mixin is ENABLED — the file is merged on every apply. Disable via UCI option purewrt.settings.mihomo_mixin_enabled.')
      : _('Mixin is DISABLED — set UCI option purewrt.settings.mihomo_mixin_enabled=1 (or via the Settings tab) to make it take effect on apply.'));
  var previewOut = E('div', { 'data-role': 'mixin-preview', 'style': 'margin-top:.5em' });

  saveBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    var body = textarea.value;
    saveBtn.disabled = true;
    callMixinSet(body).then(function(r) {
      if (r && r.ok === false) {
        ui.addNotification(null, E('p', _('Save failed: %s').format(r.error || _('unknown'))), 'danger');
      } else {
        ui.addNotification(null, E('p', _('Mixin saved.')), 'info');
      }
    }, function(err) {
      ui.addNotification(null, E('p', _('Save failed: %s').format(String(err))), 'danger');
    }).finally(function() { saveBtn.disabled = false; });
  });
  previewBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    previewBtn.disabled = true;
    callMixinPreview(textarea.value).then(function(out) {
      previewOut.innerHTML = '';
      previewOut.appendChild(E('h4', {}, _('Merged preview')));
      previewOut.appendChild(E('pre', { 'class': 'purewrt-mihomo-yaml' }, out));
    }, function(err) {
      previewOut.innerHTML = '';
      previewOut.appendChild(E('p', { 'class': 'alert-message warning' }, _('Preview failed: %s').format(String(err))));
    }).finally(function() { previewBtn.disabled = false; });
  });

  return E('div', { 'class': 'cbi-section' }, [
    E('h3', {}, _('Mixin (user overrides)')),
    enableNote,
    textarea,
    E('div', { 'style': 'display:flex;gap:.4em;margin-top:.4em' }, [ saveBtn, previewBtn ]),
    previewOut
  ]);
}

// refreshAll re-pulls status + apk_updates and rewrites the inline
// status block. Called after install / revert so the displayed state
// reflects reality without forcing a page reload.
// renderProxyGroupsSection lists mihomo's proxy groups with a node
// selector each — switch is immediate (in-flight connections drain so
// long-lived flows re-establish through the new node) and survives until
// the next config reload regenerates the groups.
function proxyNodeLabel(mem) {
  if (!mem.alive && mem.delay === 0) return mem.name + ' (' + _('dead') + ')';
  if (mem.delay > 0) return mem.name + ' (' + mem.delay + ' ms)';
  return mem.name;
}

function renderProxyGroupsSection(groups) {
  var body = E('div', { 'data-role': 'proxy-groups-body' });
  var refreshBtn = E('button', { 'class': 'btn', 'style': 'margin-left:.5em' }, _('Refresh'));
  refreshBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    refreshBtn.disabled = true;
    callProxyGroups().then(function(gs) { renderProxyGroupsBody(body, gs || []); })
      .catch(function() {})
      .finally(function() { refreshBtn.disabled = false; });
  });
  var section = E('div', { 'class': 'cbi-section' }, [
    E('div', { 'style': 'display:flex;align-items:center;gap:.5em' }, [
      E('h3', { 'style': 'margin:0' }, _('Proxy groups')), refreshBtn
    ]),
    E('p', { 'class': 'cbi-section-note' }, _(
      'All member nodes are shown. Selector groups let you click a node to switch; url-test / fallback / load-balance pick automatically — the active node is outlined green, the rest gray.'
    )),
    body
  ]);
  renderProxyGroupsBody(body, groups || []);
  return section;
}

// renderProxyGroupsBody (re)renders the groups into `body`. Each group shows
// ALL member nodes as chips: the active node (g.now) gets a green outline, the
// rest gray (dead nodes red/dashed). Selector groups make chips clickable to
// switch; auto groups (url-test/fallback/load-balance) are display-only.
function renderProxyGroupsBody(body, groups) {
  body.innerHTML = '';
  if (!groups.length) {
    body.appendChild(E('em', {}, _('No proxy groups — is mihomo running with imported proxies?')));
    return;
  }
  groups.forEach(function(g) {
    var selectable = g.type === 'Selector';
    var rowStatus = E('span', { 'style': 'margin-left:.6em' });
    var chipByName = {};

    function nodeClass(mem) {
      var c = 'purewrt-mihomo-node ' + (g.now && mem.name === g.now ? 'purewrt-mihomo-node-active' : 'purewrt-mihomo-node-idle');
      if (!mem.alive && mem.delay === 0) c += ' purewrt-mihomo-node-dead';
      if (selectable) c += ' purewrt-mihomo-node-sel';
      return c;
    }

    var grid = E('div', { 'class': 'purewrt-mihomo-node-grid' }, g.members.map(function(mem) {
      var chip = E('span', { 'class': nodeClass(mem), 'title': selectable ? _('click to switch') : '' }, proxyNodeLabel(mem));
      chipByName[mem.name] = chip;
      if (selectable) {
        chip.addEventListener('click', function() {
          rowStatus.textContent = _('switching…');
          callProxySelect(g.name, mem.name).then(function(res) {
            g.now = mem.name;
            g.members.forEach(function(m2) {
              var c2 = chipByName[m2.name];
              if (!c2) return;
              c2.classList.toggle('purewrt-mihomo-node-active', m2.name === g.now);
              c2.classList.toggle('purewrt-mihomo-node-idle', m2.name !== g.now);
            });
            rowStatus.textContent = _('switched') + (res && res.drained ? ' (' + res.drained + ' ' + _('connections drained') + ')' : '');
          }).catch(function(err) { rowStatus.textContent = _('switch failed: ') + err; });
        });
      }
      return chip;
    }));

    var testBtn = E('button', { 'class': 'btn', 'style': 'margin-left:.5em' }, _('Test latency'));
    testBtn.addEventListener('click', function(ev) {
      ev.preventDefault();
      testBtn.disabled = true;
      rowStatus.textContent = _('testing…');
      callProxyDelayTest(g.name).then(function(delays) {
        delays = delays || {};
        g.members.forEach(function(mem) {
          var d = delays[mem.name];
          mem.delay = d || 0;
          mem.alive = !!d;
          var chip = chipByName[mem.name];
          if (!chip) return;
          chip.textContent = d ? mem.name + ' (' + d + ' ms)' : mem.name + ' (' + _('dead') + ')';
          chip.classList.toggle('purewrt-mihomo-node-dead', !d);
        });
        rowStatus.textContent = _('latency updated');
        testBtn.disabled = false;
      }).catch(function(err) { rowStatus.textContent = _('test failed: ') + err; testBtn.disabled = false; });
    });

    var hint = E('span', { 'class': 'cbi-section-note', 'style': 'margin-left:.5em' },
      selectable ? _('click a node to switch') : _('auto — active node highlighted'));
    body.appendChild(E('div', { 'style': 'margin:.6em 0' }, [
      E('div', {}, [
        E('strong', {}, g.name), ' ',
        E('span', { 'class': 'cbi-section-note' }, '(' + g.type + (g.section ? ', ' + _('section') + ' ' + g.section : '') + ')'),
        hint
      ]),
      grid,
      E('div', { 'style': 'margin-top:.3em' }, [ testBtn, rowStatus ])
    ]));
  });
}

var doms = {};
function refreshAll() {
  Promise.all([callStatus(), callApkUpdates('0')]).then(function(r) {
    var statusBody = doms.statusContainer && doms.statusContainer.querySelector('[data-role="mihomo-status-body"]');
    if (statusBody && r[0]) {
      var newDom = renderStatusSection(r[0]);
      doms.statusContainer.replaceWith(newDom);
      doms.statusContainer = newDom;
    }
    var updatesBody = doms.updatesContainer && doms.updatesContainer.querySelector('[data-role="updates-body"]');
    if (updatesBody && r[1]) {
      updatesBody.innerHTML = '';
      updatesBody.appendChild(renderPackageUpdate(r[1], 'mihomo-alpha'));
    }
  });
}

return view.extend({
  load: function() {
    ensureStyles();
    return Promise.all([
      callStatus().catch(function() { return null; }),
      callApkUpdates('0').catch(function() { return null; }),
      callCheckUpdate('').catch(function(e) { return { error: String(e) }; }),
      callMihomoConfig().catch(function() { return ''; }),
      callMixinGet().catch(function() { return { enabled: false, body: '', exists: false }; }),
      uci.load('purewrt').catch(function() { return null; }),
      callProxyGroups().catch(function() { return []; })
    ]);
  },
  render: function(data) {
    var status         = data[0] || { running: false };
    var apkUpdates     = data[1] || [];
    var initialRelease = data[2] || null;
    var generatedYAML  = data[3] || '';
    var mixinInfo      = data[4] || { enabled: false, body: '' };
    var proxyGroups    = data[6] || [];

    var statusSection = renderStatusSection(status);
    var updatesSection = E('div', { 'class': 'cbi-section' }, [
      E('h3', {}, _('Package version (mihomo-alpha)')),
      E('p', { 'class': 'cbi-section-note' }, _(
        'Installed vs upgradable mihomo-alpha apk package. The Software page (System → Software) is where you actually apply upgrades. The GitHub install path below is independent of apk and lands the binary under <workdir>/mihomo-bin/.'
      )),
      renderPackageUpdate(apkUpdates, 'mihomo-alpha'),
      E('button', {
        'class': 'btn',
        'style': 'margin-top:.5em',
        'click': function(ev) {
          ev.preventDefault();
          ev.target.disabled = true;
          callApkUpdates('1').then(function(r) {
            var body = updatesSection.querySelector('[data-role="updates-body"]');
            if (body) {
              body.innerHTML = '';
              body.appendChild(renderPackageUpdate(r, 'mihomo-alpha'));
            }
            ev.target.disabled = false;
          });
        }
      }, '↻ ' + _('Refresh repo index'))
    ]);
    // Determine current channel from the initial check result (defaults to alpha).
    var currentChannel = (initialRelease && initialRelease.Channel) || 'alpha';

    doms.statusContainer  = statusSection;
    doms.updatesContainer = updatesSection;

    return E('div', { 'class': 'cbi-map' }, [
      E('h2', _('PureWRT Mihomo')),
      E('p', { 'class': 'cbi-section-note' }, _(
        'Everything mihomo lives here: runtime status, GitHub binary install, generated config preview, and an editable mixin file that gets deep-merged on apply.'
      )),
      statusSection,
      renderProxyGroupsSection(proxyGroups),
      updatesSection,
      renderUpgradeSection(initialRelease, currentChannel),
      renderGeneratedConfigSection(generatedYAML),
      renderMixinSection(mixinInfo)
    ]);
  },
  handleSave: null, handleSaveApply: null, handleReset: null
});
