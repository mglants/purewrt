'use strict';
'require view';
'require form';
'require rpc';
'require ui';
'require uci';
'require purewrt.styles';
'require purewrt.format as fmt';

// Global PureWRT settings — everything the Setup Wizard doesn't cover. Each
// card maps to one form.NamedSection but they all write to the same UCI
// section (purewrt.settings of type 'main'), so the page reads + saves like
// a single form. Grouped for scannability since the underlying record holds
// ~60 fields. Settings owned by the wizard (subscription, resource_profile,
// ipv6, bootstrap_doh_enabled/resolvers, auto_update_*, dashboard_enabled,
// wizard_vpn_pending) are deliberately omitted here — the wizard is their
// canonical entry point.

var callReload = rpc.declare({ object: 'purewrt', method: 'reload' });
var callConfigExport = rpc.declare({ object: 'purewrt', method: 'config_export' });
var callConfigImport = rpc.declare({ object: 'purewrt', method: 'config_import', params: [ 'body' ] });

// backupRestoreCard renders the export/import block appended below the
// settings form. Export downloads the redacted UCI dump as a file; import
// validates server-side (purewrt import-config) and reports warnings —
// applying remains an explicit follow-up step.
function backupRestoreCard() {
  var importArea = E('textarea', {
    'class': 'cbi-input-textarea',
    'style': 'width:100%;min-height:10em;font-family:monospace',
    'placeholder': _('Paste an exported PureWRT config here…')
  });
  var status = E('div', { 'style': 'margin-top:.5em' });
  var exportBtn = E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': function(ev) {
    ev.preventDefault();
    callConfigExport().then(function(res) {
      var text = (res && res.config) || '';
      if (!text) { ui.addNotification(null, E('p', _('Export returned no data')), 'error'); return; }
      var blob = new Blob([text], { type: 'text/plain' });
      var a = E('a', { 'href': URL.createObjectURL(blob), 'download': 'purewrt-config-export.txt' });
      document.body.appendChild(a);
      a.click();
      a.remove();
    }).catch(function(err) {
      ui.addNotification(null, E('p', _('Export failed: ') + err), 'error');
    });
  } }, _('Export config'));
  var importBtn = E('button', { 'class': 'btn cbi-button cbi-button-negative', 'style': 'margin-left:.5em', 'click': function(ev) {
    ev.preventDefault();
    var body = importArea.value || '';
    if (!body.trim()) { ui.addNotification(null, E('p', _('Nothing to import')), 'error'); return; }
    if (!confirm(_('Replace /etc/config/purewrt with the pasted config? A .purewrt.bak backup is kept; routing is untouched until the next apply.'))) return;
    while (status.firstChild) status.removeChild(status.firstChild);
    callConfigImport(body).then(function(res) {
      if (res && res.ok) {
        var children = [ E('strong', {}, _('Imported. ')),
          _('Config replaced (backup: %s). Run a reload/apply to activate.').format(res.backup || '-') ];
        (res.warnings || []).forEach(function(w) {
          children.push(E('div', { 'style': 'color:#f0ad4e' }, '⚠ ' + w));
        });
        status.appendChild(E('div', {}, children));
      } else {
        status.appendChild(E('div', { 'style': 'color:#d9534f' }, _('Import failed: ') + ((res && res.error) || 'unknown error')));
      }
    }).catch(function(err) {
      status.appendChild(E('div', { 'style': 'color:#d9534f' }, _('Import failed: ') + err));
    });
  } }, _('Validate & import'));
  return E('div', { 'class': 'cbi-section' }, [
    E('h3', {}, _('Backup / Restore')),
    E('div', { 'class': 'cbi-section-descr' },
      _('Export downloads the whole PureWRT config as portable UCI text with secrets redacted (controller secret, subscription tokens, HWIDs) — re-enter those after restoring on another router. Import validates first and never applies automatically.')),
    E('div', {}, [ exportBtn, importBtn ]),
    importArea,
    status
  ]);
}

function addRow(section, kind, name, title, opts) {
  var o = section.option(kind, name, title);
  opts = opts || {};
  if (opts.placeholder !== undefined) o.placeholder = opts.placeholder;
  if (opts.description) o.description = opts.description;
  if (opts.datatype) o.datatype = opts.datatype;
  if (opts.validate) o.validate = opts.validate;
  if (opts.default !== undefined) o.default = opts.default;
  if (opts.password) o.password = true;
  if (opts.rmempty !== undefined) o.rmempty = opts.rmempty;
  if (opts.values) {
    opts.values.forEach(function(v) {
      if (Array.isArray(v)) o.value(v[0], v[1]);
      else o.value(v, v);
    });
  }
  return o;
}

// fw4 zone names for the LAN-sources picker, WAN-forwarding ones first
// (suggested defaults), each labelled. Read from the live firewall config.
function firewallZoneValues() {
  var fwdWan = {};
  uci.sections('firewall', 'forwarding', function(f) {
    if (f.dest === 'wan') fwdWan[f.src] = true;
  });
  var names = [];
  uci.sections('firewall', 'zone', function(z) {
    var n = z.name || z['.name'];
    if (n && names.indexOf(n) < 0) names.push(n);
  });
  names.sort(function(a, b) {
    return (fwdWan[b] ? 1 : 0) - (fwdWan[a] ? 1 : 0) || a.localeCompare(b);
  });
  return names.map(function(n) { return [n, n + (fwdWan[n] ? ' (→ wan)' : '')]; });
}

return view.extend({
  load: function() {
    // Needed to enumerate fw4 zones for the LAN-sources picker.
    return uci.load('firewall').catch(function() { return null; });
  },
  render: function() {
    var zoneValues = firewallZoneValues();
    var m = new form.Map('purewrt', _('PureWRT Settings'),
      _('Advanced settings. The Setup Wizard handles the common ones (subscription, IPv6, resource profile, auto-update, dashboard on/off, bootstrap DNS) — this page exposes everything else. Save & Apply triggers a PureWRT reload so changes take effect immediately.'));

    // ---- Apply behavior ----
    var apply = m.section(form.NamedSection, 'settings', 'main', _('Apply behavior'),
      _('How "purewrt apply" stages and recovers from failures.'));
    apply.anonymous = true;
    addRow(apply, form.Flag, 'auto_reload', _('Auto-reload'), { default: '1',
      description: _('After UCI is saved via this UI, automatically apply the new config. Disable to require an explicit `purewrt apply` from the CLI.') });
    addRow(apply, form.Flag, 'safe_apply', _('Safe apply'), { default: '1',
      description: _('Validate the staged config (mihomo -t, nft -c) before swapping the live state in. Disabling skips the dry-run — faster but you can break routing if generation produces a bad nft file.') });
    addRow(apply, form.Flag, 'rollback_on_fail', _('Rollback on failure'), { default: '1',
      description: _('If apply fails mid-flight (nft -f rejects, mihomo doesn\'t come up), restore the previous on-disk state.') });
    addRow(apply, form.Value, 'backup_retention', _('Backup retention'), { datatype: 'uinteger', default: '3',
      description: _('How many pre-apply backups to keep on disk. 0 disables backups entirely.') });
    addRow(apply, form.Value, 'apply_backup_max_bytes', _('Backup max size (bytes)'), { datatype: 'uinteger', default: '0',
      description: _('Skip backup snapshotting for files larger than this. 0 = no limit.') });

    // ---- Logging + telemetry ----
    var logs = m.section(form.NamedSection, 'settings', 'main', _('Logging & telemetry'));
    logs.anonymous = true;
    addRow(logs, form.ListValue, 'log_level', _('Log level'), {
      values: ['debug', 'info', 'warn', 'error'], default: 'warn',
      description: _('Min severity for syslog. `info` exposes the apply-step trace useful for debugging; `warn` (default) is the production noise floor.') });
    addRow(logs, form.ListValue, 'log_format', _('Log format'), {
      values: [['text', 'text (human)'], ['json', 'JSON (machine-ingestion)']], default: 'text' });
    addRow(logs, form.Flag, 'metrics_enabled', _('purewrt-api /metrics'), { default: '0',
      description: _('Expose Prometheus metrics on purewrt-api. Used by the Statistics page\'s live traffic + by external scrapers.') });
    addRow(logs, form.DynamicList, 'api_listen', _('purewrt-api listen addresses'), {
      placeholder: '0.0.0.0:8787',
      description: _('host:port addresses the API daemon binds. Empty = 0.0.0.0:8787 (all interfaces; the firewall still blocks WAN input). Add 127.0.0.1:8787 for loopback-only, or a specific interface IP to pick interfaces. Restart purewrt-api after changing.') });

    // ---- Connectivity monitoring (net-check) ----
    var netcheck = m.section(form.NamedSection, 'settings', 'main', _('Connectivity monitoring'),
      _('Schedule `purewrt net-check` to periodically probe real proxy throughput and record metrics. Run it on demand from the Diagnostics page.'));
    netcheck.anonymous = true;
    addRow(netcheck, form.Flag, 'net_check_enabled', _('Scheduled net-check'), { default: '0',
      description: _('Run net-check on a cron schedule. It transfers real bytes through the proxy, so it consumes subscription quota — off by default.') });
    var ncCron = addRow(netcheck, form.Value, 'net_check_cron', _('Schedule (cron)'), { placeholder: '*/30 * * * *',
      validate: fmt.validateCron,
      description: _('Cron expression. Empty = manual only (run from Diagnostics).') });
    ncCron.depends('net_check_enabled', '1');
    var ncBytes = addRow(netcheck, form.Value, 'net_check_bytes', _('Probe size (bytes)'), { datatype: 'uinteger', default: '2097152',
      description: _('Per-run download/upload size for the scheduled probe. Smaller bounds quota; ~2 MiB default. Each tick moves ~this down + half up.') });
    ncBytes.depends('net_check_enabled', '1');

    // ---- Mihomo runtime ----
    var mihomo = m.section(form.NamedSection, 'settings', 'main', _('Mihomo runtime'),
      _('Where PureWRT pulls mihomo from + which release channel to track.'));
    mihomo.anonymous = true;
    addRow(mihomo, form.Value, 'mihomo_bin', _('Mihomo binary path'), { placeholder: '/usr/bin/mihomo',
      description: _('Empty uses the package-installed binary. Set automatically by "Install release" on the Mihomo page.') });
    addRow(mihomo, form.Value, 'mihomo_config', _('Mihomo config path'), { placeholder: '/etc/purewrt/generated/mihomo.yaml',
      description: _('Where the generated mihomo config is written. Change only for non-standard layouts.') });
    addRow(mihomo, form.Flag, 'mihomo_allow_lan', _('Expose proxy to LAN (allow-lan)'), { default: '0',
      description: _('Off (default) binds mihomo\'s mixed-port (HTTP/SOCKS, 7890) to 127.0.0.1 only, so a LAN scan can\'t detect or use the router as an open proxy. The transparent (TPROXY) routing for your sections is unaffected. Turn on only if you want LAN clients to point at the router as an explicit proxy. (The dashboard/controller port and TPROXY ports are separate.)') });
    addRow(mihomo, form.ListValue, 'mihomo_channel', _('Update channel'), {
      values: [['alpha', 'alpha (Prerelease)'], ['stable', 'stable (Release)']], default: 'alpha',
      description: _('Which MetaCubeX release stream "Install release" and auto-update track. Alpha ships fixes fast but is a prerelease build; pick stable for conservative routers. Auto-update stays off unless you enable it.') });
    addRow(mihomo, form.Value, 'mihomo_release_api', _('Release API URL'),
      { placeholder: 'https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/Prerelease-Alpha',
        validate: fmt.validateHTTPURL });
    addRow(mihomo, form.Flag, 'mihomo_geodata_enabled', _('Mihomo geodata'), { default: '0',
      description: _('Enable mihomo\'s built-in geodata + auto-update. PureWRT\'s rule providers cover most use cases — leave off unless you write GEOIP/GEOSITE rules manually.') });

    // ---- Dashboard (advanced) ----
    var dash = m.section(form.NamedSection, 'settings', 'main', _('Mihomo dashboard (advanced)'),
      _('Toggle the dashboard + tune its bind address and UI bundle. The wizard also sets dashboard_enabled in its Updates & Dashboard step; this is the same option exposed here for post-wizard tweaks.'));
    dash.anonymous = true;
    addRow(dash, form.Flag, 'dashboard_enabled', _('Enable dashboard'), { default: '1',
      description: _('Honored even on the low resource profile — explicit user opt-in. Disable to skip downloading the ~5 MB metacubexd UI bundle.') });
    addRow(dash, form.Value, 'dashboard_listen', _('Listen address'), { placeholder: '0.0.0.0:9090' });
    addRow(dash, form.Value, 'external_controller', _('External controller'), { placeholder: '127.0.0.1:9090',
      description: _('Where mihomo binds its RESTful control API. Dashboard talks to this. Usually mirrors dashboard_listen.') });
    addRow(dash, form.Value, 'secret', _('Controller secret'), { password: true,
      description: _('Auth token for the external controller. Auto-generated on first run; rotate by clearing and saving.') });
    addRow(dash, form.Value, 'dashboard_path', _('Local install path'), { placeholder: '/etc/purewrt/dashboard' });
    addRow(dash, form.Value, 'dashboard_url', _('Dashboard download URL'),
      { placeholder: 'https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip',
        validate: fmt.validateHTTPURL });
    addRow(dash, form.Value, 'dashboard_name', _('Dashboard name'), { placeholder: 'metacubexd',
      description: _('Subdirectory under /ui/. Lets you bundle multiple dashboard distributions.') });

    // ---- Updates (advanced) ----
    var upd = m.section(form.NamedSection, 'settings', 'main', _('Updates (advanced)'),
      _('Beyond auto-update on/off + cron — these tune the network + I/O priorities of the update job.'));
    upd.anonymous = true;
    addRow(upd, form.Flag, 'suppress_hwid', _('Suppress HWID fingerprint (global)'), { default: '0',
      description: _('Never send router identity (HWID / device-name query params and x-hwid / X-Device-* headers) with any download. Overrides the per-subscription and per-proxy-provider settings; panels that key responses on device identity may serve different content.') });
    addRow(upd, form.Flag, 'update_via_proxy', _('Download via proxy'), { default: '0',
      description: _('Route subscription + provider downloads through the local mihomo proxy (the generated config always opens mixed-port 7890) instead of the WAN directly. Useful when the WAN path is censored but mihomo\'s nodes can reach the provider. No URL needed — it uses mihomo automatically.') });
    addRow(upd, form.Value, 'update_proxy_url', _('Proxy URL override'), { placeholder: _('(empty = local mihomo proxy, http://127.0.0.1:7890)'),
      description: _('Only set this to route updates through a different proxy (e.g. an upstream SOCKS/HTTP gateway). Empty uses mihomo\'s own mixed-port. Also used as the automatic last-resort fallback when direct downloads fail.') });
    addRow(upd, form.Value, 'update_concurrency', _('Concurrent downloads'), { datatype: 'uinteger', default: '2',
      description: _('Number of providers fetched in parallel. Higher = faster, but more bandwidth + RAM during fetch.') });
    addRow(upd, form.Flag, 'reload_after_update', _('Reload after update'), { default: '1',
      description: _('Apply PureWRT after a successful update cycle. Leave on unless you script applies separately.') });
    addRow(upd, form.Flag, 'background_updates', _('Background updates'), { default: '1',
      description: _('Run update-if-needed in the background at boot (init.d service) so the foreground apply doesn\'t wait on downloads.') });
    addRow(upd, form.Value, 'boot_update_delay', _('Boot update delay (s)'), { datatype: 'uinteger', default: '0',
      description: _('Wait this many seconds after boot before triggering the background update. Useful if WAN takes time to come up.') });
    addRow(upd, form.Value, 'update_nice', _('CPU nice'), { datatype: 'integer', default: '19' });
    addRow(upd, form.Value, 'update_ionice_class', _('I/O nice class'), { datatype: 'uinteger', default: '3' });
    addRow(upd, form.Value, 'update_ionice_level', _('I/O nice level'), { datatype: 'uinteger', default: '7' });

    // ---- Cache ----
    var cache = m.section(form.NamedSection, 'settings', 'main', _('Cache'),
      _('PureWRT caches downloaded provider artifacts to avoid re-fetching unchanged files.'));
    cache.anonymous = true;
    addRow(cache, form.ListValue, 'cache_mode', _('Cache mode'), {
      values: [['auto', 'auto (resource-profile aware)'], ['memory', 'memory (tmpfs)'], ['disk', 'disk']], default: 'auto' });
    addRow(cache, form.Value, 'cache_dir', _('Cache directory'),
      { placeholder: '/etc/purewrt/cache', description: _('Empty = default. Pin to a different filesystem if /etc is space-constrained.') });
    addRow(cache, form.ListValue, 'artifact_cache_mode', _('Artifact cache mode'), {
      values: [['auto', 'auto'], ['off', 'off'], ['on', 'on']], default: 'auto' });
    addRow(cache, form.Value, 'artifact_cache_max_bytes', _('Artifact cache max size (bytes)'),
      { datatype: 'uinteger', default: '16777216' });
    addRow(cache, form.Value, 'artifact_cache_max_entries', _('Artifact cache max entries'),
      { datatype: 'uinteger', default: '50000' });

    // ---- Rule processing ----
    var rules = m.section(form.NamedSection, 'settings', 'main', _('Rule processing'));
    rules.anonymous = true;
    addRow(rules, form.ListValue, 'rule_dedup_mode', _('Rule dedup mode'), {
      values: [['auto', 'auto (profile-aware)'], ['off', 'off'], ['section', 'section (first-wins by section)'], ['full', 'full (first-wins overall)']],
      default: 'auto',
      description: _('How aggressively to deduplicate overlapping rules across providers. "full" gives the cleanest nftset state at the cost of more CPU during generation.') });

    // ---- Bootstrap DoH (advanced) ----
    var doh = m.section(form.NamedSection, 'settings', 'main', _('Bootstrap DoH (advanced)'),
      _('Use the wizard to pick the resolver pool; these tune the bootstrap-call behaviour.'));
    doh.anonymous = true;
    addRow(doh, form.Value, 'bootstrap_doh_timeout_ms', _('DoH timeout (ms)'),
      { datatype: 'uinteger', default: '8000' });
    addRow(doh, form.Flag, 'bootstrap_proxy_fallback', _('Proxy fallback'), { default: '1',
      description: _('If every bootstrap DoH endpoint fails, retry via the system DNS resolver. Disable for hard-censorship setups where ISP DNS is hostile.') });
    addRow(doh, form.ListValue, 'bootstrap_tls_fingerprint', _('TLS fingerprint'),
      { values: [['browser', 'browser (default)'], ['off', 'off']], default: 'browser' });
    addRow(doh, form.Flag, 'bootstrap_health_gate', _('Health gate before apply'), { default: '0',
      description: _('Probe every bootstrap resolver before applying; abort if none answer. Heavy but catches silent DNS-blocking before it bricks the apply.') });

    // ---- Mwan3 integration ----
    // Lives here (rather than its own tab) because the four settings under
    // it only matter when the router also runs OpenWrt's mwan3 package —
    // an integration concern, not a routing-policy concern. Bound to UCI
    // section `mwan3` of type `mwan3` (not `settings`/`main`), which is
    // fine: form.Map allows multiple NamedSections on different UCI
    // sections within one Map.
    var mwan3 = m.section(form.NamedSection, 'mwan3', 'mwan3', _('Mwan3 integration'),
      _('Settings used only when OpenWrt\'s mwan3 package is installed and PureWRT\'s routing must coexist with mwan3\'s policies.'));
    mwan3.anonymous = true;
    addRow(mwan3, form.ListValue, 'mode', _('Mode'), {
      values: [
        [ 'coexist',    _('coexist (default — keep PureWRT + mwan3 marks disjoint)') ],
        [ 'integrated', _('integrated (emit mwan3 policy rules via PureWRT)') ],
        [ 'standalone', _('standalone (ignore mwan3 entirely)') ]
      ],
      default: 'coexist',
      description: _('coexist mode is safe with any mwan3 setup; integrated mode lets PureWRT install its own mwan3 policies (requires integrated_rules below).') });
    addRow(mwan3, form.Flag, 'detect', _('Auto-detect mwan3 members'), { default: '1',
      description: _('Resolve mwan3 WAN members at apply time so failover doesn\'t require regenerating PureWRT rules.') });
    addRow(mwan3, form.Flag, 'mmx_mask_auto', _('Auto-detect mmx mask'), { default: '1',
      description: _('Read mwan3\'s mmx_mask from its UCI config rather than hard-coding it here. Disable to override below.') });
    addRow(mwan3, form.Value, 'mwan3_mask', _('mwan3 mmx_mask (manual)'), { placeholder: '0xff00',
      description: _('Only used when auto-detect is off.') });
    addRow(mwan3, form.Value, 'purewrt_mark', _('PureWRT fwmark'), { placeholder: '0x1',
      description: _('Must NOT overlap mwan3\'s mmx_mask range or generation will refuse to write rules.') });
    addRow(mwan3, form.Value, 'purewrt_mask', _('PureWRT fwmark mask'), { placeholder: '0xff' });
    addRow(mwan3, form.Value, 'rule_priority', _('ip rule priority'),
      { datatype: 'uinteger', placeholder: '100' });
    addRow(mwan3, form.Flag, 'integrated_rules', _('Emit integrated rules'), { default: '0',
      description: _('Only honored when Mode = integrated. Lets PureWRT install mwan3 policy rules into mwan3\'s UCI on apply.') });

    // ---- Geo data ----
    var geo = m.section(form.NamedSection, 'settings', 'main', _('Geo data'),
      _('Sources used by the `geo-refresh` job to keep mihomo\'s GeoIP/GeoSite/MMDB datasets current.'));
    geo.anonymous = true;
    addRow(geo, form.Value, 'geo_refresh_geoip_url', _('GeoIP URL'), { placeholder: '(default)', validate: fmt.validateHTTPURL });
    addRow(geo, form.Value, 'geo_refresh_geosite_url', _('GeoSite URL'), { placeholder: '(default)', validate: fmt.validateHTTPURL });
    addRow(geo, form.Value, 'geo_refresh_mmdb_url', _('MMDB URL'), { placeholder: '(default)', validate: fmt.validateHTTPURL });
    addRow(geo, form.Value, 'geo_refresh_geoip_dir', _('Geo install dir'), { placeholder: '/etc/purewrt/geo' });
    addRow(geo, form.Value, 'geo_refresh_cron', _('Refresh cron'), { placeholder: '7 3 * * *',
      validate: fmt.validateCron,
      description: _('Empty disables the scheduled refresh (manual only via `purewrt geo-refresh`).') });

    // ---- Firewall + routing internals ----
    var fw = m.section(form.NamedSection, 'settings', 'main', _('Firewall & routing internals'),
      _('Change only if you have a conflict with another fwmark/route table consumer on this router.'));
    fw.anonymous = true;
    addRow(fw, form.Value, 'fwmark', _('Firewall mark'), { placeholder: '0x1' });
    addRow(fw, form.Value, 'fwmark_mask', _('Firewall mark mask'), { placeholder: '0xff' });
    addRow(fw, form.Value, 'route_table', _('Route table'), { datatype: 'uinteger', placeholder: '100' });
    addRow(fw, form.Value, 'ip_rule_priority', _('ip rule priority'), { datatype: 'uinteger', placeholder: '100' });
    addRow(fw, form.ListValue, 'ipv6_mode', _('IPv6 mode (override)'),
      { values: [['auto', 'auto (follow IPv6 flag + profile)'], ['on', 'on (force)'], ['off', 'off (force)']], default: 'auto',
        description: _('Use the Setup Wizard to toggle IPv6 normally. This override only matters when you need to decouple PureWRT\'s v6 routing from the `ipv6` flag.') });
    addRow(fw, form.Flag, 'ipv6_reject_when_off', _('Reject v6 when IPv6 off'), { default: '0',
      description: _('When IPv6 routing is off, drop v6 packets at nftables instead of leaking them direct. Pairs with the wizard\'s wan6-disable.') });
    addRow(fw, form.Flag, 'router_output_proxy', _('Proxy router-originated traffic'), { default: '0',
      description: _('Mark outbound traffic from the router itself for proxy via the OUTPUT chain. Off by default to avoid breaking the router\'s own update / NTP / DNS paths.') });
    addRow(fw, form.Value, 'cgroup_v2_path', _('Cgroupv2 path'), { placeholder: 'services/mihomo',
      description: _('Used in the cgroupv2 self-exemption rule so mihomo\'s own outbound isn\'t re-marked. Matches procd\'s service path; rarely needs editing.') });
    addRow(fw, form.DynamicList, 'ipv6_wan_interface', _('IPv6 WAN interfaces (override)'),
      { placeholder: 'wan6',
        description: _('Names of /etc/config/network sections to disable when IPv6 routing is off. Empty = autodetect at apply time (every proto=dhcpv6 interface). Set explicitly for multi-WAN setups or non-standard section names.') });
    addRow(fw, form.DynamicList, 'lan_source_zone', _('LAN source zones (routed)'),
      { values: zoneValues, placeholder: 'lan',
        description: _('Firewall zones whose clients route through PureWRT. For each, PureWRT writes the DNS-hijack redirect + a TPROXY input-accept rule keyed on PureWRT\'s fwmark — required so proxied traffic is accepted on zones with input REJECT (multi-VLAN setups). Zones that forward to wan are marked (→ wan). Empty = lan.') });

    // ---- Paths ----
    var paths = m.section(form.NamedSection, 'settings', 'main', _('Paths'),
      _('Where PureWRT stores config + runtime artefacts. Changes here require careful manual cleanup of the old paths.'));
    paths.anonymous = true;
    addRow(paths, form.Value, 'workdir', _('Work dir'), { placeholder: '/etc/purewrt' });
    addRow(paths, form.Value, 'runtime_dir', _('Runtime dir'), { placeholder: '/tmp/purewrt' });
    addRow(paths, form.Value, 'generated_dir', _('Generated dir'), { placeholder: '(default: runtime_dir/generated)' });
    addRow(paths, form.Value, 'dnsmasq_include_dir', _('Dnsmasq include dir'), { placeholder: '(autodetect)' });

    return m.render().then(function(root) {
      // Default LuCI footer Save/Save & Apply work fine since every section
      // writes to the same UCI section — the form's onsave fires once with
      // the merged record. No custom save chain needed here; subscriptions/
      // proxyproviders use save_chain because their saves trigger
      // long-running update jobs, but a Settings save only needs an apply.
      root.appendChild(backupRestoreCard());
      return root;
    });
  }
});
