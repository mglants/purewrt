'use strict';
'require view';
'require form';
'require uci';
'require rpc';
'require fs';
'require ui';
'require purewrt.table_section as tableSection';
'require purewrt.format as fmt';

// Manual rule providers (format = "manual") live as plain text files under
// /etc/purewrt/rulesets/<name>.txt, owned by the user, no `url`. The
// textarea below reads/writes that file via fs.* (LuCI's stock file
// plugin gated by the ACL whitelist on /etc/purewrt/rulesets/*.txt).
var MANUAL_RULES_DIR = '/etc/purewrt/rulesets';
function manualPathFor(name) { return MANUAL_RULES_DIR + '/' + name + '.txt'; }

// pathForManualSection returns the on-disk path to read/write for a section's
// manual body. Respects an existing UCI `path` value when it points inside
// MANUAL_RULES_DIR — covers users who already have a manual file with a
// non-.txt extension (e.g. legacy .list from the pre-format=manual era).
// Falls back to the derived <name>.txt for fresh provisions.
function pathForManualSection(section_id) {
  var existing = uci.get('purewrt', section_id, 'path') || '';
  if (existing && existing.indexOf(MANUAL_RULES_DIR + '/') === 0) return existing;
  var name = uci.get('purewrt', section_id, 'name') || section_id;
  return manualPathFor(name);
}

var callReload = rpc.declare({ object: 'purewrt', method: 'reload' });
// Catalog import — same backend path the setup wizard's "Default lists" flow
// uses (default_lists_catalog → native_list_add ×N → update → reload). The
// catalog ships a JSON array, wrapped {"catalog":[…]} for ubus.
var callDefaultListsCatalog = rpc.declare({ object: 'purewrt', method: 'default_lists_catalog', expect: { catalog: [] } });
var callNativeListAdd = rpc.declare({ object: 'purewrt', method: 'native_list_add', params: [ 'url', 'section', 'priority' ] });
var callUpdate = rpc.declare({ object: 'purewrt', method: 'update' });
var callUpdateRuleProvider = rpc.declare({ object: 'purewrt', method: 'update_rule_provider', params: [ 'name' ] });
var callUpdateRuleProviderHot = rpc.declare({ object: 'purewrt', method: 'update_rule_provider_no_restart', params: [ 'name' ] });
var callRuleProviderStatus = rpc.declare({ object: 'purewrt', method: 'rule_provider_status' });
// Geo helpers — geo_list returns categories/countries from the local
// downloaded v2ray dat (geo-refresh cron populates it). The envelope
// wrapper is for ubus which rejects top-level JSON arrays.
var callGeoList = rpc.declare({ object: 'purewrt', method: 'geo_list', params: [ 'kind' ], expect: { items: [] } });
var callGeoDefaults = rpc.declare({ object: 'purewrt', method: 'geo_default_sources' });

function providerStatus(stats, name) {
  var providers = (stats && stats.rule_providers) || [];
  for (var i = 0; i < providers.length; i++)
    if (providers[i].name === name)
      return providers[i];
  return null;
}

function sectionTitle(sid) {
  return uci.get('purewrt', sid, 'name') || sid || _('New rule provider');
}

function preserveExistingOption(opt) {
  opt.rmempty = true;
  opt.write = function(sectionId, value) {
    var old = uci.get('purewrt', sectionId, opt.option);

    if ((old == null || old === '') && (value == null || value === '' || value === 'auto'))
      return;

    this.super('write', [ sectionId, value ]);
  };
  opt.remove = function(sectionId) {
    var old = uci.get('purewrt', sectionId, opt.option);

    if (old != null && old !== '')
      this.map.data.set('purewrt', sectionId, opt.option, old);
  };
}

function preserveHiddenFlag(section, optionName) {
  var opt = section.option(form.Value, optionName, optionName);

  opt.modalonly = true;
  opt.readonly = true;
  opt.render = function() { return E([]); };
  opt.write = function(sectionId, value) {
    var old = uci.get('purewrt', sectionId, optionName);

    if (old != null && old !== '')
      this.map.data.set('purewrt', sectionId, optionName, old);
  };
  opt.remove = function(sectionId) {
    var old = uci.get('purewrt', sectionId, optionName);

    if (old != null && old !== '')
      this.map.data.set('purewrt', sectionId, optionName, old);
  };

  return opt;
}

function updateRuleProvider(sid) {
  var name = uci.get('purewrt', sid, 'name') || sid;
  return callUpdateRuleProvider(name).then(function() {
    ui.addNotification(null, E('p', _('Rule provider updated and applied')), 'info');
  });
}

function hotReloadRuleProvider(sid) {
  var name = uci.get('purewrt', sid, 'name') || sid;
  return callUpdateRuleProviderHot(name).then(function() {
    ui.addNotification(null, E('p', _('Rule provider hot-reloaded via mihomo PUT /providers/rules')), 'info');
  });
}

function ruleSummary(sid, stats) {
  var name = sectionTitle(sid);
  var st = providerStatus(stats, name);
  return [
    name,
    uci.get('purewrt', sid, 'behavior') || '-',
    uci.get('purewrt', sid, 'format') || '-',
    uci.get('purewrt', sid, 'section') || '-',
    uci.get('purewrt', sid, 'priority') || '1000',
    st && st.error ? _('Error') : (st && st.last_success ? _('OK') : '-')
  ];
}

// nativeListNameFor mirrors the Go nativeListName() derivation
// (internal/manager/native_list.go) so we can detect already-imported catalog
// entries: strip the directory + .native/.lst suffix, lowercase, collapse
// non-alnum runs to '_', trim '_', prefix 'native_'.
function nativeListNameFor(file) {
  var base = String(file || '');
  var slash = base.lastIndexOf('/');
  if (slash >= 0) base = base.slice(slash + 1);
  base = base.replace(/\.(native|lst)$/, '')
             .toLowerCase()
             .replace(/[^a-z0-9_]+/g, '_')
             .replace(/^_+|_+$/g, '');
  if (!base) base = 'list';
  return 'native_' + base;
}

// existingRuleProviderNames returns the set of rule_provider section names
// currently in UCI, so the picker can flag entries that are already imported.
function existingRuleProviderNames() {
  var set = {};
  uci.sections('purewrt', 'rule_provider', function(sec) {
    var n = sec.name || sec['.name'];
    if (n) set[n] = true;
  });
  return set;
}

// openCatalogImport pops a multi-select picker over the published rules
// catalog (default_lists_catalog) and imports the chosen entries via the same
// idempotent native_list_add → update → reload chain the setup wizard uses.
// `sections` is the list of existing routing sections, for the per-row target
// dropdown.
function openCatalogImport(sections) {
  var base = uci.get('purewrt', 'settings', 'default_lists_base_url') || '';
  if (base && !/\/$/.test(base)) base += '/';

  ui.showModal(_('Import rule providers from catalog'), [
    E('p', { 'class': 'spinning' }, _('Fetching catalog…'))
  ]);

  callDefaultListsCatalog().catch(function() { return []; }).then(function(catalog) {
    catalog = catalog || [];
    var existing = existingRuleProviderNames();

    if (!catalog.length) {
      ui.showModal(_('Import rule providers from catalog'), [
        E('p', {}, _('The catalog could not be fetched, or it is empty. Check the Default-lists base URL in Settings and the router’s connectivity, then try again.')),
        E('div', { 'class': 'right' }, [
          E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Close'))
        ])
      ]);
      return;
    }

    // One row of UI state per catalog entry.
    var rows = catalog.map(function(entry) {
      var suggested = entry.suggested_section || 'common';
      // Build the section option list: suggested + existing sections + direct/reject, deduped.
      var opts = [ suggested ];
      (sections || []).forEach(function(sec) { if (opts.indexOf(sec.name) < 0) opts.push(sec.name); });
      [ 'direct', 'reject' ].forEach(function(n) { if (opts.indexOf(n) < 0) opts.push(n); });

      var cb = E('input', { 'type': 'checkbox', 'style': 'margin-right:.4em' });
      var sel = E('select', { 'class': 'cbi-input-select', 'style': 'margin-left:.6em' },
        opts.map(function(n) {
          return E('option', n === suggested ? { 'value': n, 'selected': 'selected' } : { 'value': n }, n);
        }));

      var counts = [];
      if (entry.domains) counts.push(entry.domains + ' ' + _('domains'));
      if (entry.subnets) counts.push(entry.subnets + ' ' + _('subnets'));
      var already = !!existing[nativeListNameFor(entry.file)];

      var label = E('label', { 'style': 'display:flex;align-items:center;flex-wrap:wrap;gap:.2em;padding:.25em 0' }, [
        cb,
        E('strong', {}, entry.name || entry.file),
        counts.length ? E('span', { 'style': 'color:#888;margin-left:.4em' }, '— ' + counts.join(', ')) : E('span'),
        (entry.priority != null && entry.priority !== '') ? E('span', { 'style': 'color:#888;margin-left:.4em' }, _('(priority %s)').format(entry.priority)) : E('span'),
        already ? E('span', { 'class': 'purewrt-pill purewrt-pill-info', 'style': 'margin-left:.4em' }, _('already imported')) : E('span'),
        E('span', { 'style': 'margin-left:auto' }, [ _('→ section '), sel ])
      ]);

      return { entry: entry, cb: cb, sel: sel, node: label };
    });

    var importBtn = E('button', { 'class': 'btn cbi-button-save', 'disabled': 'disabled' }, _('Import selected'));

    function checkedCount() {
      var n = 0;
      rows.forEach(function(r) { if (r.cb.checked) n++; });
      return n;
    }
    function refreshBtn() {
      var n = checkedCount();
      var noBase = !base;
      importBtn.disabled = (n === 0 || noBase) ? 'disabled' : null;
      importBtn.textContent = n ? _('Import %d selected').format(n) : _('Import selected');
    }
    rows.forEach(function(r) { r.cb.addEventListener('change', refreshBtn); });

    var body = [
      E('p', {}, _('Select which catalog lists to import. Each becomes a native_import rule provider bound to the chosen section (created if it doesn’t exist), using the catalog’s priority.')),
      base ? E([]) : E('p', { 'class': 'alert-message warning' }, _('The Default-lists base URL is not set (Settings). Set it before importing.')),
      E('div', { 'style': 'max-height:24em;overflow-y:auto;border:1px solid #ccc;border-radius:4px;padding:.3em .6em;margin:.4em 0' },
        rows.map(function(r) { return r.node; }))
    ];

    importBtn.addEventListener('click', function(ev) {
      ev.preventDefault();
      var chosen = rows.filter(function(r) { return r.cb.checked; });
      if (!chosen.length || !base) return;
      importBtn.disabled = 'disabled';
      importBtn.textContent = _('Importing…');
      var adds = chosen.map(function(r) {
        return callNativeListAdd(base + r.entry.file, r.sel.value, String(r.entry.priority != null ? r.entry.priority : ''));
      });
      Promise.all(adds).then(callUpdate).then(callReload).then(function() {
        ui.hideModal();
        ui.addNotification(null, E('p', _('Imported %d catalog list(s) and applied').format(chosen.length)), 'info');
        window.location.reload();
      }).catch(function(err) {
        importBtn.disabled = null;
        refreshBtn();
        ui.addNotification(null, E('p', _('Catalog import failed: %s').format((err && err.message) || err)), 'error');
      });
    });

    ui.showModal(_('Import rule providers from catalog'), body.concat([
      E('div', { 'class': 'right' }, [
        E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')),
        ' ',
        importBtn
      ])
    ]));
    refreshBtn();
  });
}

return view.extend({
  load: function() {
    return Promise.all([
      uci.load('purewrt'),
      callRuleProviderStatus().catch(function() { return {}; }),
      // Pull geo entries up-front so the picker dropdown renders without
      // a second round-trip. Both calls degrade to [] when the dat files
      // aren't present yet — the UI shows a hint pointing at Settings →
      // Geo data in that case.
      callGeoList('geosite').catch(function() { return []; }),
      callGeoList('geoip').catch(function() { return []; }),
      callGeoDefaults().catch(function() { return {}; })
    ]).then(function(data) {
      var sections = [];
      uci.sections('purewrt', 'section', function(s) {
        var name = s['.name'] || s.name;
        if (name)
          sections.push({ name: name, action: s.action || 'proxy' });
      });
      return { sections: sections, stats: data[1] || {}, geosite: data[2] || [], geoip: data[3] || [], geoDefaults: data[4] || {} };
    });
  },

  render: function(data) {
    var sections = (data && data.sections) || [];
    var stats = (data && data.stats) || {};
    var geosite = (data && data.geosite) || [];
    var geoip = (data && data.geoip) || [];
    var geoDefaults = (data && data.geoDefaults) || {};
    var m = new form.Map('purewrt', _('PureWRT Rule Providers'));

    m.handleSaveApply = function(ev, mode) {
      // Pre-save hook: when a geo-backed provider exists and
      // Settings.GeoRefresh{GeoIP,GeoSite}URL is empty, fill it from
      // geoDefaults so the user sees sensible URLs in Settings → Geo
      // data after saving (Go side does the same on its writes; this
      // mirrors the behaviour for direct UCI writes from LuCI).
      try {
        var hasGeosite = false, hasGeoip = false;
        uci.sections('purewrt', 'rule_provider', function(sec) {
          var fmt = sec.format || '';
          if (fmt === 'geosite') hasGeosite = true;
          if (fmt === 'geoip')   hasGeoip   = true;
        });
        if (hasGeosite && !uci.get('purewrt', 'settings', 'geo_refresh_geosite_url') && geoDefaults.geosite) {
          uci.set('purewrt', 'settings', 'geo_refresh_geosite_url', geoDefaults.geosite);
        }
        if (hasGeoip && !uci.get('purewrt', 'settings', 'geo_refresh_geoip_url') && geoDefaults.geoip) {
          uci.set('purewrt', 'settings', 'geo_refresh_geoip_url', geoDefaults.geoip);
        }
        if (hasGeoip && !uci.get('purewrt', 'settings', 'geo_refresh_mmdb_url') && geoDefaults.mmdb) {
          uci.set('purewrt', 'settings', 'geo_refresh_mmdb_url', geoDefaults.mmdb);
        }
      } catch (e) { /* seeding is best-effort; never block a save */ }
      return m.save(null, mode).then(function() {
        return callReload();
      }).then(function() {
        ui.addNotification(null, E('p', _('Rule-provider routing saved and PureWRT applied')), 'info');
      });
    };

    var s = m.section(form.TypedSection, 'rule_provider', _('Rule providers'));
    s.addremove = true;
    s.anonymous = false;
    s.sectiontitle = sectionTitle;

    s.option(form.Flag, 'enabled', _('Enabled'));
    s.option(form.Value, 'name', _('Name'));

    var behavior = s.option(form.ListValue, 'behavior', _('Behavior'));
    behavior.value('domain', _('Domain'));
    behavior.value('ipcidr', _('IP/CIDR'));
    behavior.value('classical', _('Classical'));
    // Behavior is meaningless for geo formats — the dat file is
    // self-describing (domains for geosite, CIDRs for geoip) and
    // ParseGeoProvider hardcodes the right rule types.
    behavior.depends('format', 'text');
    behavior.depends('format', 'mrs');
    behavior.description = _('How the provider\'s entries are matched against traffic. <strong>Domain</strong>: each entry is a domain or suffix, matched against DNS queries (populates dynamic dns_ sets). <strong>IP/CIDR</strong>: each entry is an IPv4/IPv6 address or CIDR, matched against packet destinations (populates static nftset). <strong>Classical</strong>: accepts mixed content — bare FQDNs (<code>example.com</code>), bare IPs (<code>74.125.131.19</code> auto-promoted to <code>/32</code>), CIDRs, and full rule expressions (<code>DOMAIN-SUFFIX,google.com</code>, <code>IP-CIDR,1.2.3.4/24</code>). Most expressive; processed entirely inside mihomo, so slightly slower than Domain/IP-only.');

    var format = s.option(form.ListValue, 'format', _('Format'));
    format.value('text', _('Text'));
    format.value('mrs', _('MRS'));
    format.value('geosite', _('GeoSite category'));
    format.value('geoip', _('GeoIP country'));
    format.description = _('On-disk encoding of the rule file. <strong>Text</strong>: one entry per line. <strong>MRS</strong>: mihomo\'s binary ruleset. <strong>GeoSite/GeoIP</strong>: extracts the chosen category/country from the locally-downloaded v2ray <code>geosite.dat</code> / <code>geoip.dat</code> (managed by the geo-refresh cron). No URL is fetched for geo formats — the local dat is the source, and rules are expanded into nftset / nftables sets exactly like a URL list.');

    // Per-format geo target dropdown. CBI doesn't let one ListValue
    // swap its option list based on another field's value, so we use
    // two separate options that both bridge into the same canonical
    // `geo_target` UCI key via cfgvalue/write/remove overrides. Each
    // is only visible for its matching format.
    function makeGeoTarget(formatVal, label, items) {
      var opt = s.option(form.ListValue, 'geo_target_ui_' + formatVal, label);
      opt.depends('format', formatVal);
      opt.rmempty = false;
      // Both options read from / write to the canonical geo_target key
      // so a single UCI field carries the picked value regardless of
      // which dropdown the user clicked.
      opt.cfgvalue = function(sid) { return uci.get('purewrt', sid, 'geo_target') || ''; };
      opt.write = function(sid, val) { uci.set('purewrt', sid, 'geo_target', val); };
      opt.remove = function(sid) { /* leave geo_target alone — the canonical writer for the active format will handle it */ };
      if (items && items.length) {
        items.forEach(function(name) { opt.value(name, name); });
        opt.description = _('Pick a %s entry from the locally-downloaded geo database. ~%d available; type to filter.').format(formatVal, items.length);
      } else {
        opt.value('', _('— geo files not downloaded yet —'));
        opt.description = _('No %s entries found in <code>/etc/purewrt/geo/%s.dat</code>. Run <strong>purewrt geo-refresh</strong> or use Settings → Geo data, then reopen this dialog.').format(formatVal, formatVal);
      }
      return opt;
    }
    makeGeoTarget('geosite', _('GeoSite category'), geosite);
    makeGeoTarget('geoip',   _('GeoIP country'),   geoip);

    var parseMode = s.option(form.ListValue, 'parse_mode', _('Parse mode'));
    parseMode.value('auto', _('Auto'));
    parseMode.value('normalize', _('Normalize'));
    // native_import: pre-built nftset-builder list (bare domains + @cidr +
    // CIDRs) imported verbatim — no parse/validate/dedup on the router.
    parseMode.value('native_import', _('Native import (pre-built list)'));
    // Geo providers always go through the canonical text-serialization
    // path materializeGeoProvider writes; the parse-mode toggle would
    // be ignored anyway, so hide it for geo formats.
    parseMode.depends('format', 'text');
    parseMode.depends('format', 'mrs');
    parseMode.description = _('How PureWRT consumes the parsed entries. <strong>Auto</strong>: picks Normalize for domain/classical providers and Native fast for IP/CIDR providers. <strong>Normalize</strong>: every entry is parsed and re-serialised into PureWRT\'s canonical format (slowest but allows dedup, validation, and cross-provider conflict resolution). <strong>Native fast</strong>: accepts dnsmasq <code>nftset=…</code> lines and <code>nft add element</code> blocks as data and pipes them straight into PureWRT-owned outputs (fastest; skips validation). <strong>Native only</strong>: same as Native fast but rejects anything that isn\'t already in native format instead of falling back.');
    preserveExistingOption(parseMode);

    // URL is shown for text/mrs only — geo formats have no URL.
    var url = s.option(form.Value, 'url', _('URL'));
    url.depends('format', 'text');
    url.depends('format', 'mrs');
    url.validate = fmt.validateHTTPURL;
    var path = s.option(form.Value, 'path', _('Local path'));
    path.depends('format', 'mrs');
    path.depends({ format: 'text', url: /.+/ });
    // When path is hidden (format=text + url empty), form's parse cycle
    // would otherwise unset it. We need it set to the derived
    // <name>.txt so the generator can find the local file. Intercept
    // remove() to write the derived path instead of unsetting.
    var origPathRemove = path.remove.bind(path);
    path.remove = function(sid) {
      var fmt = (this.section && this.section.formvalue)
        ? this.section.formvalue(sid, 'format') : null;
      if (fmt == null) fmt = uci.get('purewrt', sid, 'format');
      var urlVal = (this.section && this.section.formvalue)
        ? this.section.formvalue(sid, 'url') : null;
      if (urlVal == null) urlVal = uci.get('purewrt', sid, 'url');
      if (fmt === 'text' && (urlVal == null || urlVal === '')) {
        uci.set('purewrt', sid, 'path', pathForManualSection(sid));
        return;
      }
      return origPathRemove(sid);
    };

    // The local-file rules textarea — only visible when format=text AND
    // url is empty. Reads the file body on modal open (via fs.read in
    // load()) and writes it on save (via fs.write in write()). Also
    // takes responsibility for setting `path` since that field is hidden
    // when url is empty and won't write itself.
    var manualBody = s.option(form.TextValue, '_manual_body', _('Local rules'));
    // depends() value as a string compares literally — empty string here
    // matches an unset/empty url field.
    manualBody.depends({ format: 'text', url: '' });
    manualBody.modalonly = true;
    manualBody.rows = 16;
    manualBody.wrap = 'off';
    manualBody.monospace = true;
    manualBody.placeholder = '# one entry per line — IPs, CIDRs, or FQDNs\n# lines starting with # are comments\nexample.com\nsub.domain.com\n74.125.131.19\n74.125.0.0/16';
    manualBody.description = _('One entry per line: IP, CIDR, or FQDN. Comments start with <code>#</code> at the beginning of a line. File is stored at <code>/etc/purewrt/rulesets/&lt;name&gt;.txt</code>.');
    // Always fetch the file on modal open — not gated on current
    // saved format. Reasons:
    //   1. The user can flip format=text → manual mid-modal and expects
    //      to see any existing file body, not a blank textarea.
    //   2. CRDR providers migrated from the old custom-modal flow have
    //      format=text but a real file under rulesets/<name>.txt — fetching
    //      lets the user recover them by simply switching format=manual.
    // LuCI's section.load awaits this Promise then calls cfgvalue(sid,
    // body) as a setter to seed the default cached_cfgvalues cache. No
    // custom cfgvalue override needed — the default handles get + set.
    manualBody.load = function(section_id) {
      // Swallow ALL fs errors (not just NotFoundError) — section.load
      // walks load() for every option on every section regardless of
      // depends visibility. Reading a binary `.mrs` file via fs.read
      // returns UnsupportedError, which would otherwise reject
      // Promise.all and stall the whole form render. The textarea is
      // hidden for non-manual formats anyway, so an empty body is the
      // right placeholder when the read fails.
      return fs.read(pathForManualSection(section_id)).catch(function() { return ''; });
    };
    manualBody.write = function(section_id, value) {
      var p = pathForManualSection(section_id);
      // Auto-set path / clear url here so the UCI section is consistent
      // even though those fields are hidden by depends. Also stamp
      // user_overridden_section so subscription imports don't try to
      // reconcile this provider.
      uci.set('purewrt', section_id, 'path', p);
      uci.unset('purewrt', section_id, 'url');
      uci.set('purewrt', section_id, 'user_overridden_section', '1');
      // Normalise CRLF + trailing whitespace + ensure single trailing LF
      // so subsequent reads round-trip cleanly.
      var body = String(value || '').replace(/\r\n/g, '\n').replace(/[ \t\n]+$/, '');
      if (body) body += '\n';
      return fs.write(p, body);
    };
    manualBody.remove = function() { /* keep the file on format change */ };
    var interval = s.option(form.Value, 'interval', _('Update interval'));
    interval.datatype = 'uinteger';

    var priority = s.option(form.Value, 'priority', _('Conflict priority'));
    priority.datatype = 'integer';
    priority.placeholder = '1000';
    priority.description = _('Lower value wins when the same exact domain/CIDR/native rule appears in multiple providers. Empty or 0 uses the default priority 1000.');

    var targetSection = s.option(form.ListValue, 'section', _('Routing section'));
    targetSection.rmempty = false;
    targetSection.write = function(sectionId, value) {
      var old = uci.get('purewrt', sectionId, 'section');

      this.super('write', [ sectionId, value ]);

      if (old !== value)
        this.map.data.set('purewrt', sectionId, 'user_overridden_section', '1');
    };
    targetSection.value('direct', _('Direct'));
    targetSection.value('reject', _('Reject'));
    (sections || []).forEach(function(sec) {
      targetSection.value(sec.name, sec.name + ' (' + sec.action + ')');
    });

    var category = s.option(form.Value, 'category', _('Detected category'));
    category.readonly = true;
    var sourceKind = s.option(form.Value, 'source_kind', _('Source kind'));
    sourceKind.readonly = true;
    var detectedAction = s.option(form.Value, 'route_action', _('Detected action'));
    detectedAction.readonly = true;
    preserveHiddenFlag(s, 'user_overridden_section');
    preserveHiddenFlag(s, 'user_overridden_export');
    var mirror = s.option(form.DynamicList, 'mirror', _('Mirror URLs'));
    mirror.description = _('Alternate URLs tried after the primary fails. Useful when the upstream ruleset host is intermittently blocked.');
    var pin = s.option(form.Value, 'pin_sha256', _('TLS pin (SPKI SHA-256)'));
    pin.placeholder = 'sha256/<64 hex chars>,sha256/...';
    pin.description = _('Comma-separated SubjectPublicKeyInfo SHA-256 hashes. The handshake fails unless one matches a cert in the peer chain.');
    var supHWID = s.option(form.Flag, 'suppress_hwid', _('Suppress HWID fingerprint'));
    supHWID.default = '0';
    supHWID.description = _('Disable router-derived HWID/device-name injection (URL + headers) for this rule provider.');

    var lastSuccess = s.option(form.DummyValue, '_last_success', _('Last successful update'));
    lastSuccess.cfgvalue = function(sectionId) {
      var name = uci.get('purewrt', sectionId, 'name') || sectionId;
      var st = providerStatus(stats, name);
      return st && st.last_success ? st.last_success : '-';
    };

    var lastError = s.option(form.DummyValue, '_last_error', _('Last error'));
    lastError.cfgvalue = function(sectionId) {
      var name = uci.get('purewrt', sectionId, 'name') || sectionId;
      var st = providerStatus(stats, name);
      return st && st.error ? st.error : '-';
    };

    var update = s.option(form.Button, '_update', _('Update this provider'));
    update.inputstyle = 'apply';
    update.onclick = function(ev, sectionId) {
      return updateRuleProvider(sectionId);
    };

    var hotReload = s.option(form.Button, '_hot_reload', _('Hot reload (no apply)'));
    hotReload.inputstyle = 'action';
    hotReload.description = _('Re-downloads the provider then asks mihomo to refresh its rule engine in place. Skips the full PureWRT apply pipeline — much faster, but assumes the on-disk file path is already wired into mihomo.yaml.');
    hotReload.onclick = function(ev, sectionId) {
      return hotReloadRuleProvider(sectionId);
    };

    return m.render().then(function(root) {
      tableSection.render(root, {
        columns: '5rem 0 1.5fr 1fr 1fr 1.4fr 1fr 1fr 1fr 18rem',
        headers: [ '', '', _('Name'), _('Behavior'), _('Format'), _('Section'), _('Priority'), _('Status'), _('Enable'), '' ],
        draggable: true,
        showEnable: true,
        titleOf: sectionTitle,
        summaryOf: function(sid) { return ruleSummary(sid, stats); },
        save: function() { return m.save().then(callReload); },
        actions: [
          { label: _('Update'), style: 'apply', onclick: function(sid) { return updateRuleProvider(sid); } },
          { label: _('Edit'), kind: 'edit' },
          { label: _('Delete'), kind: 'delete', style: 'remove' }
        ]
      });
      // Top toolbar: import rule providers from the published catalog (multi-select).
      var bar = E('div', { 'style': 'margin:.5em 0' }, [
        E('button', {
          'class': 'btn cbi-button-action',
          'click': function(ev) { ev.preventDefault(); openCatalogImport(sections); }
        }, _('Import from catalog…'))
      ]);
      root.insertBefore(bar, root.firstChild);
      return root;
    });
  }
});
