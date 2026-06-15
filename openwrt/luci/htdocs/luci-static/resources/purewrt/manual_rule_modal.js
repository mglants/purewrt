'use strict';
'require baseclass';
'require ui';
'require uci';
'require rpc';
'require fs';

// purewrt.manual_rule_modal — paste-and-save editor for manual rule
// providers. A "manual" provider is a rule_provider UCI section backed by
// a local file (no `url`, just `path`) that the user owns through this UI.
//
// File I/O goes through LuCI's stock `fs` helper (rpcd's `file` plugin)
// gated by the ACL whitelist on /etc/purewrt/rulesets/*.txt — same pattern
// as ruantiblock's user_lists/* editor. No custom ubus methods, no Go
// CLI subcommands, no shell handler — just two RPC calls (file/read,
// file/write) the LuCI runtime already knows how to talk to.
//
// Reload after save uses the existing `purewrt:reload` RPC so the
// generator + dnsmasq + nftables all see the new file in one apply.

var callReload = rpc.declare({ object: 'purewrt', method: 'reload' });

// MANUAL_RULES_DIR mirrors config.DefaultWorkdir + "/rulesets" on the
// backend. Used both for "is this a manual provider?" detection (path
// lives under here AND url is empty) and to construct the file path we
// write into the new UCI section.
var MANUAL_RULES_DIR = '/etc/purewrt/rulesets';
var MANUAL_NAME_RE = /^[A-Za-z0-9._-]{1,64}$/;

// A "manual" provider in the simplified model is: format=text + no URL.
// Path extension doesn't matter (legacy `.list` files from before the
// format simplification still qualify). The URL emptiness is what marks
// it as locally-edited rather than upstream-fetched.
function isManualProvider(section) {
  if (!section) return false;
  if (section.url && String(section.url).trim() !== '') return false;
  var fmt = String(section.format || 'text').toLowerCase();
  return fmt === 'text';
}

function listManualProviders() {
  var out = [];
  (uci.sections('purewrt', 'rule_provider') || []).forEach(function(s) {
    if (!isManualProvider(s)) return;
    out.push({
      name: s.name || s['.name'],
      sid: s['.name'],
      section: s.section || '',
      path: s.path || ''
    });
  });
  return out;
}

function manualPathFor(name) {
  return MANUAL_RULES_DIR + '/' + name + '.txt';
}

// pathForName looks up the UCI-stored path for a rule_provider matched by
// `name`. Legacy providers may use non-.txt extensions (e.g. `.list` from
// the pre-format-simplification era), so we honour the saved path when
// present and only fall back to the derived <name>.txt for fresh providers
// the user is about to create.
function pathForName(name) {
  var sections = uci.sections('purewrt', 'rule_provider') || [];
  for (var i = 0; i < sections.length; i++) {
    if (sections[i].name === name) {
      var p = sections[i].path || '';
      if (p) return p;
      break;
    }
  }
  return manualPathFor(name);
}

// validateName mirrors what the backend used to enforce in Go. Kept in
// JS so the user gets immediate feedback (no round-trip just to fail).
// "." and ".." are explicit rejects despite matching the dot-in-charset
// regex, same as the prior Go check.
function validateName(name) {
  if (!MANUAL_NAME_RE.test(name) || name === '.' || name === '..') {
    return _('Name must match [A-Za-z0-9._-]{1,64} and not be . or ..');
  }
  return null;
}

// normaliseBody collapses CRLF → LF and ensures exactly one trailing
// newline. Same normalisation the previous Go backend did before
// atomic-write — keeping it in JS means a round-trip read after write
// returns the same bytes the user just typed.
function normaliseBody(body) {
  var s = String(body || '').replace(/\r\n/g, '\n');
  s = s.replace(/[ \t\n]+$/, '');
  return s ? s + '\n' : '';
}

// readBody returns the file body, or empty string when the file doesn't
// exist yet OR is empty (fresh creates shouldn't error — they should see an
// empty editor). fs.read rejects with a NotFoundError on missing files, and
// with "No data received" on a zero-byte file (the `file` ubus read returns
// no `data` field). A manual provider created with an empty textarea writes a
// 0-byte file, so the very next append would otherwise fail — flatten both to
// an empty string and let other errors bubble.
function readBody(name) {
  return fs.read(pathForName(name)).catch(function(e) {
    if (e && (e.name === 'NotFoundError' || /No data received/i.test(String((e && e.message) || e))))
      return '';
    throw e;
  });
}

function writeBody(name, body) {
  return fs.write(pathForName(name), normaliseBody(body));
}

// appendLine is a read-modify-write of a single line with dedup. Used by
// the "Add to manual provider" CTAs on the blocking + diagnostics pages.
// Returns {added: true/false} so the caller can show "added" vs
// "duplicate" notifications without a separate verify-round-trip.
function appendLine(name, line) {
  var clean = String(line || '').trim();
  if (!clean) return Promise.reject(new Error(_('empty line')));
  if (clean.indexOf('\n') >= 0 || clean.indexOf('\r') >= 0)
    return Promise.reject(new Error(_('line must not contain newlines')));
  return readBody(name).then(function(body) {
    var want = clean.toLowerCase();
    var existing = body.split('\n');
    for (var i = 0; i < existing.length; i++) {
      if (existing[i].trim().toLowerCase() === want)
        return { added: false };
    }
    var next = body && !body.endsWith('\n') ? body + '\n' : body;
    next += clean + '\n';
    return writeBody(name, next).then(function() { return { added: true }; });
  });
}

function deleteFile(name) {
  return fs.remove(manualPathFor(name)).catch(function(e) {
    // Missing file is fine — the caller may have already deleted the UCI
    // section without ever writing a body.
    if (e && e.name === 'NotFoundError') return null;
    throw e;
  });
}

// writeUCIFor creates or updates the UCI rule_provider section for a
// manual provider. Idempotent — when editing, the same section is
// updated in place (matched by `name` field, not `.name` SID).
function writeUCIFor(name, section, priority, enabled) {
  var existing = (uci.sections('purewrt', 'rule_provider') || []).filter(function(s) {
    return s.name === name;
  })[0];
  var sid = existing ? existing['.name'] : uci.add('purewrt', 'rule_provider');
  uci.set('purewrt', sid, 'name', name);
  uci.set('purewrt', sid, 'enabled', enabled ? '1' : '0');
  // Manual providers are always classical — the parser auto-classifies
  // FQDN / IP / CIDR / classical-rule entries (the union of what the
  // other behaviors accept). No reason to expose the choice to the user.
  uci.set('purewrt', sid, 'behavior', 'classical');
  uci.set('purewrt', sid, 'format', 'text');
  // Preserve an existing path if the UCI section already has one (legacy
  // .list files from before the format simplification still work). Derive
  // <name>.txt only for fresh creates where no path was ever set.
  var existingPath = existing && existing.path ? existing.path : '';
  uci.set('purewrt', sid, 'path', existingPath || manualPathFor(name));
  uci.unset('purewrt', sid, 'url');
  if (section)
    uci.set('purewrt', sid, 'section', section);
  if (priority)
    uci.set('purewrt', sid, 'priority', String(priority));
  uci.set('purewrt', sid, 'user_overridden_section', '1');
  return sid;
}

// openManualModal renders the create/edit form in ui.showModal.
//   opts = { name, onSave }
//
// Section list is loaded from UCI inside the modal — the picker callers
// (blocking.js, diagnostics.js) don't have a sections array on hand and
// shouldn't be forced to plumb one through. uci.load is idempotent, so
// callers that already loaded purewrt UCI (e.g. the picker did, on its
// way here) pay nothing extra.
function openManualModal(opts) {
  opts = opts || {};
  return uci.load('purewrt').catch(function() { return null; }).then(function() {
    var existing = opts.name ? (uci.sections('purewrt', 'rule_provider') || []).filter(function(s) {
      return s.name === opts.name;
    })[0] : null;
    var bodyPromise = existing ? readBody(opts.name).catch(function() { return ''; }) : Promise.resolve('');
    return bodyPromise.then(function(body) {
      return renderManualForm(opts, existing, body);
    });
  });
}

function renderManualForm(opts, existing, body) {
  var nameInput = E('input', {
    'class': 'cbi-input-text',
    'value': existing ? existing.name : '',
    'placeholder': 'my_block_list',
    'disabled': existing ? 'disabled' : null
  });

  // Build section dropdown from live UCI: the two fixed targets (direct,
  // reject) plus every defined routing section. Mirrors the same logic
  // ruleproviders.js uses for its section dropdown, just kept here so the
  // picker's "+ create new" path doesn't need the caller to pre-fetch.
  var sectionSel = E('select', { 'class': 'cbi-input-select' });
  sectionSel.appendChild(E('option', { 'value': '' }, _('(no override)')));
  var sectionNames = ['direct', 'reject'];
  (uci.sections('purewrt', 'section') || []).forEach(function(s) {
    var n = s.name || s['.name'];
    if (n && sectionNames.indexOf(n) < 0) sectionNames.push(n);
  });
  sectionNames.forEach(function(n) {
    var attrs = { 'value': n };
    if (existing && existing.section === n) attrs.selected = 'selected';
    sectionSel.appendChild(E('option', attrs, n));
  });

  var prioInput = E('input', {
    'class': 'cbi-input-text',
    'value': (existing && existing.priority) || '',
    'placeholder': '1000'
  });
  var textarea = E('textarea', {
    'class': 'cbi-input-textarea',
    'rows': 16,
    'wrap': 'off',
    'spellcheck': 'false',
    'style': 'width:100%;font-family:monospace',
    'placeholder': '# one entry per line — IPs, CIDRs, or FQDNs\n# lines starting with # are comments\nexample.com\nsub.domain.com\n74.125.131.19\n74.125.0.0/16'
  }, body || '');

  // Use LuCI's standard cbi-value row markup so the modal looks the same
  // as the Edit Rule Provider modal that lives next to it — same label
  // column width, same spacing, same input padding.
  function row(label, input, hint) {
    return E('div', { 'class': 'cbi-value' }, [
      E('label', { 'class': 'cbi-value-title' }, label),
      E('div', { 'class': 'cbi-value-field' }, [
        input,
        hint ? E('div', { 'class': 'cbi-value-description' }, hint) : E([])
      ])
    ]);
  }

  var formEl = E('div', {}, [
    row(_('Name'), nameInput, existing
      ? _('Rule provider name is fixed once created. Delete and recreate to rename.')
      : _('Lowercase, letters/digits/dot/hyphen/underscore. Becomes the file name under /etc/purewrt/rulesets/.')),
    row(_('Section'), sectionSel, _('Routing section the matched traffic goes through. Empty means the provider is loaded into mihomo but isn\'t wired into any nftset.')),
    row(_('Conflict priority'), prioInput, _('Lower value wins on conflicts with other providers. Empty = 1000 (default).')),
    row(_('Rules'), textarea, _('One entry per line: IP, CIDR, or FQDN. Full mihomo rule expressions also accepted (DOMAIN-SUFFIX,…). Comments start with <code>#</code>.'))
  ]);

  return new Promise(function(resolve) {
    function save(ev) {
      ev.preventDefault();
      var name = (nameInput.value || '').trim();
      var err = validateName(name);
      if (err) {
        ui.addNotification(null, E('p', err), 'warning');
        return;
      }
      var section = sectionSel.value || '';
      var prio = (prioInput.value || '').trim();
      var bodyOut = textarea.value || '';
      writeBody(name, bodyOut).then(function() {
        writeUCIFor(name, section, prio, true);
        return uci.save();
      }).then(function() {
        return uci.apply();
      }).then(function() {
        return callReload();
      }).then(function() {
        ui.hideModal();
        ui.addNotification(null, E('p', _('Manual rule provider %s saved').format(name)), 'info');
        if (typeof opts.onSave === 'function') opts.onSave(name);
        resolve(name);
      }).catch(function(e) {
        ui.addNotification(null, E('p', _('Save failed: %s').format(e && e.message || e)), 'danger');
      });
    }
    ui.showModal(existing ? _('Edit manual rule provider: %s').format(opts.name) : _('Add manual rule provider'), [
      formEl,
      E('div', { 'class': 'right' }, [
        E('button', { 'class': 'btn', 'click': function(ev) { ev.preventDefault(); ui.hideModal(); resolve(null); } }, _('Cancel')),
        ' ',
        E('button', { 'class': 'btn cbi-button-save', 'click': save }, existing ? _('Save changes') : _('Add'))
      ])
    ]);
  });
}

// openManualPicker — "pick which manual provider to append to" dialog
// used by the blocking + diagnostics CTAs.
//
// IMPORTANT: callers (blocking.js, diagnostics.js) don't necessarily call
// uci.load('purewrt') at view init — they have no other reason to. So
// the picker MUST load UCI itself before listing, or the dropdown would
// always claim "no manual providers yet" even when several exist.
function openManualPicker(opts) {
  opts = opts || {};
  var entry = (opts.entry || '').trim();
  return uci.load('purewrt').catch(function() { return null; }).then(function() {
    return openManualPickerInner(opts, entry);
  });
}

// callIpdbASN is bound lazily so callers without the ipdb feature
// available don't trigger an RPC on every modal open.
var callIpdbASN = null;
function ensureIpdbASNCall() {
  if (!callIpdbASN) {
    callIpdbASN = rpc.declare({ object: 'purewrt', method: 'ipdb_asn', params: [ 'asn' ] });
  }
  return callIpdbASN;
}

// asnComment builds the trailing "# ASxxxxx ORG (CC)" annotation we
// append to entries when the caller has IP-database context. The
// optional `extra` (e.g. "single IP" / "whole-AS member") rides along
// inside the same comment so a user opening the manual file later can
// see at a glance how the line got there. Returns "" when no ASN is
// known so callers always pass through the raw value safely.
function asnComment(asn, asOrg, country, extra) {
  if (!asn) return '';
  var label = 'AS' + asn;
  if (asOrg)   label += ' ' + asOrg;
  if (country) label += ' (' + country + ')';
  if (extra)   label += ' — ' + extra;
  return ' # ' + label;
}

// annotateLine builds the final string written into the manual file:
// raw entry + (optional) inline ASN comment. The text parser strips
// inline `#` comments before parsing the value, so the annotation is
// purely human-facing — provider matching ignores it. Returns the bare
// value untouched when no asn is known (the common case for hostnames
// and for IPs added without the optional ipdb installed).
function annotateLine(value, asn, asOrg, country, extra) {
  var c = asnComment(asn, asOrg, country, extra);
  return c ? value + c : value;
}

function openManualPickerInner(opts, entry) {
  var providers = listManualProviders();

  var pickerSel = E('select', { 'class': 'cbi-input-select', 'style': 'width:20em' });
  if (!providers.length) {
    pickerSel.appendChild(E('option', { 'value': '' }, _('(no manual providers yet — create one below)')));
  } else {
    providers.forEach(function(p) {
      pickerSel.appendChild(E('option', { 'value': p.name }, p.name + (p.section ? ' → ' + p.section : '')));
    });
  }
  pickerSel.appendChild(E('option', { 'value': '__new__' }, _('+ create new manual provider…')));

  var entryInput = E('input', {
    'class': 'cbi-input-text',
    'value': entry,
    'style': 'width:20em'
  });

  // Scope selector: when caller passed ASN context, offer the user a
  // choice between adding just this single entry vs. expanding to every
  // CIDR the ASN owns (via the offline ipdb). Hidden entirely when no
  // ASN is available — keeps the picker visually identical to the old
  // single-entry shape for the common case.
  var asn = parseInt(opts.asn, 10) || 0;
  var asOrg = opts.asOrg || '';
  var scopeRadioEntry, scopeRadioASN, scopeRow;
  if (asn > 0) {
    var scopeName = 'manual-picker-scope-' + Math.random().toString(36).slice(2, 8);
    scopeRadioEntry = E('input', { 'type': 'radio', 'name': scopeName, 'value': 'entry', 'checked': 'checked' });
    scopeRadioASN  = E('input', { 'type': 'radio', 'name': scopeName, 'value': 'asn' });
    var asLabel = 'AS' + asn + (asOrg ? ' · ' + asOrg : '');
    scopeRow = E('div', { 'style': 'display:flex;flex-direction:column;gap:.2em;margin:.4em 0;padding:.4em;border:1px solid #444;border-radius:4px' }, [
      E('label', { 'style': 'cursor:pointer' }, [
        scopeRadioEntry, ' ', _('Add only this entry')
      ]),
      E('label', { 'style': 'cursor:pointer' }, [
        scopeRadioASN, ' ',
        _('Add every CIDR owned by %s (whole-AS routing)').format(asLabel)
      ])
    ]);
  }

  return new Promise(function(resolve) {
    function commit(ev) {
      ev.preventDefault();
      var name = pickerSel.value;
      var line = (entryInput.value || '').trim();
      var wantWholeAS = scopeRadioASN && scopeRadioASN.checked;
      if (!wantWholeAS && !line) {
        ui.addNotification(null, E('p', _('Nothing to add — entry is empty.')), 'warning');
        return;
      }
      // Whole-AS path: fetch the CIDR list from the offline ipdb and use
      // the existing batch-append machinery to write everything to the
      // chosen provider in one transaction. Falls back to single-line
      // append if ipdb returns nothing (DB not installed, ASN unknown).
      if (wantWholeAS) {
        ensureIpdbASNCall()(String(asn)).then(function(res) {
          var prefixes = (res && res.prefixes) || [];
          if (!prefixes.length) {
            ui.addNotification(null, E('p', _('AS%d has no prefixes in the local IP database. Did you run `purewrt ipdb-update`?').format(asn)), 'warning');
            return;
          }
          // Annotate every prefix so the manual file records where each
          // line came from. We trust the AS lookup's own asOrg/country
          // (the response struct populates them from the iptoasn entry)
          // and fall back to the picker-supplied values otherwise.
          var resOrg = (res && res.as_org) || asOrg;
          var resCC  = (res && res.country) || opts.country || '';
          var annotated = prefixes.map(function(p) {
            return annotateLine(p, asn, resOrg, resCC, _('whole-AS'));
          });
          if (name === '__new__' || !name) {
            ui.hideModal();
            openManualModal({
              onSave: function(saved) {
                return appendAll(saved, annotated).then(function(summary) {
                  return callReload().then(function() {
                    resolve({ name: saved, summary: summary, asn: asn, created: true });
                  });
                });
              }
            });
            return;
          }
          appendAll(name, annotated).then(function(summary) {
            ui.hideModal();
            ui.addNotification(null, E('p',
              _('Added %d of %d AS%d prefixes to %s; applying…').format(summary.added, prefixes.length, asn, name)),
              'info');
            return callReload().then(function() {
              resolve({ name: name, summary: summary, asn: asn });
            });
          }).catch(function(e) {
            ui.addNotification(null, E('p', _('Whole-AS append failed: %s').format(e && e.message || e)), 'danger');
          });
        }, function(err) {
          ui.addNotification(null, E('p', _('ipdb-asn lookup failed: %s').format(String(err))), 'danger');
        });
        return;
      }
      // For a single-entry write, annotate with ASN/country only when
      // the caller supplied that context (which means ipdb is installed
      // and the row carried enrichment). Domain entries don't carry
      // ASN data so they pass through untouched.
      var annotatedLine = annotateLine(line, asn, asOrg, opts.country);
      if (name === '__new__' || !name) {
        ui.hideModal();
        openManualModal({
          onSave: function(saved) {
            // After create, append the entry too (it isn't in the freshly
            // saved body if the user didn't paste it into the textarea).
            return appendLine(saved, annotatedLine).then(function() {
              return callReload();
            }).then(function() {
              resolve({ name: saved, line: annotatedLine, created: true });
            });
          }
        });
        return;
      }
      appendLine(name, annotatedLine).then(function(res) {
        ui.hideModal();
        if (res.added) {
          ui.addNotification(null, E('p', _('Added %s to %s; applying…').format(annotatedLine, name)), 'info');
          return callReload().then(function() { resolve({ name: name, line: annotatedLine, created: false }); });
        }
        ui.addNotification(null, E('p', _('%s is already in %s').format(annotatedLine, name)), 'info');
        resolve({ name: name, line: annotatedLine, created: false, duplicate: true });
      }).catch(function(e) {
        ui.addNotification(null, E('p', _('Append failed: %s').format(e && e.message || e)), 'danger');
      });
    }
    function row(label, input) {
      return E('div', { 'style': 'display:flex;align-items:center;gap:.5em;margin:.4em 0' }, [
        E('label', { 'style': 'min-width:10em' }, label),
        input
      ]);
    }
    var children = [
      row(_('Entry'), entryInput),
      row(_('Provider'), pickerSel)
    ];
    if (scopeRow) children.push(scopeRow);
    ui.showModal(_('Add to manual rule provider'), [
      E('div', { 'style': 'min-width:30em' }, children),
      E('div', { 'class': 'right', 'style': 'margin-top:1em' }, [
        E('button', { 'class': 'btn', 'click': function(ev) { ev.preventDefault(); ui.hideModal(); resolve(null); } }, _('Cancel')),
        ' ',
        E('button', { 'class': 'btn cbi-button-save', 'click': commit }, _('Add'))
      ])
    ]);
  });
}

// openManualBatchPicker — pick a provider once, append N entries to it.
// Same shape as openManualPicker but accepts opts.entries (string[]); rejects
// empty input. Used by the Client Traffic page's "Add N selected" button so
// the user can route multiple destinations through one section in one
// gesture instead of opening the single-entry picker N times.
function openManualBatchPicker(opts) {
  opts = opts || {};
  var entries = (opts.entries || []).map(function(e) { return String(e || '').trim(); })
                                    .filter(function(e) { return e !== ''; });
  if (!entries.length) {
    return Promise.reject(new Error(_('No entries selected')));
  }
  // Dedup while preserving caller order.
  var seen = {};
  entries = entries.filter(function(e) { if (seen[e]) return false; seen[e] = 1; return true; });
  return uci.load('purewrt').catch(function() { return null; }).then(function() {
    return openManualBatchPickerInner(opts, entries);
  });
}

function openManualBatchPickerInner(opts, entries) {
  var providers = listManualProviders();
  var pickerSel = E('select', { 'class': 'cbi-input-select', 'style': 'width:20em' });
  if (!providers.length) {
    pickerSel.appendChild(E('option', { 'value': '' }, _('(no manual providers yet — create one below)')));
  } else {
    providers.forEach(function(p) {
      pickerSel.appendChild(E('option', { 'value': p.name }, p.name + (p.section ? ' → ' + p.section : '')));
    });
  }
  pickerSel.appendChild(E('option', { 'value': '__new__' }, _('+ create new manual provider…')));

  // Render the entry list as a read-only block so the user can see exactly
  // what they're committing. Keeping it textual (not editable) — the picker
  // is the wrong place to edit individual entries; if they want to tweak,
  // they cancel and uncheck in the table.
  var entryList = E('ul', { 'style': 'margin:.2em 0 .5em 1em;max-height:14em;overflow-y:auto' });
  entries.forEach(function(e) {
    entryList.appendChild(E('li', { 'style': 'font-family:monospace;font-size:.9em' }, e));
  });

  return new Promise(function(resolve) {
    function commit(ev) {
      ev.preventDefault();
      var name = pickerSel.value;
      if (name === '__new__' || !name) {
        ui.hideModal();
        // Open the create-form, then append everything to the new provider.
        openManualModal({
          onSave: function(saved) {
            return appendAll(saved, entries).then(function(summary) {
              return callReload().then(function() {
                resolve({ name: saved, created: true, summary: summary });
              });
            });
          }
        });
        return;
      }
      appendAll(name, entries).then(function(summary) {
        ui.hideModal();
        var msg = _('Added %d of %d to %s%s; applying…').format(
          summary.added, entries.length, name,
          summary.duplicates ? ' (' + summary.duplicates + ' duplicate)' : '');
        ui.addNotification(null, E('p', msg), 'info');
        return callReload().then(function() {
          resolve({ name: name, created: false, summary: summary });
        });
      }).catch(function(e) {
        ui.addNotification(null, E('p', _('Batch append failed: %s').format(e && e.message || e)), 'danger');
      });
    }
    ui.showModal(_('Add %d entries to manual rule provider').format(entries.length), [
      E('div', { 'style': 'min-width:30em' }, [
        E('div', { 'style': 'margin:.4em 0' }, [
          E('label', { 'style': 'min-width:10em;display:inline-block' }, _('Provider')),
          pickerSel
        ]),
        E('div', { 'style': 'margin:.6em 0 .2em 0' }, _('Entries:')),
        entryList
      ]),
      E('div', { 'class': 'right', 'style': 'margin-top:1em' }, [
        E('button', { 'class': 'btn', 'click': function(ev) { ev.preventDefault(); ui.hideModal(); resolve(null); } }, _('Cancel')),
        ' ',
        E('button', { 'class': 'btn cbi-button-save', 'click': commit }, _('Add all'))
      ])
    ]);
  });
}

// appendAll calls appendLine for each entry sequentially. Sequential, not
// parallel, because they all read-modify-write the same body file —
// concurrent writes would lose entries. Returns a summary so the caller can
// show "Added N of M (K duplicates)" in one notification.
function appendAll(name, entries) {
  var added = 0, duplicates = 0;
  var p = Promise.resolve();
  entries.forEach(function(line) {
    p = p.then(function() {
      return appendLine(name, line).then(function(res) {
        if (res.added) added++;
        else duplicates++;
      });
    });
  });
  return p.then(function() { return { added: added, duplicates: duplicates, total: entries.length }; });
}

return baseclass.extend({
  isManualProvider: isManualProvider,
  listManualProviders: listManualProviders,
  openManualModal: openManualModal,
  openManualPicker: openManualPicker,
  openManualBatchPicker: openManualBatchPicker,
  deleteFile: deleteFile
});
