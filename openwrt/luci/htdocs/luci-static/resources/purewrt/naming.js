'use strict';
'require baseclass';
'require uci';
'require ui';

// Type-scoped UCI section-id prefixes — MUST mirror internal/config/write.go.
// libuci section ids share one namespace per config file across all types,
// and `uci set purewrt.<existing>=<othertype>` silently RETYPES the existing
// section instead of erroring. Prefixing the id per type (sec_youtube /
// rp_youtube / zs_youtube) lets the same display name exist on every type
// while making cross-type id collisions structurally impossible.

var PREFIX = {
  section: 'sec_',
  subscription: 'sub_',
  proxy_provider: 'pp_',
  rule_provider: 'rp_',
  vpn: 'vpn_',
  zapret_profile: 'zp_',
  zapret_strategy: 'zs_'
};

// displayName recovers the user-facing name for a section id: explicit
// `option name` wins (legacy anonymous form), otherwise the type prefix is
// stripped. Legacy unprefixed named ids pass through unchanged. Returns
// null for anonymous cfgXXXXXX ids with no name option, so callers can
// substitute their own placeholder.
function displayName(sid, type) {
  var name = uci.get('purewrt', sid, 'name');
  if (name) return name;
  if (!sid || /^cfg[0-9a-f]{6}/.test(sid)) return null;
  var prefix = PREFIX[type] || '';
  if (prefix && sid.indexOf(prefix) === 0 && sid.length > prefix.length)
    return sid.substring(prefix.length);
  return sid;
}

// installPrefixedAdd wraps a TypedSection's handleAdd so the user types the
// bare name and the stored id gets the type prefix. Rejects ids already
// present in the config (any type — see the retype hazard above) and names
// that aren't valid UCI identifiers. `validate(name)` may return an error
// string for extra per-view rules (e.g. mihomo-reserved names).
function installPrefixedAdd(s, type, validate) {
  var prefix = PREFIX[type] || '';
  var origHandleAdd = s.handleAdd;
  s.handleAdd = function(ev, name) {
    if (!name || !/^[A-Za-z0-9_]+$/.test(name)) {
      ui.addNotification(null, E('p', _('Name must use letters, digits and underscore only')), 'warning');
      return Promise.resolve();
    }
    if (validate) {
      var err = validate(name);
      if (err) {
        ui.addNotification(null, E('p', err), 'warning');
        return Promise.resolve();
      }
    }
    var sid = prefix + name;
    if (uci.get('purewrt', sid)) {
      ui.addNotification(null, E('p', _('"%s" is already used by another entry').format(name)), 'warning');
      return Promise.resolve();
    }
    return origHandleAdd.call(this, ev, sid);
  };
}

// nameOf derives the display name from a uci.sections() object — the
// `s.name || s['.name']` pattern predating prefixed ids, which would show
// (and cross-reference!) raw sec_/rp_/zs_ ids once the Go serializer stops
// emitting `option name`. Cross-references between config sections (a
// routing section's zapret_strategy list, a rule provider's section) match
// on display NAMES, never on section ids.
function nameOf(sec, type) {
  if (!sec) return null;
  return sec.name || displayName(sec['.name'], type);
}

// sidOf resolves a display name back to the UCI section id within a type —
// for code that mutates sections it only knows by name (wizard routing).
function sidOf(type, name) {
  var out = null;
  (uci.sections('purewrt', type) || []).forEach(function(s) {
    if (!out && nameOf(s, type) === name) out = s['.name'];
  });
  return out;
}

return baseclass.extend({
  PREFIX: PREFIX,
  displayName: displayName,
  nameOf: nameOf,
  sidOf: sidOf,
  installPrefixedAdd: installPrefixedAdd
});
