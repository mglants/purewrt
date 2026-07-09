'use strict';
'require baseclass';

// Shared formatting helpers for the PureWRT views. These were previously
// copy-pasted into general.js, statistics.js and subscriptions.js — bug
// fixes (e.g. the negative-age clamp) had to land three times.

// humanAgo turns a unix timestamp into a "5m"/"2h"/"3d" age string, or
// null when the timestamp is missing.
function humanAgo(unix) {
  if (!unix) return null;
  var ago = Math.max(0, Math.floor(Date.now() / 1000) - Number(unix));
  if (ago < 60) return ago + 's';
  if (ago < 3600) return Math.floor(ago / 60) + 'm';
  if (ago < 86400) return Math.floor(ago / 3600) + 'h';
  return Math.floor(ago / 86400) + 'd';
}

// humanUptime turns a duration in seconds into a "2d 4h" / "3h 12m" /
// "47s" string. Used for service uptime + cron-next-run formatting.
function humanUptime(sec) {
  sec = Math.max(0, Math.floor(Number(sec || 0)));
  if (sec < 60) return sec + 's';
  if (sec < 3600) return Math.floor(sec / 60) + 'm ' + (sec % 60) + 's';
  if (sec < 86400) return Math.floor(sec / 3600) + 'h ' + Math.floor((sec % 3600) / 60) + 'm';
  return Math.floor(sec / 86400) + 'd ' + Math.floor((sec % 86400) / 3600) + 'h';
}

// pill returns a compact coloured chip span using the shared purewrt-pill
// classes from purewrt.styles (the importing view must also require it).
function pill(text, variant) {
  return E('span', { 'class': 'purewrt-pill purewrt-pill-' + (variant || 'muted'), 'style': 'min-width:auto;padding:1px 8px;font-size:.85em' }, text);
}

// spinner returns a rotating-spinner loading line (LuCI's stock .spinning class
// + our dim styling). Use while an async action runs, then replace it with the
// result. Centralises the pattern previously inlined across the views.
function spinner(text) {
  return E('em', { 'class': 'purewrt-text-dim spinning' }, text || _('Working…'));
}

// errorDetails renders a failure notification body: a one-line summary plus
// the FULL command output behind a collapsible <details>, instead of the old
// .slice(0, 400) truncation that hid the root cause (the interesting error is
// usually at the end of a long apply log, forcing users into SSH + syslog).
function errorDetails(summary, output) {
  var body = [E('p', {}, summary)];
  output = String(output || '').trim();
  if (output) {
    body.push(E('details', { 'style': 'margin-top:6px' }, [
      E('summary', { 'style': 'cursor:pointer' }, _('Show full output')),
      E('pre', { 'style': 'max-height:24em;overflow:auto;white-space:pre-wrap;font-size:.85em;margin-top:4px' }, output)
    ]));
  }
  return E('div', {}, body);
}

// Form validators, shared by the settings/subscriptions/sections views.
// Each returns true or a translated error string — the shape LuCI's
// AbstractValue.validate expects — so a typo is rejected at input time
// instead of surfacing minutes later as a cryptic apply-log line.

// validateCron accepts a 5-field busybox-crond expression (numeric fields
// with * , - / — crond on OpenWrt has no @daily or name aliases).
function validateCron(sid, v) {
  if (!v) return true;
  var fields = v.trim().split(/\s+/);
  if (fields.length !== 5)
    return _('Expected 5 cron fields (minute hour day month weekday), got %d').format(fields.length);
  var part = /^(\*|\d+(-\d+)?)(\/\d+)?$/;
  for (var i = 0; i < 5; i++) {
    var ok = fields[i].split(',').every(function(p) { return part.test(p); });
    if (!ok) return _('Invalid cron field "%s" — use numbers with * , - /').format(fields[i]);
  }
  return true;
}

// validateHTTPURL accepts empty (use default) or an absolute http(s) URL.
function validateHTTPURL(sid, v) {
  if (!v) return true;
  if (!/^https?:\/\/\S+$/i.test(v.trim()))
    return _('Must be an absolute http:// or https:// URL');
  return true;
}

// validateCIDR accepts a bare IP or CIDR, v4 or v6.
function validateCIDR(v) {
  if (!v) return _('Enter an IP or CIDR.');
  var m = v.trim().match(/^(.+?)(?:\/(\d{1,3}))?$/);
  var addr = m[1], plen = m[2];
  var v6 = addr.indexOf(':') >= 0;
  if (v6) {
    if (!/^[0-9a-f:]+$/i.test(addr) || addr.indexOf('::') !== addr.lastIndexOf('::'))
      return _('"%s" is not a valid IPv6 address').format(addr);
    if (plen !== undefined && +plen > 128) return _('IPv6 prefix length must be 0-128');
  } else {
    var oct = addr.split('.');
    if (oct.length !== 4 || !oct.every(function(o) { return /^\d{1,3}$/.test(o) && +o <= 255; }))
      return _('"%s" is not a valid IPv4 address').format(addr);
    if (plen !== undefined && +plen > 32) return _('IPv4 prefix length must be 0-32');
  }
  return true;
}

return baseclass.extend({
  humanAgo: humanAgo,
  humanUptime: humanUptime,
  pill: pill,
  spinner: spinner,
  errorDetails: errorDetails,
  validateCron: validateCron,
  validateHTTPURL: validateHTTPURL,
  validateCIDR: validateCIDR
});
