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

return baseclass.extend({
  humanAgo: humanAgo,
  humanUptime: humanUptime,
  pill: pill
});
