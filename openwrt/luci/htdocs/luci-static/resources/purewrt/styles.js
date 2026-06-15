'use strict';
'require baseclass';

// Shared PureWRT palette + utility classes, injected as a <style> element
// on first import. Views that `'require purewrt.styles'` get the palette
// loaded for free and can apply CSS classes like `.purewrt-pill-ok`
// instead of repeating `'style': 'background:#5cb85c;color:white;…'`.
//
// LuCI doesn't currently have a clean "load app stylesheet via <link>"
// pattern for non-resource paths, so we self-inject. Idempotent: the
// styles are appended exactly once per page lifetime.

var CSS = [
  // pills (background-coloured rounded chips, used for verdicts)
  '.purewrt-pill{color:#fff;padding:3px 10px;border-radius:10px;font-family:monospace;font-size:.85em;display:inline-block;min-width:8em;text-align:center}',
  '.purewrt-pill-ok{background:#5cb85c}',
  '.purewrt-pill-danger{background:#d9534f}',
  '.purewrt-pill-warn{background:#f0ad4e}',
  '.purewrt-pill-info{background:#5bc0de}',
  '.purewrt-pill-muted{background:#888}',
  // confidence badges (smaller outline-only chip)
  '.purewrt-confidence{padding:1px 6px;border-radius:6px;font-size:.75em;font-family:monospace;border:1px solid currentColor}',
  '.purewrt-confidence-high{color:#5cb85c}',
  '.purewrt-confidence-medium{color:#f0ad4e}',
  '.purewrt-confidence-low{color:#888}',
  // banners (verdict strip across the top of a card)
  '.purewrt-banner{color:#fff;padding:.8em 1em;border-radius:4px;margin-bottom:1em}',
  '.purewrt-banner-ok{background:#5cb85c}',
  '.purewrt-banner-danger{background:#d9534f}',
  '.purewrt-banner-warn{background:#f0ad4e}',
  '.purewrt-banner-muted{background:#888}',
  '.purewrt-banner-sub{font-size:.85em;margin-top:.25em;opacity:.95}',
  // inline text emphasis
  '.purewrt-text-danger{color:#d9534f}',
  '.purewrt-text-warn{color:#f0ad4e}',
  '.purewrt-text-success{color:#5cb85c}',
  '.purewrt-text-muted{color:#888}',
  '.purewrt-text-dim{color:#666;font-size:.85em}',
  // section card — visual grouping around a chunk of related content.
  // Subtle border + slight background so adjacent sections don't blur
  // together visually when they all live in the same flat cbi-map.
  '.purewrt-card{border:1px solid var(--border-color-low,#333);background:var(--background-color-high,rgba(255,255,255,0.02));border-radius:6px;padding:1em 1.2em;margin:1em 0}',
  '.purewrt-card h3,.purewrt-card h4{margin-top:0}',
  // stat-card grid — flex row of label/big-number readouts.
  '.purewrt-stat-grid{display:flex;gap:1.5em;flex-wrap:wrap;align-items:flex-end;margin:.5em 0 .25em}',
  '.purewrt-stat-label{color:#888;font-size:.8em;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.15em}',
  '.purewrt-stat-value{font-family:monospace;font-size:1.4em;line-height:1.1;white-space:nowrap}',
  '.purewrt-stat-up{color:#5cb85c}',
  '.purewrt-stat-down{color:#5bc0de}',
  // sparkline + its placeholder shimmer
  '.purewrt-sparkline-wrap{position:relative;display:inline-block;margin-top:.5em}',
  '.purewrt-sparkline-empty{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:#666;font-size:.85em;pointer-events:none}',
  // kv pairs — replaces noisy 2-col "Metric/Value" table.
  '.purewrt-kv{display:grid;grid-template-columns:max-content 1fr;column-gap:1.5em;row-gap:.35em;margin:.25em 0;max-width:32em}',
  '.purewrt-kv dt{color:#888;font-size:.9em}',
  '.purewrt-kv dd{margin:0;font-family:monospace;font-size:.95em}',
  // styled table — zebra rows, hover, right-aligned numeric column.
  '.purewrt-table{width:100%;border-collapse:collapse;margin:.25em 0}',
  '.purewrt-table th{text-align:left;padding:.4em .6em;border-bottom:1px solid var(--border-color-medium,#333);color:#aaa;font-size:.85em;text-transform:uppercase;letter-spacing:.03em;font-weight:600}',
  '.purewrt-table td{padding:.35em .6em;border-bottom:1px solid var(--border-color-low,rgba(255,255,255,0.04))}',
  '.purewrt-table tr:hover td{background:rgba(255,255,255,0.03)}',
  '.purewrt-table .num{text-align:right;font-family:monospace;font-variant-numeric:tabular-nums}',
  '.purewrt-table .err{color:#d9534f;font-size:.85em}',
  '.purewrt-table .muted{color:#666}',
  // compact details/summary for collapsible per-set blocks
  'details.purewrt-collapse{margin:.5em 0;border:1px solid var(--border-color-low,#333);border-radius:4px;padding:0}',
  'details.purewrt-collapse > summary{cursor:pointer;padding:.5em .8em;background:rgba(255,255,255,0.02);font-weight:600;list-style:none}',
  'details.purewrt-collapse > summary::-webkit-details-marker{display:none}',
  'details.purewrt-collapse > summary::before{content:"▸";display:inline-block;margin-right:.5em;color:#888;transition:transform .15s}',
  'details.purewrt-collapse[open] > summary::before{transform:rotate(90deg)}',
  'details.purewrt-collapse[open] > summary{border-bottom:1px solid var(--border-color-low,#333)}',
  'details.purewrt-collapse > .purewrt-collapse-body{padding:.5em .8em}',
  // wizard routing board — stacked full-width section lanes; rule cards live
  // inside the lane they're routed to and are dragged (pointer-based) between
  // lanes. (kanban-ish: lane = section column, card = rule.)
  // draggable rule card (a rule provider / default list) — a prominent token
  '.purewrt-chip{display:inline-flex;align-items:center;gap:.4em;padding:.3em .55em;border:1px solid var(--border-color-medium,#555);border-radius:6px;background:rgba(255,255,255,0.08);box-shadow:0 1px 2px rgba(0,0,0,.25);cursor:grab;touch-action:none;user-select:none;-webkit-user-select:none;max-width:18em}',
  '.purewrt-chip:hover{border-color:var(--color-primary,#00a8e8)}',
  '.purewrt-chip:active{cursor:grabbing}',
  '.purewrt-chip-handle{color:var(--color-primary,#00a8e8);user-select:none;font-size:1.05em}',
  '.purewrt-chip-name{font-family:monospace;font-size:.9em;flex:1 1 auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
  '.purewrt-chip-inactive{opacity:.55;background:rgba(255,255,255,0.02);border-style:dashed}',
  '.purewrt-chip-dragging{opacity:.35}',
  // the ghost element that follows the pointer during a drag
  '.purewrt-drag-ghost{position:fixed;z-index:9999;pointer-events:none;opacity:.9;box-shadow:0 4px 14px rgba(0,0,0,.45);background:var(--background-color-high,#222);border:1px solid var(--color-primary,#00a8e8);border-radius:6px;padding:.3em .5em;font-family:monospace;font-size:.9em}',
  // section lane (a drop target) — left accent colored by protocol so sections
  // are visually distinct at a glance.
  '.purewrt-lane{border:1px solid var(--border-color-low,#333);border-left:4px solid #888;border-radius:6px;padding:.5em .7em;margin:.5em 0;background:rgba(255,255,255,0.02);transition:border-color .12s,background .12s}',
  '.purewrt-lane-proxy{border-left-color:#5bc0de}',
  '.purewrt-lane-direct{border-left-color:#5cb85c}',
  '.purewrt-lane-reject{border-left-color:#d9534f}',
  '.purewrt-lane-vpn{border-left-color:#9b59b6}',
  '.purewrt-lane-zapret{border-left-color:#f0ad4e}',
  '.purewrt-lane-skip{border-left-color:#666;opacity:.92}',
  '.purewrt-lane-head{display:flex;align-items:center;gap:.5em;margin-bottom:.35em}',
  '.purewrt-lane-name{font-weight:600}',
  '.purewrt-lane-count{font-size:.78em;color:#aaa;background:rgba(127,127,127,.18);border-radius:10px;padding:0 .55em}',
  '.purewrt-lane.drag-over{border-color:var(--color-primary,#00a8e8);background:rgba(0,168,232,0.10);box-shadow:0 0 0 1px var(--color-primary,#00a8e8) inset}',
  // outlined "Rules" region inside a lane so rule→section grouping is obvious
  '.purewrt-rules-box{margin-top:.4em;border:1px solid var(--border-color-low,#3a3a3a);border-radius:6px;background:rgba(0,0,0,.15);padding:.3em .45em}',
  '.purewrt-rules-cap{font-size:.72em;text-transform:uppercase;letter-spacing:.04em;color:#888;margin-bottom:.3em}',
  '.purewrt-lane-cards{display:flex;flex-wrap:wrap;gap:.4em;min-height:1.6em}',
  '.purewrt-lane-members{display:flex;flex-wrap:wrap;gap:.3em;margin-top:.35em}',
  '.purewrt-lane-empty{display:flex;align-items:center;justify-content:center;width:100%;min-height:2.2em;color:#666;font-size:.85em;font-style:italic;border:1px dashed var(--border-color-low,#444);border-radius:6px}',
  '.purewrt-server-chip{display:inline-block;margin:0 .35em .25em 0;padding:.05em .4em;border-radius:.3em;background:rgba(127,127,127,.15);font-size:.85em}',
].join('');

var INJECTED_ATTR = 'data-purewrt-styles';

function inject() {
  if (typeof document === 'undefined') return;
  if (document.head && document.head.querySelector('style[' + INJECTED_ATTR + ']')) return;
  var s = document.createElement('style');
  s.setAttribute(INJECTED_ATTR, '1');
  s.textContent = CSS;
  (document.head || document.body).appendChild(s);
}

inject();

return baseclass.extend({
  // Re-export for callers that want to ensure the styles are present (e.g.
  // in tests or in views loaded out-of-order). Calling more than once is
  // safe — the attr-check above dedupes.
  inject: inject
});
