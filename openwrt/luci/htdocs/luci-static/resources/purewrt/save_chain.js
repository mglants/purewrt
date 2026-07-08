'use strict';
'require baseclass';
'require ui';
'require purewrt.format as fmt';

// Shared "Save & Apply" chain for LuCI forms. Several views (Zapret,
// Subscriptions, Proxy Providers) need the same shape: persist UCI, then
// run one or more async steps (update / reload / restart), then notify
// the user on success or failure. Each save chain previously inlined the
// promise-then-promise-then-catch tower with the same boilerplate; this
// helper centralises:
//
//   1. m.save() must be the first promise — its failure is form
//      validation or UCI write failure and deserves its own user-visible
//      notification (was missing entirely on Zapret, silently swallowed
//      on Subscriptions / Proxy Providers).
//   2. Subsequent steps are arbitrary functions returning Promises. Each
//      step's result is passed to the next; a returned `{result:"failed",
//      output:"…"}` envelope from rpcd is surfaced as a 'danger' toast and
//      does NOT abort the chain (we still want to attempt the apply even
//      if the upstream update timed out).
//   3. Final success message is fired exactly once at the end of the
//      chain. Failure messages are fired inline as each step rejects.
//
// Usage:
//   saveChain.run(m, [
//     { fn: updateAsync.run, label: _('Provider update') },
//     { fn: callReload,       label: _('Apply') },
//   ], { onDone: _('Saved, updated and applied.') });

return baseclass.extend({
  run: function(map, steps, opts) {
    opts = opts || {};
    var doneMsg = opts.onDone || _('Saved.');
    var savingMsg = opts.onSaving;

    return map.save().then(function() {
      if (savingMsg) ui.addNotification(null, E('p', savingMsg), 'info');
      // Run steps in sequence, surfacing per-step failures without
      // aborting the chain (mirrors the existing inline behaviour where
      // a failed update still falls through to try the reload).
      var p = Promise.resolve(null);
      (steps || []).forEach(function(step) {
        p = p.then(function() {
          return step.fn().then(function(r) {
            // Two shapes appear in practice: {ok, rc, output} from the
            // bg_job async helpers, and {result:"ok"|"failed", output}
            // from rpcd-wrapped CLI calls.
            if (r && r.ok === false) {
              ui.addNotification(null,
                fmt.errorDetails(_('%s failed (rc=%s)').format(step.label, r.rc), r.output),
                'danger');
            } else if (r && r.result === 'failed') {
              ui.addNotification(null,
                fmt.errorDetails(_('%s failed').format(step.label), r.output),
                'danger');
            }
            return r;
          }, function(err) {
            ui.addNotification(null,
              E('p', _('%s timed out: %s').format(step.label, err && err.message ? err.message : String(err))),
              'danger');
            // Resolve to null so the chain continues — most callers want
            // to attempt later steps even if an earlier one stalled.
            return null;
          });
        });
      });
      return p.then(function() {
        ui.addNotification(null, E('p', doneMsg), 'info');
      });
    }).catch(function(err) {
      // m.save() rejection means form validation or UCI write failure.
      // The inner chain catches its own per-step errors, so anything
      // landing here is the save itself.
      ui.addNotification(null,
        E('p', _('Save failed: %s').format(err && err.message ? err.message : String(err))),
        'danger');
    });
  }
});
