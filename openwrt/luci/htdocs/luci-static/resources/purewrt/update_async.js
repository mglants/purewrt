'use strict';
'require baseclass';
'require purewrt.bg_job as bgJob';

// Thin wrapper around `purewrt update` via the shared bg_job factory. The
// interesting bits — start/poll dance, deadline handling, initial-poll
// head-start — live in resources/purewrt/bg_job.js. See that file for the
// reasoning; what's left here is just the per-method config: which rpcd
// names to call, how often to poll (2s — update output streams fast), and
// the deadline (4 min — first-time subscription downloads can be slow on
// a fresh router, faster on day-2).
var helper = bgJob.make({
  startMethod:  'update_start',
  statusMethod: 'update_status',
  payloadKey:   'output',
  pollMs:       2000,
  totalMs:      240000,
});

return baseclass.extend({
  run: function(options) {
    // Accept the legacy `{pollMs, totalMs}` overrides for backwards-compat
    // with any caller that imported the old singleton helper. Empty/missing
    // options just falls through to the bg_job defaults.
    if (options && (options.pollMs || options.totalMs)) {
      var override = bgJob.make({
        startMethod:  'update_start',
        statusMethod: 'update_status',
        payloadKey:   'output',
        pollMs:       options.pollMs  || 2000,
        totalMs:      options.totalMs || 240000,
      });
      return override.run();
    }
    return helper.run();
  }
});
