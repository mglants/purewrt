'use strict';
'require baseclass';
'require purewrt.bg_job as bgJob';

// Thin wrapper around `purewrt net-check` via the shared bg_job factory.
// The probe drives a real download/upload through the proxy (plus optional
// per-node sweep), so it runs longer than a status call — 3s poll, 5 min
// deadline. The status response carries the parsed JSON report in `report`.
var helper = bgJob.make({
  startMethod:  'net_check_start',
  statusMethod: 'net_check_status',
  startParams:  [ 'bytes', 'per_node' ],
  payloadKey:   'report',
  pollMs:       3000,
  totalMs:      300000,
});

return baseclass.extend({
  run: function(opts) {
    opts = opts || {};
    return helper.run(String(opts.bytes || ''), opts.perNode ? '1' : '');
  }
});
