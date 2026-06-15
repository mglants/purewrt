'use strict';
'require baseclass';
'require purewrt.bg_job as bgJob';

// Thin wrapper around `purewrt dpi-check` via the shared bg_job factory.
// Slower poll (3s) than `update_async` because the TCP-16-20 matrix
// progresses in larger chunks; longer deadline (5 min) because the worst
// case for a 30-host matrix on a slow uplink can stretch close to that.
// The dpi-check status response carries the parsed JSON report in the
// `report` field instead of `output`.
var helper = bgJob.make({
  startMethod:  'dpi_check_start',
  statusMethod: 'dpi_check_status',
  startParams:  [ 'host', 'ip', 'timeout' ],
  payloadKey:   'report',
  pollMs:       3000,
  totalMs:      300000,
});

return baseclass.extend({
  run: function(opts) {
    opts = opts || {};
    if (!opts.host) return Promise.reject(new Error('host required'));
    return helper.run(opts.host, opts.ip || '', String(opts.timeout || ''));
  }
});
