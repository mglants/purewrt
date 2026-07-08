'use strict';
'require baseclass';
'require rpc';

// Shared start/poll wrapper around any purewrt rpcd method pair that
// follows the `<name>_start` / `<name>_status` convention (update,
// dpi_check, zapret_check at the time of writing). Each long-running CLI
// is forked into the background by rpcd, returns `{result:"started"|"busy"}`
// on start, and exposes `{running, rc, ...}` on status until completion.
//
// Why a shared module: the previous incarnations (update_async.js +
// dpi_check_async.js) differed only by RPC method names, poll cadence,
// and the response payload key. They duplicated ~50 lines each — bug
// fixes (deadline math, initial-poll delay) had to land twice. This
// factory turns each caller into a 6-line wrapper that names the methods
// and inherits the polling logic.
//
// Caller usage:
//   var helper = bgJob.make({
//     startMethod:  'update_start',
//     statusMethod: 'update_status',
//     startParams:  [],          // names of params accepted by `_start`
//     payloadKey:   'output',    // status response field carrying the result blob
//     pollMs:       2000,
//     totalMs:      240000,
//   });
//   helper.run().then(({ok, rc, output}) => ...);
//
// `run()` resolves with `{ok, rc, <payloadKey>}` once the worker reports
// running=0 with a non-empty rc; rejects with `Error('… did not finish
// within Ns')` past the total deadline.
return baseclass.extend({
  make: function(spec) {
    var startParams = spec.startParams || [];
    var startDecl = { object: 'purewrt', method: spec.startMethod };
    if (startParams.length) startDecl.params = startParams;
    var statusDecl = { object: 'purewrt', method: spec.statusMethod };
    var callStart  = rpc.declare(startDecl);
    var callStatus = rpc.declare(statusDecl);
    var payloadKey = spec.payloadKey || 'output';
    var pollMs     = spec.pollMs  || 2000;
    var totalMs    = spec.totalMs || 240000;

    return {
      // run(param..., [onProgress]) — an optional trailing function is a
      // progress callback, invoked on every status poll with
      // {elapsedMs, output} (output = the worker's log tail so far). Lets a
      // view show "what phase is this in / how long has it run" instead of a
      // static "Working…" label while a 2-20 minute job grinds.
      run: function() {
        var args = Array.prototype.slice.call(arguments);
        var onProgress = null;
        if (args.length && typeof args[args.length - 1] === 'function')
          onProgress = args.pop();
        var started = Date.now();
        var deadline = Date.now() + totalMs;
        return callStart.apply(null, args).then(function(r) {
          // Guard the start outcome. A successful launch returns
          // {result:"started"|"busy"}; anything else — a {result:"failed"}
          // arm, or an empty/`null` body from an ubus access-denied (which
          // LuCI resolves rather than rejects, e.g. when the session's ACL
          // predates a new method) — must surface as an error instead of
          // polling a job that never started.
          var startResult = r && r.result;
          if (startResult !== 'started' && startResult !== 'busy') {
            return Promise.reject(new Error(
              spec.startMethod + (startResult ? ' failed: ' + startResult
                : ' returned no result — likely access denied (log out and back in to refresh ACLs)')));
          }
          return new Promise(function(resolve, reject) {
            function tick() {
              if (Date.now() > deadline) {
                reject(new Error(spec.startMethod + ' did not finish within ' + Math.round(totalMs / 1000) + 's'));
                return;
              }
              callStatus().then(function(s) {
                var running = Number(s && s.running);
                var rc = (s && s.rc) || '';
                if (running === 0 && rc !== '') {
                  var result = { ok: rc === '0', rc: rc };
                  result[payloadKey] = (s && s[payloadKey]) || (payloadKey === 'output' ? '' : null);
                  resolve(result);
                } else {
                  if (onProgress) {
                    try {
                      onProgress({ elapsedMs: Date.now() - started, output: (s && s.output) || '' });
                    } catch (e) { /* a broken progress renderer must not kill the poll loop */ }
                  }
                  setTimeout(tick, pollMs);
                }
              }, reject);
            }
            // Small head-start so a fast (cached) job resolves on the
            // first poll instead of bouncing through a full pollMs wait.
            setTimeout(tick, 250);
          });
        });
      }
    };
  }
});
