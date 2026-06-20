'use strict';
'require view';
'require form';
'require rpc';
'require ui';
'require uci';

// OONI Probe page. ooniprobe is an optional 25.12-only companion package, so
// the page gates on ooni_installed and renders a placeholder when absent
// (same pattern as the Zapret page). The form edits the `config ooni` UCI
// section; the routing split (API via mihomo mixed-port, measurements direct)
// is enforced by PureWRT's nft skuid exemption + the --proxy run flag, not by
// anything on this page.
var callOONIInstalled = rpc.declare({ object: 'purewrt', method: 'ooni_installed', expect: { installed: false } });
var callOONIStatus = rpc.declare({ object: 'purewrt', method: 'ooni_status' });
var callOONIRunStart = rpc.declare({ object: 'purewrt', method: 'ooni_run_start' });
var callOONIRunStatus = rpc.declare({ object: 'purewrt', method: 'ooni_run_status', params: [] });

function notInstalled() {
  return E('div', { 'class': 'cbi-section' }, [
    E('h2', {}, _('OONI Probe')),
    E('div', { 'class': 'alert-message warning' }, [
      E('p', {}, _('The ooniprobe package is not installed. OONI Probe is an optional companion that requires OpenWrt 25.12 or newer (it needs Go 1.24, which the 24.10 SDK does not ship). Install the ooniprobe package to enable censorship measurements.'))
    ])
  ]);
}

return view.extend({
  load: function() {
    return Promise.all([
      callOONIInstalled().catch(function() { return false; }),
      uci.load('purewrt')
    ]);
  },

  render: function(data) {
    var installed = !!(data && data[0]);
    if (!installed) {
      return notInstalled();
    }

    // Ensure the named `ooni` section exists so the form binds + saves.
    if (!uci.get('purewrt', 'ooni')) {
      uci.add('purewrt', 'ooni', 'ooni');
    }

    var m = new form.Map('purewrt', _('OONI Probe'),
      _('Run OONI censorship measurements on a schedule. The probe reaches the OONI backend (check-in, upload) through mihomo\'s mixed-port, while the measurements themselves go directly over your real network — so results reflect actual local conditions.'));

    var s = m.section(form.NamedSection, 'ooni', 'ooni');
    s.anonymous = true;

    var o;
    o = s.option(form.Flag, 'enabled', _('Enable'),
      _('Install a cron entry that runs OONI measurements as the unprivileged ooniprobe user.'));
    o.rmempty = false;

    o = s.option(form.Flag, 'upload', _('Upload results'),
      _('Submit measurements to OONI\'s public archive (OONI Explorer). Measurements are public and tied to your network ASN/country. Disable to run locally without uploading.'));
    o.depends('enabled', '1');
    o.rmempty = false;

    o = s.option(form.Value, 'schedule', _('Schedule (cron)'),
      _('Cron expression for the run. Default hourly.'));
    o.placeholder = '0 * * * *';
    o.depends('enabled', '1');

    o = s.option(form.Value, 'proxy', _('Backend proxy'),
      _('Proxy ooniprobe uses to reach the OONI backend (passed as --proxy). Defaults to mihomo\'s mixed-port. This does NOT proxy measurements.'));
    o.placeholder = 'socks5://127.0.0.1:7890';
    o.depends('enabled', '1');

    o = s.option(form.Value, 'home', _('Home directory (OONI_HOME)'),
      _('Where config.json + the measurement DB live. Defaults to tmpfs (cleared on reboot, regenerated each run).'));
    o.placeholder = '/tmp/ooni';
    o.depends('enabled', '1');

    return m.render().then(function(formEl) {
      return E('div', {}, [ formEl, renderRunPanel() ]);
    });
  }
});

function renderRunPanel() {
  var out = E('pre', { 'style': 'white-space:pre-wrap;max-height:24em;overflow:auto' }, _('Idle.'));
  var pollTimer = null;

  function stop() { if (pollTimer) { window.clearTimeout(pollTimer); pollTimer = null; } }

  function poll() {
    return callOONIRunStatus().then(function(r) {
      if (r && typeof r.output === 'string' && r.output.length) {
        out.textContent = r.output;
      }
      var running = r && (r.running === 1 || r.running === true);
      if (running) {
        pollTimer = window.setTimeout(poll, 2000);
      } else if (r && r.rc && r.rc !== '0') {
        ui.addNotification(null, E('p', _('OONI run exited with an error. See output above.')), 'warning');
      }
    }).catch(function(e) { stop(); ui.addNotification(null, E('p', e.message), 'danger'); });
  }

  var runBtn = E('button', { 'class': 'btn cbi-button cbi-button-action' }, _('Run now'));
  runBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    stop();
    out.textContent = _('Starting OONI run…');
    return callOONIRunStart().then(function(r) {
      if (r && r.result === 'busy') {
        ui.addNotification(null, E('p', _('An OONI run is already in progress. Showing its output.')), 'warning');
      }
      return poll();
    }).catch(function(e) { stop(); ui.addNotification(null, E('p', e.message), 'danger'); });
  });

  return E('div', { 'class': 'cbi-section' }, [
    E('h3', {}, _('On-demand run')),
    E('p', {}, _('Trigger a measurement now (runs as the ooniprobe user, same as the scheduled run).')),
    E('div', { 'style': 'margin-bottom:1em' }, [ runBtn ]),
    out
  ]);
}
