'use strict';
'require view';
'require rpc';
'require ui';

var callCheck = rpc.declare({ object: 'purewrt', method: 'check', params: [ 'domain', 'protocol', 'port', 'wan' ] });
return view.extend({
  render: function() {
    var input = E('input', { 'class': 'cbi-input-text', 'placeholder': _('Domain or IP address') });
    var protocol = E('select', { 'class': 'cbi-input-select' }, [
      E('option', { value: '' }, _('Protocol unspecified')),
      E('option', { value: 'tcp' }, 'TCP'),
      E('option', { value: 'udp' }, 'UDP')
    ]);
    var port = E('input', { type: 'number', min: '1', max: '65535', 'class': 'cbi-input-text', placeholder: _('Destination port (optional)') });
    var wan = E('input', { 'class': 'cbi-input-text', placeholder: _('Outgoing WAN device (optional, e.g. eth1)') });
    var out = E('pre', { style: 'white-space:pre-wrap' });
    var button = E('button', {
      'class': 'btn cbi-button cbi-button-apply',
      click: function() {
        if (!input.value.trim() || (port.value && (!port.checkValidity() || !Number.isInteger(Number(port.value))))) {
          ui.addNotification(null, E('p', _('Enter a destination and a valid port between 1 and 65535.')), 'warning');
          return;
        }
        button.disabled = true;
        return callCheck(input.value.trim(), protocol.value, port.value, wan.value.trim()).then(function(r) {
          out.textContent = r.output || JSON.stringify(r, null, 2);
        }).catch(function(e) {
          ui.addNotification(null, E('p', e.message), 'danger');
        }).finally(function() { button.disabled = false; });
      }
    }, _('Check'));
    return E('div', { 'class': 'cbi-map' }, [
      E('h2', _('PureWRT Site Checker')),
      E('p', _('Check destination-rule priority and fallthrough. Provide protocol and port for a specific flow; Zapret also needs the outgoing WAN device. Client assignments and existing connection state are not simulated.')),
      E('div', { style: 'display:flex;flex-wrap:wrap;gap:.7em' }, [
        E('label', {}, [ _('Destination'), input ]),
        E('label', {}, [ _('Protocol'), protocol ]),
        E('label', {}, [ _('Port'), port ]),
        E('label', {}, [ _('WAN device'), wan ]),
        button
      ]), out
    ]);
  }
});
