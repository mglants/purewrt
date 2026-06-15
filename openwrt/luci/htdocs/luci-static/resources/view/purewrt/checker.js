'use strict';
'require view';
'require rpc';
'require form';
'require ui';

var callCheck = rpc.declare({ object: 'purewrt', method: 'check', params: [ 'domain' ] });
return view.extend({ render: function() { var input = E('input', { 'class': 'cbi-input-text', 'placeholder': 'chatgpt.com' }); var out = E('pre', {}); return E('div', { 'class': 'cbi-map' }, [ E('h2', _('PureWRT Site Checker')), input, E('button', { 'class': 'btn cbi-button cbi-button-apply', 'click': function(){ return callCheck(input.value).then(function(r){ out.textContent = r.output || JSON.stringify(r, null, 2); }).catch(function(e){ ui.addNotification(null, E('p', e.message), 'danger'); }); } }, _('Check')), out ]); } });
