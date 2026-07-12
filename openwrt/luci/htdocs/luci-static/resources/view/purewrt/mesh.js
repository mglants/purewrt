'use strict';
'require view';
'require rpc';
'require ui';
'require poll';
'require purewrt.bg_job as bgJob';
'require purewrt.format as fmt';
'require purewrt.styles';

// Friend Mesh page. easytier is an optional companion package (like zapret /
// ooniprobe), so the page gates on mesh_installed and renders an install
// hint when absent. Everything else is CLI-backed via rpcd: no CBI map —
// the mesh section is managed by mesh-init/join/leave/rotate, not by
// field-level edits.
var callInstalled = rpc.declare({ object: 'purewrt', method: 'mesh_installed', expect: { installed: false } });
var callStatus = rpc.declare({ object: 'purewrt', method: 'mesh_status' });
var callDiagnostics = rpc.declare({ object: 'purewrt', method: 'mesh_diagnostics' });
var callInit = rpc.declare({ object: 'purewrt', method: 'mesh_init', params: [ 'name' ] });
var callLeave = rpc.declare({ object: 'purewrt', method: 'mesh_leave' });
var callCode = rpc.declare({ object: 'purewrt', method: 'mesh_code' });
var callRotate = rpc.declare({ object: 'purewrt', method: 'mesh_rotate' });
var callPeerSet = rpc.declare({ object: 'purewrt', method: 'mesh_peer_set', params: [ 'name', 'enabled' ] });
var callPeerRemove = rpc.declare({ object: 'purewrt', method: 'mesh_peer_remove', params: [ 'name' ] });

var joinJob = bgJob.make({
  startMethod: 'mesh_join_start',
  statusMethod: 'mesh_join_status',
  startParams: [ 'code', 'name' ],
  pollMs: 2000,
  totalMs: 180000
});
var syncJob = bgJob.make({
  startMethod: 'mesh_sync_start',
  statusMethod: 'mesh_sync_status',
  startParams: [],
  pollMs: 2000,
  totalMs: 120000
});

function notInstalled() {
  return E('div', { 'class': 'cbi-section' }, [
    E('h2', {}, _('Friend Mesh')),
    E('div', { 'class': 'alert-message warning' }, [
      E('p', {}, _('The easytier package is not installed. Friend Mesh links your router with friends\' PureWRT routers over an encrypted P2P overlay: when your own proxies get blocked, traffic fails over to a friend\'s working proxies (never their home IP). Install the easytier package from the PureWRT feed to enable it.'))
    ])
  ]);
}

// showCodeModal displays a freshly minted / reprinted sync-code with a copy
// button and the password warning — the code IS the group credential.
function showCodeModal(title, code, network) {
  var codeBox = E('textarea', {
    'class': 'cbi-input-textarea',
    'style': 'width:100%;height:6em;font-family:monospace',
    'readonly': 'readonly'
  }, code);
  var copyBtn = E('button', { 'class': 'btn cbi-button cbi-button-action' }, _('Copy to clipboard'));
  copyBtn.addEventListener('click', function(ev) {
    ev.preventDefault();
    codeBox.select();
    document.execCommand('copy');
    copyBtn.textContent = _('Copied');
  });
  ui.showModal(title, [
    E('p', {}, _('Network: %s').format(network || '-')),
    codeBox,
    E('div', { 'class': 'alert-message warning', 'style': 'margin-top:.5em' },
      _('Treat this code like a password: anyone who has it can join your mesh and route traffic through your proxies. Share it with friends over a channel you trust.')),
    E('div', { 'class': 'right', 'style': 'margin-top:.5em' }, [
      copyBtn, ' ',
      E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Close'))
    ])
  ]);
}

function rpcError(r, fallback) {
  return (r && r.error) ? r.error : fallback;
}

return view.extend({
  handleSaveApply: null,
  handleSave: null,
  handleReset: null,

  load: function() {
    return Promise.all([
      callInstalled().catch(function() { return false; }),
      callStatus().catch(function() { return {}; })
    ]);
  },

  render: function(data) {
    if (!data[0]) return notInstalled();
    var self = this;
    var status = data[1] || {};
    var root = E('div', {}, [ E('h2', {}, _('Friend Mesh')) ]);
    var body = E('div');
    root.appendChild(body);
    self.renderBody(body, status);
    poll.add(function() {
      return callStatus().then(function(st) {
        self.renderBody(body, st || {});
      });
    }, 10);
    return root;
  },

  renderBody: function(body, st) {
    var self = this;
    body.innerHTML = '';
    if (!st.active) {
      body.appendChild(self.renderSetup());
      return;
    }
    body.appendChild(self.renderStatusCard(st));
    body.appendChild(self.renderPeerTable(st));
  },

  // --- not joined: create / join ------------------------------------------
  renderSetup: function() {
    var self = this;
    var nameInput = E('input', { 'class': 'cbi-input-text', 'placeholder': _('node name (default: hostname)'), 'style': 'width:16em' });
    var createBtn = E('button', { 'class': 'btn cbi-button cbi-button-action important' }, _('Create new mesh'));
    createBtn.addEventListener('click', function(ev) {
      ev.preventDefault();
      createBtn.disabled = true;
      callInit(nameInput.value || '').then(function(r) {
        if (!r || !r.code) {
          ui.addNotification(null, E('p', rpcError(r, _('mesh-init failed'))), 'error');
          createBtn.disabled = false;
          return;
        }
        showCodeModal(_('Mesh created — share this sync-code'), r.code, r.network_name);
      });
    });

    var codeArea = E('textarea', { 'class': 'cbi-input-textarea', 'style': 'width:100%;height:5em;font-family:monospace', 'placeholder': 'PWMESH1-…' });
    var joinBtn = E('button', { 'class': 'btn cbi-button cbi-button-action' }, _('Join'));
    var joinProgress = E('em', {}, '');
    joinBtn.addEventListener('click', function(ev) {
      ev.preventDefault();
      var code = (codeArea.value || '').trim();
      if (!code) {
        ui.addNotification(null, E('p', _('Paste a sync-code first')), 'warning');
        return;
      }
      joinBtn.disabled = true;
      joinProgress.textContent = _('Joining — applying configuration…');
      joinJob.run(code, nameInput.value || '').then(function(res) {
        joinProgress.textContent = '';
        joinBtn.disabled = false;
        if (res.ok) {
          ui.addNotification(null, E('p', _('Joined the mesh. Peer discovery runs every few minutes; use "Sync now" to discover friends immediately.')), 'info');
        } else {
          ui.addNotification(null, E('pre', {}, res.output || _('join failed')), 'error');
        }
      }).catch(function(e) {
        joinProgress.textContent = '';
        joinBtn.disabled = false;
        ui.addNotification(null, E('p', e.message), 'error');
      });
    });

    return E('div', { 'class': 'cbi-section' }, [
      E('div', { 'class': 'cbi-section-descr' },
        _('Link this router with friends\' PureWRT routers over an encrypted P2P overlay. When your own proxies are blocked, selected traffic fails over to a friend\'s working proxies — never their raw connection. One friend creates a mesh and shares the sync-code; everyone else pastes it here.')),
      E('h3', {}, _('Node name')),
      E('div', { 'style': 'margin-bottom:1em' }, [ nameInput ]),
      E('h3', {}, _('Create')),
      E('div', { 'style': 'margin-bottom:1em' }, [ createBtn ]),
      E('h3', {}, _('Join with a sync-code')),
      codeArea,
      E('div', { 'style': 'margin-top:.5em' }, [ joinBtn, ' ', joinProgress ])
    ]);
  },

  // --- joined: status card --------------------------------------------------
  renderStatusCard: function(st) {
    var self = this;
    var showCodeBtn = E('button', { 'class': 'btn cbi-button' }, _('Show sync-code'));
    showCodeBtn.addEventListener('click', function(ev) {
      ev.preventDefault();
      callCode().then(function(r) {
        if (r && r.code) showCodeModal(_('Group sync-code'), r.code, r.network_name);
        else ui.addNotification(null, E('p', rpcError(r, _('mesh-code failed'))), 'error');
      });
    });
    var syncBtn = E('button', { 'class': 'btn cbi-button' }, _('Sync now'));
    syncBtn.addEventListener('click', function(ev) {
      ev.preventDefault();
      syncBtn.disabled = true;
      syncJob.run().then(function(res) {
        syncBtn.disabled = false;
        ui.addNotification(null, res.ok
          ? E('p', _('Peer sync finished.'))
          : E('pre', {}, res.output || _('sync failed')), res.ok ? 'info' : 'warning');
      }).catch(function(e) { syncBtn.disabled = false; ui.addNotification(null, E('p', e.message), 'error'); });
    });
    var rotateBtn = E('button', { 'class': 'btn cbi-button cbi-button-remove' }, _('Rotate secrets'));
    rotateBtn.addEventListener('click', this.twoClick(rotateBtn, _('Rotate secrets'), function() {
      callRotate().then(function(r) {
        if (r && r.code) showCodeModal(_('Secrets rotated — everyone must re-join with this new code'), r.code, r.network_name);
        else ui.addNotification(null, E('p', rpcError(r, _('mesh-rotate failed'))), 'error');
      });
    }));
    var leaveBtn = E('button', { 'class': 'btn cbi-button-negative' }, _('Leave mesh'));
    leaveBtn.addEventListener('click', this.twoClick(leaveBtn, _('Leave mesh'), function() {
      callLeave().then(function(r) {
        if (r && r.error) ui.addNotification(null, E('p', r.error), 'error');
        else ui.addNotification(null, E('p', _('Left the mesh.')), 'info');
      });
    }));

    var diagBtn = E('button', { 'class': 'btn cbi-button' }, _('Diagnostics'));
    var diagBox = E('div', { 'style': 'display:none;margin-top:.7em' });
    diagBtn.addEventListener('click', function(ev) {
      ev.preventDefault();
      if (diagBox.style.display !== 'none') { diagBox.style.display = 'none'; return; }
      diagBox.style.display = '';
      diagBox.innerHTML = '';
      diagBox.appendChild(E('em', {}, _('Querying overlay…')));
      callDiagnostics().then(function(d) {
        diagBox.innerHTML = '';
        diagBox.appendChild(self.renderDiagnostics(d || {}));
      }).catch(function(e) {
        diagBox.innerHTML = '';
        diagBox.appendChild(E('em', {}, e.message));
      });
    });

    return E('div', { 'class': 'cbi-section' }, [
      E('h3', {}, _('Mesh status')),
      E('div', {}, [
        E('strong', {}, _('Network: ')), st.network_name || '-',
        E('span', { 'style': 'margin-left:1.5em' }, [ E('strong', {}, _('Node: ')), st.node_name || '-' ])
      ]),
      E('div', { 'style': 'margin-top:.3em' }, [
        E('strong', {}, _('Overlay: ')),
        fmt.pill(st.daemon_running ? _('running') : _('down'), st.daemon_running ? 'ok' : 'danger'),
        st.overlay_ip ? E('span', { 'style': 'margin-left:.6em;font-family:monospace' }, st.overlay_ip) : '',
        E('span', { 'style': 'margin-left:1.5em' }, [
          E('strong', {}, _('Exit offered: ')),
          fmt.pill(st.exit_enabled ? _('yes') : _('no'), st.exit_enabled ? 'ok' : 'muted')
        ])
      ]),
      E('div', { 'style': 'margin-top:.7em' }, [ showCodeBtn, ' ', syncBtn, ' ', diagBtn, ' ', rotateBtn, ' ', leaveBtn ]),
      diagBox
    ]);
  },

  // Diagnostics: per-rendezvous dial status + STUN NAT classification —
  // "why is the overlay not forming?" in one glance.
  renderDiagnostics: function(d) {
    var connStatus = function(s) {
      if (s === 'connected') return fmt.pill(_('connected'), 'ok');
      if (s === 'connecting') return fmt.pill(_('connecting'), 'warn');
      return fmt.pill(s || _('unknown'), 'danger');
    };
    // Symmetric-and-worse NAT defeats hole punching: friends fall back to
    // relaying through the rendezvous.
    var natPill = function(t) {
      if (!t || t === 'Unknown') return fmt.pill(_('unknown'), 'muted');
      var punchable = [ 'OpenInternet', 'NoPAT', 'FullCone', 'Restricted', 'PortRestricted' ].indexOf(t) >= 0;
      return fmt.pill(t, punchable ? 'ok' : 'warn');
    };
    var rows = (d.connectors || []).map(function(c) {
      return E('div', { 'style': 'margin-top:.2em' }, [
        E('span', { 'style': 'font-family:monospace;margin-right:.6em' }, c.url), connStatus(c.status)
      ]);
    });
    return E('div', { 'style': 'border-top:1px solid #ccc;padding-top:.5em' }, [
      E('div', {}, [ E('strong', {}, _('Rendezvous: ')),
        rows.length ? '' : E('em', {}, d.daemon_running ? _('none configured') : _('overlay daemon not running')) ]),
      E('div', {}, rows),
      E('div', { 'style': 'margin-top:.5em' }, [
        E('strong', {}, _('NAT: ')), 'UDP ', natPill(d.nat_udp), ' TCP ', natPill(d.nat_tcp),
        E('span', { 'style': 'margin-left:1.5em' }, [
          E('strong', {}, _('Public IP: ')),
          E('span', { 'style': 'font-family:monospace' }, (d.public_ips || []).join(', ') || '-')
        ])
      ]),
      E('div', { 'class': 'cbi-section-descr', 'style': 'margin-top:.4em' },
        _('A symmetric NAT usually defeats hole punching — friend traffic then relays through the rendezvous node instead of flowing directly.'))
    ]);
  },

  // twoClick arms a destructive button: first click arms for 3s, second fires.
  twoClick: function(btn, label, fire) {
    var pending = false, timer = null;
    return function(ev) {
      ev.preventDefault();
      if (!pending) {
        pending = true;
        btn.textContent = _('Click again to confirm');
        timer = window.setTimeout(function() { pending = false; btn.textContent = label; }, 3000);
        return;
      }
      if (timer) window.clearTimeout(timer);
      pending = false;
      btn.textContent = label;
      fire();
    };
  },

  // --- joined: peer table ----------------------------------------------------
  renderPeerTable: function(st) {
    var peers = st.peers || [];
    var table = E('table', { 'class': 'table cbi-section-table' }, [
      E('tr', { 'class': 'tr table-titles' }, [
        E('th', { 'class': 'th' }, _('Friend')),
        E('th', { 'class': 'th' }, _('Overlay IP')),
        E('th', { 'class': 'th' }, _('Link')),
        E('th', { 'class': 'th' }, _('Latency')),
        E('th', { 'class': 'th' }, _('Offers exit')),
        E('th', { 'class': 'th' }, _('Use exit')),
        E('th', { 'class': 'th' }, '')
      ])
    ]);
    if (!peers.length) {
      table.appendChild(E('tr', { 'class': 'tr' }, E('td', { 'class': 'td', 'colspan': 7 },
        E('em', {}, _('No friends discovered yet. Have a friend join with your sync-code, then click "Sync now".')))));
    }
    peers.forEach(function(p) {
      var link = p.live ? (p.relay ? fmt.pill(_('relay'), 'warn') : fmt.pill('p2p', 'ok')) : fmt.pill(_('offline'), 'muted');
      var en = E('input', { 'type': 'checkbox' });
      en.checked = !!p.enabled;
      en.addEventListener('change', function() {
        en.disabled = true;
        callPeerSet(p.name, en.checked ? '1' : '0').then(function(r) {
          en.disabled = false;
          if (r && r.error) {
            ui.addNotification(null, E('p', r.error), 'error');
            en.checked = !en.checked;
          }
        });
      });
      // Forget only offline peers: the usual orphan is a friend who left and
      // rejoined under a new node name. A live peer would just be re-added by
      // the next sync, so the button stays hidden for those.
      var forget = '';
      if (!p.live) {
        forget = E('button', { 'class': 'btn cbi-button cbi-button-remove', 'title': _('Remove this peer from the config. If it is actually alive, the next sync re-adds it.') }, _('Forget'));
        forget.addEventListener('click', function(ev) {
          ev.preventDefault();
          forget.disabled = true;
          callPeerRemove(p.name).then(function(r) {
            if (r && r.error) {
              ui.addNotification(null, E('p', r.error), 'error');
              forget.disabled = false;
            } else {
              ui.addNotification(null, E('p', _('Peer forgotten.')), 'info');
            }
          });
        });
      }
      table.appendChild(E('tr', { 'class': 'tr' }, [
        E('td', { 'class': 'td' }, p.name),
        E('td', { 'class': 'td', 'style': 'font-family:monospace' }, p.overlay_ip || '-'),
        E('td', { 'class': 'td' }, link),
        E('td', { 'class': 'td' }, p.live && p.latency_ms ? (Math.round(p.latency_ms) + ' ms') : '-'),
        E('td', { 'class': 'td' }, p.exit_offered ? _('yes') : _('no')),
        E('td', { 'class': 'td' }, en),
        E('td', { 'class': 'td' }, forget)
      ]));
    });
    return E('div', { 'class': 'cbi-section' }, [
      E('h3', {}, _('Friends')),
      E('div', { 'class': 'cbi-section-descr' },
        _('Discovered PureWRT routers in this mesh. "Use exit" adds that friend as an automatic fallback for your proxy sections — traffic only shifts there when all of your own nodes are dead, and it always leaves through the friend\'s proxies, never their home connection.')),
      table
    ]);
  }
});
