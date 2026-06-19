'use strict';
'require baseclass';
'require ui';
'require uci';
'require network';

// purewrt.vpn_modal — render the VPN editor (formerly the standalone VPN
// Routing tab) inside a LuCI modal, callable from any page. The
// Sections / Routing page hooks this up next to the per-section
// `action == 'vpn'` picker so users add / edit VPN interfaces inline with
// the section that needs them, removing the need for a dedicated VPN tab.
//
// Public API:
//   openVPNModal({ name, onSave }) — opens the modal. If `name` matches an
//     existing UCI vpn section, the form is prefilled and Save updates in
//     place; otherwise a new anonymous vpn section is created. `onSave` is
//     called with the saved entry's `name` after the UCI write completes,
//     so the caller can refresh its dropdown + pre-select the new VPN.

// vpnDeviceCandidates filters and sorts /etc/config/network devices into
// the ones that plausibly carry a VPN endpoint (wireguard, tunnel, tap,
// etc.). Extracted from the deleted vpn.js so sections.js doesn't have to
// know about device-type heuristics.
function vpnDeviceCandidates(devices) {
  var out = [];
  (devices || []).forEach(function(dev) {
    var name = dev.getName && dev.getName();
    if (!name || name === 'lo') return;
    var typ = (dev.getType && dev.getType()) || '';
    var likelyVPN = typ === 'wireguard' || typ === 'tunnel' || typ === 'vxlan' ||
      /^(wg|tun|tap|xfrm|zt|gre|ipsec)/.test(name);
    out.push({ name: name, type: typ, likely: likelyVPN });
  });
  out.sort(function(a, b) {
    if (a.likely !== b.likely) return a.likely ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
  return out;
}

// findVPNByName returns the UCI section descriptor for the vpn named
// `name`, or null. Anonymous vpn sections are looked up by their `name`
// option (the user-visible identifier), not by `.name` (the UCI section
// id) — that's what the rest of the codebase uses to refer to a VPN.
function findVPNByName(name) {
  if (!name) return null;
  var sections = uci.sections('purewrt', 'vpn') || [];
  for (var i = 0; i < sections.length; i++) {
    if (sections[i].name === name) return sections[i];
  }
  return null;
}

function renderForm(initial, devices) {
  // Each row: label on the left (.cbi-value-title) + input on the right
  // (.cbi-value-field). Mirrors the standard cbi form look so the modal
  // doesn't feel like a bolt-on.
  function row(label, input, hint) {
    return E('div', { 'class': 'cbi-value', 'style': 'display:flex;flex-wrap:wrap;align-items:center;gap:.5em;margin:.4em 0' }, [
      E('label', { 'class': 'cbi-value-title', 'style': 'min-width:14em' }, label),
      E('div', { 'class': 'cbi-value-field', 'style': 'flex:1;min-width:14em' }, [
        input,
        hint ? E('div', { 'class': 'cbi-value-description', 'style': 'color:#888;font-size:.85em;margin-top:.2em' }, hint) : E([])
      ])
    ]);
  }

  // -- name --
  var nameInput = E('input', { 'class': 'cbi-input-text', 'value': initial.name || '', 'placeholder': 'vpn', 'style': 'width:14em' });

  // -- interface (combobox; VPN-likely first) --
  var ifaceSelect = E('select', { 'class': 'cbi-input-select', 'style': 'width:18em' });
  vpnDeviceCandidates(devices).forEach(function(d) {
    var label = d.type ? (d.name + ' (' + d.type + ')') : d.name;
    var attrs = { 'value': d.name };
    if (d.name === initial.interface) attrs.selected = 'selected';
    ifaceSelect.appendChild(E('option', attrs, label));
  });
  // Allow custom values that the detector missed — add a hidden option for
  // whatever was already saved if it's not in the auto-detected list.
  if (initial.interface && !Array.prototype.some.call(ifaceSelect.options, function(o) { return o.value === initial.interface; })) {
    var customOpt = E('option', { 'value': initial.interface, 'selected': 'selected' }, initial.interface + ' (custom)');
    ifaceSelect.insertBefore(customOpt, ifaceSelect.firstChild);
  }

  // -- enabled --
  var enabledChk = E('input', { 'type': 'checkbox' });
  if (initial.enabled !== '0') enabledChk.checked = true;

  // VPNs are mihomo `direct` outbounds now — only the interface matters.
  // Routing (table/fwmark/priority/masquerade) is handled by mihomo, so those
  // kernel knobs are gone.
  var formEl = E('div', { 'style': 'min-width:32em' }, [
    row(_('Enabled'),    enabledChk),
    row(_('Name'),       nameInput, _('Used to add this VPN to a section/DNS proxy pool. Lowercase, no spaces.')),
    row(_('Interface'),  ifaceSelect, _('Pick an existing network device. WireGuard/TUN/TAP interfaces are listed first. mihomo binds outbound sockets to it.'))
  ]);

  return {
    el: formEl,
    read: function() {
      return {
        name: (nameInput.value || '').trim(),
        interface: ifaceSelect.value,
        enabled: enabledChk.checked ? '1' : '0'
      };
    }
  };
}

function writeVPN(existing, values) {
  // sid = existing UCI section id when editing, or null to add a new
  // anonymous section. uci.add returns the freshly minted .name for the
  // new section which we then `uci.set` per option.
  var sid = existing ? existing['.name'] : uci.add('purewrt', 'vpn');
  if (!sid) throw new Error('uci.add returned no section id');
  uci.set('purewrt', sid, 'name', values.name);
  uci.set('purewrt', sid, 'interface', values.interface);
  uci.set('purewrt', sid, 'enabled', values.enabled);
  return sid;
}

// snapshotParentModal/restoreParentModal: LuCI has a single modal slot, so
// opening the VPN modal from inside the Sections / Routing modal replaces
// the section form. We snapshot the section modal's title + child nodes,
// then on close put them back via ui.showModal again.
//
// Critical: we DETACH the snapshot children from dlg ourselves (instead of
// letting ui.showModal->dom.content do it). dom.content walks every
// descendant of the cleared node and `delete this.registry[data-idref]` —
// that nukes the LuCI class bindings for every form widget in modalMapEl.
// Re-attaching the same DOM nodes later doesn't restore the registry, so
// any subsequent `dom.findClassInstance` walks crash trying to read
// `registry[stale-id]._class`. By detaching first, dom.content's
// descendant scan finds nothing in our subtree, and the bindings survive.
function snapshotParentModal() {
  var dlg = document.querySelector('#modal_overlay .modal');
  if (!dlg || !dlg.firstChild) return null;
  var h4 = dlg.querySelector(':scope > h4');
  var title = h4 ? h4.innerText : '';
  var children = Array.prototype.filter.call(dlg.childNodes, function(n) {
    return n !== h4;
  });
  if (!children.length) return null;
  // Detach BEFORE ui.showModal runs dom.content on dlg. Children retain
  // their data-idref attributes AND their registry entries because they're
  // no longer descendants of dlg at the moment dom.content scans it.
  children.forEach(function(n) { if (n.parentNode === dlg) dlg.removeChild(n); });
  return { title: title, children: children };
}

function restoreParentModal(snap) {
  if (!snap) return false;
  ui.showModal(snap.title, snap.children);
  return true;
}

function openVPNModal(opts) {
  opts = opts || {};
  var existing = findVPNByName(opts.name);
  var initial = existing ? {
    name:      existing.name || '',
    interface: existing.interface || '',
    enabled:   existing.enabled || '1'
  } : { enabled: '1' };

  // Capture the parent modal state NOW, before ui.showModal for the VPN
  // form wipes it. opts.snapshotParent=false lets a caller opt out (e.g.
  // when launched from a non-modal context).
  var parentSnap = (opts.snapshotParent !== false) ? snapshotParentModal() : null;

  return network.getDevices().then(function(devices) {
    var form = renderForm(initial, devices);

    // closeWith: shared exit path for Cancel / Save / Delete. If we captured
    // a parent modal, put it back on screen; otherwise just hide the modal
    // entirely (the old behavior, used by non-modal callers). The result
    // arg signals which callback (if any) to fire.
    function closeWith(result) {
      if (!restoreParentModal(parentSnap)) ui.hideModal();
      if (!result) return;
      if (result.deleted && typeof opts.onDelete === 'function')
        opts.onDelete(result.deleted);
      else if (result.saved && typeof opts.onSave === 'function')
        opts.onSave(result.saved, !!existing);
    }

    // Two-click delete: first click flips the button label + colour to a
    // confirm state; a second click within 3 s commits. Avoids window.confirm
    // (which blocks the page) and keeps UX inside the existing modal so the
    // parent modal still restores on close.
    var deletePending = false;
    var deleteResetTimer = null;
    function onDeleteClick(ev, btn) {
      ev.preventDefault();
      if (!existing) return;
      if (!deletePending) {
        deletePending = true;
        btn.textContent = _('Click again to confirm delete');
        btn.classList.add('cbi-button-negative');
        deleteResetTimer = window.setTimeout(function() {
          deletePending = false;
          btn.textContent = _('Delete');
          btn.classList.remove('cbi-button-negative');
        }, 3000);
        return;
      }
      if (deleteResetTimer) window.clearTimeout(deleteResetTimer);
      btn.disabled = true;
      uci.remove('purewrt', existing['.name']);
      return uci.save().then(function() {
        return uci.apply();
      }).then(function() {
        ui.addNotification(null, E('p', _('VPN %s deleted.').format(existing.name || '')), 'info');
        closeWith({ deleted: existing.name || existing['.name'] });
      }).catch(function(e) {
        btn.disabled = false;
        deletePending = false;
        btn.textContent = _('Delete');
        btn.classList.remove('cbi-button-negative');
        ui.addNotification(null, E('p', _('VPN delete failed: %s').format(e && e.message || e)), 'danger');
      });
    }

    function onSave(ev) {
      ev.preventDefault();
      var values = form.read();
      if (!values.name || !/^[A-Za-z0-9_]+$/.test(values.name)) {
        ui.addNotification(null, E('p', _('VPN name must be non-empty and contain only letters, digits, and underscores.')), 'warning');
        return;
      }
      if (!values.interface) {
        ui.addNotification(null, E('p', _('Pick an interface for the VPN to bind to.')), 'warning');
        return;
      }
      var clash = findVPNByName(values.name);
      if (clash && (!existing || clash['.name'] !== existing['.name'])) {
        ui.addNotification(null, E('p', _('A VPN named %s already exists.').format(values.name)), 'warning');
        return;
      }
      try { writeVPN(existing, values); }
      catch (e) {
        ui.addNotification(null, E('p', _('VPN save failed: %s').format(e && e.message || e)), 'danger');
        return;
      }
      return uci.save().then(function() {
        return uci.apply();
      }).then(function() {
        ui.addNotification(null, E('p', _('VPN %s saved.').format(values.name)), 'info');
        closeWith({ saved: values.name });
      }).catch(function(e) {
        ui.addNotification(null, E('p', _('UCI commit failed: %s').format(e && e.message || e)), 'danger');
      });
    }

    // Delete button only makes sense when editing an existing VPN. Layout:
    // [Delete]                            [Cancel]  [Save]
    var footerChildren = [];
    if (existing) {
      var deleteBtn = E('button', {
        'class': 'btn cbi-button-remove',
        'style': 'margin-right:auto'
      }, _('Delete'));
      deleteBtn.addEventListener('click', function(ev) { onDeleteClick(ev, deleteBtn); });
      footerChildren.push(deleteBtn);
    }
    footerChildren.push(
      E('button', { 'class': 'btn', 'click': function(ev) { ev.preventDefault(); closeWith(null); } }, _('Cancel')),
      ' ',
      E('button', { 'class': 'btn cbi-button-save', 'click': onSave }, existing ? _('Save changes') : _('Add VPN'))
    );

    var title = existing ? _('Edit VPN: %s').format(initial.name) : _('Add VPN');
    ui.showModal(title, [
      form.el,
      E('div', {
        'class': 'right',
        'style': 'margin-top:1em;display:flex;align-items:center;gap:.5em'
      }, footerChildren)
    ]);
  });
}

return baseclass.extend({
  openVPNModal: openVPNModal,
  vpnDeviceCandidates: vpnDeviceCandidates,
  findVPNByName: findVPNByName
});
