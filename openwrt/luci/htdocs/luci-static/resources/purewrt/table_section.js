'use strict';
'require baseclass';
'require uci';
'require ui';
'require dom';

function sectionWrapper(root, node) {
  var wrapper = node.parentNode;

  if (wrapper && wrapper !== root && wrapper.classList && wrapper.classList.contains('cbi-section') &&
      wrapper.querySelectorAll('.cbi-section-node[data-section-id]').length === 1 &&
      !wrapper.querySelector('.cbi-section-create, .cbi-button-add'))
    return wrapper;

  return node;
}

function sectionNodes(root, filterNode) {
  var nodes = Array.prototype.slice.call(root.querySelectorAll('.cbi-section-node[data-section-id]'));

  if (filterNode)
    nodes = nodes.filter(filterNode);

  return nodes;
}

function tableHeader(columns, labels) {
  return E('div', {
    'class': 'cbi-section-table-titles purewrt-section-row-head',
    'style': 'display:grid;grid-template-columns:' + columns + ';align-items:center;text-align:center;border-top:1px solid var(--border-color-medium,#333);border-bottom:1px solid var(--border-color-medium,#333);padding:.65em .75em;font-weight:bold;background:var(--background-color-high,#252525)'
  }, labels.map(function(label) { return E('span', {}, [ label ]); }));
}

function rowCell(content) {
  return E('span', { 'style': 'text-align:center' }, [ content ]);
}

function triggerInput(input, name) {
  var ev;

  if (typeof Event === 'function')
    ev = new Event(name, { bubbles: true });
  else {
    ev = document.createEvent('Event');
    ev.initEvent(name, true, true);
  }

  input.dispatchEvent(ev);
}

function enabledToggle(wrapper) {
  var node = wrapper.querySelector('.cbi-section-node[data-section-id]');
  var input = wrapper.querySelector('input[type="checkbox"][data-widget-id$=".enabled"]');
  var checked = input ? input.checked : uci.get('purewrt', node.getAttribute('data-section-id'), 'enabled') !== '0';

  return E('input', {
    'type': 'checkbox',
    'checked': checked ? 'checked' : null,
    'click': function(ev) { ev.stopPropagation(); },
    'change': function(ev) {
      ev.stopPropagation();
      if (input) {
        input.checked = ev.target.checked;
        triggerInput(input, 'input');
        triggerInput(input, 'change');
      }
    }
  });
}

function hideSectionChrome(node) {
  var prev = node.previousSibling;

  while (prev) {
    if (prev.nodeType === 1 && prev.classList && prev.classList.contains('purewrt-section-row'))
      break;

    if (prev.nodeType === 1 && (prev.matches('h3, h4') || (prev.classList && prev.classList.contains('cbi-section-remove'))))
      prev.style.display = 'none';

    prev = prev.previousSibling;
  }
}

function priorityInput(node) {
  return node.querySelector('input[id$=".priority"], input[name$=".priority"]');
}

function priorityValue(node, idx) {
  var input = priorityInput(node);
  var value = input ? parseInt(input.value || input.getAttribute('value') || '1000', 10) : 1000;

  if (isNaN(value) || value <= 0)
    value = 1000;

  return value * 100000 + idx;
}

function updatePriorities(root, filterNode) {
  sectionNodes(root, filterNode).forEach(function(node, idx) {
    var input = priorityInput(node);

    if (!input)
      return;

    input.value = String((idx + 1) * 10);
    triggerInput(input, 'input');
    triggerInput(input, 'change');
  });
}

function clickRemove(node, wrapper) {
  var sid = node.getAttribute('data-section-id');
  var selector = 'button[name^="cbi.rts."][data-section-id="' + sid + '"]';
  var btn = null;
  var scope = wrapper.parentNode || node.parentNode;

  if (scope)
    btn = scope.querySelector(selector);

  if (!btn) {
    var prev = node.previousSibling;

    while (prev) {
      if (prev.nodeType === 1 && prev.classList && prev.classList.contains('purewrt-section-row'))
        break;

      if (prev.nodeType === 1 && prev.classList && prev.classList.contains('cbi-section-remove')) {
        btn = prev.querySelector(selector) || prev.querySelector('button[name^="cbi.rts."]');
        if (btn)
          break;
      }

      prev = prev.previousSibling;
    }
  }

  if (btn)
    btn.click();
}

function openSectionModal(title, wrapper, saveFn, afterRestoreFn) {
  var placeholder = document.createComment('purewrt-modal-placeholder');
  var parent = wrapper.parentNode;
  // Find the page cbi-map (= map.root for the CBIMap instance). Anything
  // above the wrapper inside the page is fine; the immediate parent in our
  // layout is `parent` itself, but we walk just in case the section was
  // nested inside another cbi-section.
  var pageMapEl = wrapper.closest ? wrapper.closest('.cbi-map') : parent;
  var map = pageMapEl ? dom.findClassInstance(pageMapEl) : null;

  parent.insertBefore(placeholder, wrapper);
  wrapper.style.display = '';

  // The modal cbi-map is a NEW div, and the form fields live inside it
  // once we move `wrapper` here. The CBIMap instance's `root` still points
  // at the original page cbi-map — but checkDepends / findElement search
  // `this.root`. Without swapping, depends evaluation can't see the moved
  // fields, so action=vpn (etc.) silently fails to swap visible widgets.
  var modalMapEl = E('div', { 'class': 'cbi-map', 'style': 'max-height:70vh;overflow:auto' }, [ wrapper ]);
  var originalRoot = map ? map.root : null;
  if (map) {
    map.root = modalMapEl;
    // Re-evaluate visibility with the new root so depends-driven fields
    // (like `vpn`, `zapret_strategy`) show/hide based on current action.
    try { map.checkDepends(); } catch (e) { /* non-fatal */ }
  }

  function restore() {
    if (placeholder.parentNode) {
      placeholder.parentNode.insertBefore(wrapper, placeholder);
      placeholder.parentNode.removeChild(placeholder);
    }
    wrapper.style.display = 'none';
    // Restore map.root so the page's standard save/render path operates
    // on the right element. We deliberately do NOT call map.checkDepends()
    // here — the wrapper is hidden via display:none, and the upcoming
    // m.save() chain triggers renderContents() which rebuilds the map's
    // DOM children and re-evaluates depends fresh. Calling checkDepends
    // now would race against that rebuild and (in practice) wipe the
    // table_section's custom row headers.
    if (map && originalRoot) {
      map.root = originalRoot;
    }
    ui.hideModal();
  }

  ui.showModal(title, [
    modalMapEl,
    E('div', { 'class': 'right' }, [
      E('button', { 'class': 'btn', 'click': function(ev) { ev.preventDefault(); restore(); } }, [ _('Dismiss') ]),
      ' ',
      E('button', { 'class': 'btn cbi-button-save', 'click': function(ev) {
        ev.preventDefault();
        restore();
        if (afterRestoreFn)
          afterRestoreFn();
        return Promise.resolve(saveFn ? saveFn() : null).finally(function() {
          if (afterRestoreFn)
            afterRestoreFn();
        });
      } }, [ _('Save') ])
    ])
  ]);
}

function editSection(root, opt, sid, wrapper) {
  wrapper.style.display = '';

  return openSectionModal(opt.titleOf(sid), wrapper, opt.save, function() {
    render(root, opt);
  });
}

function movePair(pair, targetHeader, after) {
  var parent = targetHeader.parentNode;
  var ref = after ? targetHeader.nextSibling : targetHeader;

  parent.insertBefore(pair.header, ref);
  parent.insertBefore(pair.wrapper, ref);
}

function clearDropIndicators(root) {
  Array.prototype.forEach.call(root.querySelectorAll('.purewrt-section-row'), function(row) {
    row.classList.remove('drag-over-above');
    row.classList.remove('drag-over-below');
    row.style.borderTop = '';
    row.style.borderBottom = '';
    row.style.boxShadow = '';
  });
}

function updateDropIndicator(root, row, ev) {
  var rect = row.getBoundingClientRect();

  clearDropIndicators(root);
  if (ev.clientY <= rect.top + rect.height / 2) {
    row.classList.add('drag-over-above');
    row.style.borderTop = '3px solid var(--color-primary,#00a8e8)';
    row.style.boxShadow = '0 -2px 0 var(--color-primary,#00a8e8)';
  }
  else {
    row.classList.add('drag-over-below');
    row.style.borderBottom = '3px solid var(--color-primary,#00a8e8)';
    row.style.boxShadow = '0 2px 0 var(--color-primary,#00a8e8)';
  }
}

function render(root, opt) {
  var previousRows = Array.prototype.slice.call(root.querySelectorAll('.purewrt-section-row'));

  Array.prototype.forEach.call(root.querySelectorAll('.purewrt-section-row-head'), function(header) {
    header.parentNode.removeChild(header);
  });

  previousRows.forEach(function(header) {
    if (header.purewrtWrapper)
      header.purewrtWrapper.style.display = '';
    header.parentNode.removeChild(header);
  });

  var pairs = sectionNodes(root, opt.filterNode).map(function(node, idx) {
    return { node: node, wrapper: sectionWrapper(root, node), order: idx };
  });

  if (!pairs.length)
    return root;

  if (opt.draggable)
    pairs.sort(function(a, b) {
      return priorityValue(a.node, a.order) - priorityValue(b.node, b.order);
    });

  pairs.forEach(function(pair) {
    if (!opt.editing)
      pair.wrapper.style.display = 'none';
  });

  var parent = pairs[0].wrapper.parentNode;
  var marker = document.createComment('purewrt-section-rows');
  var rerender = function() { render(root, opt); };

  parent.insertBefore(marker, pairs[0].wrapper);

  if (!root.purewrtRowsBound) {
    root.addEventListener('click', function(ev) {
      var target = ev.target;

      if (target && target.closest && target.closest('.cbi-button-add, button[name^="cbi.rts."]'))
        window.setTimeout(rerender, 300);
    }, true);
    root.purewrtRowsBound = true;
  }

  pairs.forEach(function(pair, idx) {
    var node = pair.node;
    var sid = node.getAttribute('data-section-id');
    var cells = opt.summaryOf(sid);
    var heading = node.querySelector('h3, h4');
    var wrapper = pair.wrapper;
    var header = E('div', {
      'class': 'cbi-section purewrt-section-row',
      'style': 'display:grid;grid-template-columns:' + opt.columns + ';align-items:center;text-align:center;margin-bottom:0;border-bottom:1px solid var(--border-color-medium,#333);padding:.65em .75em',
      'tabindex': '0',
      'role': 'button',
      'keydown': function(ev) {
        if (ev.key === 'Enter' || ev.key === ' ') {
          ev.preventDefault();
          editSection(root, opt, sid, wrapper);
        }
      }
    });

      if (heading)
        heading.style.display = 'none';
    hideSectionChrome(node);

    header.purewrtWrapper = wrapper;
    wrapper.purewrtHeader = header;

    if (opt.draggable) {
      var handle = E('span', {
        'class': 'cbi-button drag-handle center purewrt-drag-handle',
        'draggable': 'true',
        'title': _('Drag to reorder'),
        'style': 'cursor:move;user-select:none;display:inline-block',
        'dragstart': function(ev) {
          if (!ev.target.classList.contains('drag-handle'))
            return false;
          root.purewrtDragged = { header: header, wrapper: wrapper };
          ev.dataTransfer.effectAllowed = 'move';
          ev.dataTransfer.setData('text', 'drag');
          ev.target.style.opacity = '0.4';
        },
        'dragend': function(ev) {
          ev.target.style.opacity = '';
          clearDropIndicators(root);
          root.purewrtDragged = null;
        }
      }, [ '☰' ]);

      header.appendChild(handle);
    }

    header.appendChild(E('span', { 'style': 'min-width:1em' }, [ '' ]));
    cells.forEach(function(cell) { header.appendChild(rowCell(cell)); });
    if (opt.showEnable)
      header.appendChild(E('span', {}, [ enabledToggle(wrapper) ]));
    var actionChildren = [];

    (opt.actions || []).forEach(function(action, actionIdx) {
      var button = E('button', {
        'class': 'btn cbi-button cbi-button-' + (action.style || action.kind || 'neutral'),
        'click': function(ev) {
          ev.preventDefault();
          if (action.kind === 'edit') {
            ev.stopPropagation();
            return editSection(root, opt, sid, wrapper);
          }
          if (action.kind === 'delete')
            return clickRemove(node, wrapper);
          return action.onclick ? action.onclick(sid, node, wrapper) : null;
        }
      }, [ action.label ]);

      if (actionIdx)
        actionChildren.push(' ');
      actionChildren.push(button);
    });

    header.appendChild(E('span', { 'style': 'white-space:nowrap;text-align:right;justify-self:end' }, actionChildren));

    if (opt.draggable) {
      header.addEventListener('dragover', function(ev) {
        if (!root.purewrtDragged || root.purewrtDragged.header === header)
          return;
        ev.preventDefault();
        ev.dataTransfer.dropEffect = 'move';
        updateDropIndicator(root, header, ev);
      });
      header.addEventListener('dragleave', function() {
        header.classList.remove('drag-over-above');
        header.classList.remove('drag-over-below');
      });
      header.addEventListener('drop', function(ev) {
        if (!root.purewrtDragged || root.purewrtDragged.header === header)
          return;
        ev.preventDefault();
        var after = header.classList.contains('drag-over-below');
        clearDropIndicators(root);
        movePair(root.purewrtDragged, header, after);
        updatePriorities(root, opt.filterNode);
        root.purewrtDragged.header.classList.add('flash');
      });
    }

    if (idx === 0)
      parent.insertBefore(tableHeader(opt.columns, opt.headers), marker);
    parent.insertBefore(header, marker);
    parent.insertBefore(wrapper, marker);
    if (!opt.editing)
      wrapper.style.display = 'none';
  });

  parent.removeChild(marker);

  return root;
}

return baseclass.extend({
  render: render
});
