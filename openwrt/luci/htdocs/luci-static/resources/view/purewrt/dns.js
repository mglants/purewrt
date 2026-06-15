'use strict';
'require view';
'require form';
'require rpc';
'require ui';

var callResolversProbe = rpc.declare({ object: 'purewrt', method: 'resolvers_probe' });

// resolversProbeModal renders the {ok, any_endpoint_ok, canary, entries[]}
// payload returned by the resolvers_probe rpcd method as a colored table.
// Lives on this page because the bootstrap DoH section is the only caller —
// previously it lived on the Quick Start page alongside the bootstrap
// options, but those moved here so DNS-shaped settings are all in one tab.
function resolversProbeModal(res) {
  if (!res || typeof res !== 'object') {
    return E('pre', { 'style': 'white-space:pre-wrap' }, String(res));
  }
  var entries = res.entries || [];
  var ok = 0;
  entries.forEach(function(e) { if (e.ok) ok++; });
  var rows = entries.map(function(e) {
    var color = e.ok ? '#5cb85c' : '#d9534f';
    var pill = E('span', { 'style': 'background:' + color + ';color:white;padding:2px 8px;border-radius:8px;font-family:monospace;font-size:0.85em' }, e.ok ? 'OK' : 'FAIL');
    return E('tr', {}, [
      E('td', {}, pill),
      E('td', { 'style': 'font-family:monospace' }, e.url),
      E('td', {}, (e.latency_ms || 0) + ' ms'),
      E('td', { 'style': 'color:#888' }, e.error || (e.ips || []).join(', '))
    ]);
  });
  var summary = E('p', { 'style': res.any_endpoint_ok ? '' : 'color:#d9534f' },
    ok + '/' + entries.length + ' DoH endpoints answered for ' + (res.canary || 'canary') + '. ' + (res.ok ? _('Healthy.') : res.any_endpoint_ok ? _('Degraded but workable.') : _('All endpoints unreachable — add your own DoH endpoint or check zapret.')));
  var tbl = E('table', { 'class': 'table cbi-section-table' }, [
    E('thead', {}, E('tr', {}, [ E('th', {}, _('Status')), E('th', {}, _('Endpoint')), E('th', {}, _('Latency')), E('th', {}, _('Details')) ]))
  ].concat(rows.map(function(r) { return r; })));
  return E('div', {}, [ summary, tbl ]);
}

return view.extend({
  render: function() {
    var m = new form.Map('purewrt', _('PureWRT DNS'));
    var s = m.section(form.NamedSection, 'dns', 'dns', _('DNS'));

    s.option(form.Flag, 'enabled', _('Enabled'));
    var backend = s.option(form.DummyValue, 'backend', _('Backend'));
    backend.default = 'dnsmasq';
    backend.cfgvalue = function() { return 'dnsmasq'; };
    backend.description = _('PureWRT uses dnsmasq nftset integration as the supported DNS backend.');
    s.option(form.Value, 'listen', _('Mihomo DNS listen'));
    var udp = s.option(form.DynamicList, 'udp_upstream', _('UDP DNS fallback upstreams'));
    udp.description = _('Plain DNS servers used before DoH so a fresh router can resolve/bootstrap even when DoH endpoints are blocked.');
    s.option(form.DynamicList, 'doh_upstream', _('DoH upstreams'));
    var doq = s.option(form.DynamicList, 'doq_upstream', _('DoQ upstreams'));
    doq.description = _('DNS-over-QUIC upstreams used by mihomo (e.g. quic://dns.adguard-dns.com or quic://94.140.14.14). Tried alongside DoH; useful when DoH is selectively filtered.');
    s.option(form.Flag, 'hijack_lan_dns', _('Hijack LAN DNS'));
    s.option(form.Flag, 'block_dot', _('Block DoT (tcp/853)'));
    var blockDoq = s.option(form.Flag, 'block_doq', _('Block DoQ (udp/853)'));
    blockDoq.default = '1';
    blockDoq.description = _('Reject DNS-over-QUIC egress so clients with hardcoded DoQ resolvers (recent Android) fall back to the LAN-hijacked path.');
    var blockDoh3 = s.option(form.Flag, 'block_doh3', _('Block DoH3 (udp/443 to known DoH endpoints)'));
    blockDoh3.default = '1';
    blockDoh3.description = _('Reject UDP/443 to the DoH endpoint IPs listed below. Required because blanket-blocking UDP/443 would break all QUIC.');
    var doh3v4 = s.option(form.DynamicList, 'doh3_block_ip4', _('DoH3 block — IPv4'));
    doh3v4.depends('block_doh3', '1');
    doh3v4.description = _('IPv4 addresses or CIDRs to refuse on UDP/443. Defaults cover Cloudflare, Google, Quad9, AdGuard, NextDNS.');
    var doh3v6 = s.option(form.DynamicList, 'doh3_block_ip6', _('DoH3 block — IPv6'));
    doh3v6.depends('block_doh3', '1');
    doh3v6.description = _('IPv6 addresses or CIDRs to refuse on UDP/443.');
    s.option(form.Flag, 'fake_ip', _('Fake-IP compatibility'));
    var mode = s.option(form.ListValue, 'enhanced_mode', _('Enhanced mode'));
    mode.value('normal');
    mode.value('fake-ip');

    var groupType = s.option(form.ListValue, 'proxy_group_type', _('DNSProxy group type'));
    groupType.value('select', _('select'));
    groupType.value('url-test', _('url-test'));
    groupType.value('load-balance', _('load-balance'));
    groupType.default = 'url-test';
    groupType.description = _('Mihomo proxy group type used for DoH and DNS fallback routing rules.');
    var filter = s.option(form.Value, 'proxy_filter', _('DNSProxy filter'));
    filter.description = _('Mihomo regex include filter for proxies used by DNSProxy. Empty includes all proxies.');
    var excludeFilter = s.option(form.Value, 'proxy_exclude_filter', _('DNSProxy exclude-filter'));
    excludeFilter.description = _('Mihomo regex exclude filter for proxies used by DNSProxy.');
    var strategy = s.option(form.ListValue, 'proxy_strategy', _('DNSProxy load-balance strategy'));
    strategy.value('sticky-sessions', _('sticky-sessions'));
    strategy.value('consistent-hashing', _('consistent-hashing'));
    strategy.value('round-robin', _('round-robin'));
    strategy.default = 'sticky-sessions';
    strategy.depends('proxy_group_type', 'load-balance');

    // Bootstrap DoH governs how PureWRT itself resolves subscription /
    // rule-provider / mihomo-update hostnames, separate from the LAN DNS
    // configured above. Keeping it on this tab so all DNS-shaped settings
    // are in one place rather than buried on Quick Start.
    var b = m.section(form.NamedSection, 'settings', 'main', _('Bootstrap DoH (for PureWRT downloads)'));
    var bootstrapDoh = b.option(form.Flag, 'bootstrap_doh_enabled', _('Bootstrap downloads via DoH'));
    bootstrapDoh.default = '1';
    bootstrapDoh.rmempty = false;
    bootstrapDoh.description = _('Resolve subscription and mihomo-update hosts via DNS-over-HTTPS instead of the system resolver, so a fresh router can fetch its own config even when ISP DNS is censored.');
    var bootstrapResolvers = b.option(form.DynamicList, 'bootstrap_doh_resolver', _('Bootstrap DoH resolvers'));
    bootstrapResolvers.depends('bootstrap_doh_enabled', '1');
    bootstrapResolvers.placeholder = 'https://1.1.1.1/dns-query';
    bootstrapResolvers.description = _('IP-literal DoH endpoints used during bootstrap. Defaults cover Cloudflare, Google, Quad9, AdGuard, Mullvad, Yandex — the union is harder to fully blanket-block than any single provider. <b>In heavily censored networks where these are all blocked, add your own DoH endpoint (your VPS, a friend’s server)</b> — it will be tried alongside the defaults. Run <code>purewrt resolvers-probe</code> to verify reachability.');
    var bootstrapTimeout = b.option(form.Value, 'bootstrap_doh_timeout_ms', _('Bootstrap DoH timeout (ms)'));
    bootstrapTimeout.depends('bootstrap_doh_enabled', '1');
    bootstrapTimeout.datatype = 'uinteger';
    bootstrapTimeout.placeholder = '8000';
    var bootstrapTofuPath = b.option(form.Value, 'bootstrap_tofu_path', _('Bootstrap DNS cache path'));
    bootstrapTofuPath.placeholder = '/etc/purewrt/dns-tofu.json';
    bootstrapTofuPath.description = _('Trust-on-first-use IP cache. After each successful DoH lookup the resolved IPs are remembered so day-2 updates skip DoH entirely — survives reboot. Set to <code>off</code> to disable, or change the path to put it on tmpfs.');
    var bootstrapTofuTTL = b.option(form.Value, 'bootstrap_tofu_ttl_sec', _('Bootstrap DNS cache TTL (s)'));
    bootstrapTofuTTL.datatype = 'uinteger';
    bootstrapTofuTTL.placeholder = '604800';
    bootstrapTofuTTL.description = _('How long a cached resolution is trusted before going back to DoH. Default 7 days.');
    var bootstrapHealthGate = b.option(form.Flag, 'bootstrap_health_gate', _('Health-gate apply on DoH reachability'));
    bootstrapHealthGate.depends('bootstrap_doh_enabled', '1');
    bootstrapHealthGate.default = '0';
    bootstrapHealthGate.description = _('When set, <code>purewrt apply</code> probes the bootstrap resolvers first and aborts loudly if every endpoint times out — fails the apply instead of silently degrading to the (likely hijacked) ISP DNS. Adds ~3–8s to each apply.');
    var probeResolvers = b.option(form.Button, '_probe_resolvers', _('Probe DoH resolvers now'));
    probeResolvers.depends('bootstrap_doh_enabled', '1');
    probeResolvers.inputstyle = 'action';
    probeResolvers.description = _('Runs the same DoH probe as the health gate against the configured pool and shows latency + reachability per endpoint. Useful for verifying which endpoints survive your network before flipping the gate on.');
    probeResolvers.onclick = function() {
      return callResolversProbe().then(function(res) {
        ui.showModal(_('DoH resolvers probe'), [
          resolversProbeModal(res),
          E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Close'))
        ]);
      });
    };
    var bootstrapFallback = b.option(form.Flag, 'bootstrap_proxy_fallback', _('Retry blocked downloads through local mihomo'));
    bootstrapFallback.default = '1';
    bootstrapFallback.rmempty = false;
    bootstrapFallback.description = _('After direct + mirror attempts all fail, run one final pass through the local mihomo mixed-port. Lets a routine update recover when the subscription host is freshly blocked on bare WAN.');
    var tlsFp = b.option(form.ListValue, 'bootstrap_tls_fingerprint', _('Bootstrap TLS fingerprint'));
    tlsFp.value('browser', _('Browser (Chrome-shaped ALPN/curves/ciphers)'));
    tlsFp.value('off', _('Off (stdlib defaults)'));
    tlsFp.default = 'browser';
    tlsFp.description = _('Tunes the TLS ClientHello our downloads emit, so censors fingerprinting JA3/JA4 see a browser-shaped handshake instead of the stock Go signature.');

    return m.render();
  }
});
