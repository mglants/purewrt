# OONI measurements over mwan3 WANs

In LuCI → PureWRT → OONI Probe, select **Test WANs** to run each selected
mwan3 interface sequentially. Leave the selection empty for the existing
router routing and resolver behavior; mwan3 is then unnecessary.

Equivalent UCI example (generic interface names):

```uci
config ooni 'ooni'
    option enabled '1'
    option upload '0'
    list wan 'wan_a'
    list wan 'wan_b'
```

Cron and **Run now** invoke the same `purewrt ooni-run` command and share a
lock. Each selected WAN gets its own OONI home below
`<OONI_HOME>/wan-<interface>`, including its database and measurement files.
The configured upload preference applies to scheduled and interactive runs.

For a single local website measurement without publishing results:

```sh
purewrt ooni-run --no-collector --input https://example.com/
```

This uses separate homes ending in `-local` and disables collection in both
the generated OONI configuration and command line.

## Routing and DNS

PureWRT discovers the selected WAN's device and IPv4 routing table from
netifd and mwan3's live rules. Temporary UID rules at priorities 97 and 98 select the WAN's table before
mwan3's mark-based rules. An nftables OUTPUT route chain also enforces the
selected WAN's mark after mwan3 restores connection marks; UID rules alone
are insufficient on the tested router. A later output guard rejects traffic
leaving through any other device. Only the dedicated OONI user is affected.
Loopback remains available through the kernel's priority-0 local table,
so the existing backend proxy continues to work.

A terminal rejection rule prevents a missing route from falling through to
another WAN. Pinned measurements currently support IPv4 only: IPv6 is
rejected for the OONI user during each run. Empty WAN selection retains
normal IPv6 behavior.

The runner reads `dns-server` from the selected interface's netifd status.
When peer DNS is disabled, it uses the advertised servers retained in
`inactive.dns-server`. It requires non-loopback IPv4 DNS servers and fails
the run if none are available, rather than substituting the router resolver.

A private mount namespace gives the probe its own `/etc/resolv.conf`.
The original router resolver and DNS settings are untouched. Website
measurement system-DNS queries therefore use the selected WAN's servers
and routing table. OONI's backend/session resolver may still use its own
DoH mechanisms through the configured backend proxy.

Requires full `ip` with UID-rule support and kernel mount namespaces.
If these are unavailable, a pinned run fails explicitly. No extra namespace
command package is required; the runner uses the kernel API directly.

## Cleanup and limitations

Normal completion, child failure, cancellation and timeouts remove the
temporary routing rules and the dedicated `inet purewrt_ooni` nftables table. Existing rules at priorities 97/98 cause the run
to stop without changing them. If the runner is forcibly killed with SIGKILL,
its rules can remain: inspect `ip -4 rule show` and `ip -6 rule show`, stop
any remaining probe, and remove only its matching UID rules and the
`inet purewrt_ooni` table before retrying.
Do not delete another application's rules to free these priorities.

OONI's successful exit means a measurement completed, not that the measured
site is accessible. DNS failures and blocked connections are measurement
results. Separate WAN directories identify the selected interface locally;
public results retain OONI's normal schema, not a custom WAN label.

## Router validation

A local-only website measurement completed sequentially on two WANs.
The probe's mount namespace contained the selected ISP resolver list;
the host resolver checksum was unchanged, and IPv4/IPv6 temporary rules
were removed afterward. The initial UID-only attempt leaked queries onto the default WAN and was
replaced with explicit nftables WAN marking plus an egress guard. The final
packet capture confirmed DNS requests and replies on each intended WAN; both
website measurements resolved and reported accessible. This is a smoke test of
the runner, not certification of every OONI nettest or IPv6 support.
