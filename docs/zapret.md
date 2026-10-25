# Zapret applications and client testing

Zapret is optional. Install the separate `zapret` package to use the Zapret page.
Neither normal Zapret processing nor client testing requires mwan3.

## Configure an application

1. Open **PureWRT → Zapret → Strategy library**. Choose a catalog entry or create
   a user entry. Preview its parameters and TCP/UDP port scope.
2. Add an application such as `discord` to the routing strategies table. Assign
   a library strategy to each WAN where that application should use Zapret.
   Different WANs can use different strategies.
3. In **Sections / routing**, select action **Zapret** and the application.
   Add the destination lists or client assignments that identify its traffic.
4. **Save & Apply**, then check runtime status and section counters.

The application name is a label, not automatic application detection. Destination
lists identify matching sites/IPs; a client assignment covers that client's traffic.
The library's protocol and port settings further restrict Zapret processing.

OpenWrt selects the outgoing WAN. PureWRT applies the strategy assigned to the
actual egress device. A WAN with no assignment receives no Zapret processing;
it does not automatically fall back to a proxy. With mwan3, new connections after
failover use the surviving WAN's assignment. Existing sessions may need reconnecting.

Production uses one shared nfqws2 process and queue across applications and WANs.
The client tester uses a separate temporary process. PureWRT validates reserved
mark bits before apply and preserves unrelated routing marks.

## Test with a LAN client

Select a directly attached, awake IPv4 client, a WAN with an IPv4 default route,
and a strategy. Start the five-minute test, then restart the application on the
client and exercise login, gameplay and voice separately.

During the test, that client's internet TCP/UDP traffic bypasses its normal
PureWRT proxy routing and uses the selected WAN. Local access and router DNS keep
their ordinary paths. IPv6 internet forwarding is temporarily blocked for the
client. The test stays pinned to its WAN even if that WAN fails.

- Pair one TCP-only and one UDP-only candidate, or select a combined candidate.
- Select **Manual strategy (paste parameters)** to test pasted nfqws2 options
  without creating a library entry. Include `--filter-tcp=` or `--filter-udp=`;
  combine profiles with `--new`. Protocols and ports are inferred from the filters.
  Paste parameters only, not an executable or shell command. Process/routing
  options and Lua imports are rejected. Built-in blobs and inline hex are supported;
  use the library for custom blob files. Manual input is limited to 16 KiB.
  You can edit and switch manual parameters during a test. Adding the result to
  routing saves the tested parameters, even if the text box has since been edited.
- **Switch strategy** changes the candidate while retaining the temporary route.
  **Previous/Next** switches immediately during a test, within the same protocol
  category. Reconnect the application to exercise a new handshake.
- Switching does not extend the five-minute deadline. Closing the page does not
  stop the worker. **Stop and restore** or timeout removes temporary routing.
- Queue counters confirm that packets reached nfqws, not that the application
  works. Judge success on the client.

Avoid Save & Apply or firewall reloads during a test. The runner stops when its
temporary routing integration disappears. Flow-offload exclusions are temporary
and scoped to the selected client; no persistent offload setting is changed.

After success, **Add to routing strategies** stages the tested WAN assignment in
the named application, preserving its other WAN assignments. It references the
library entry; a separate TCP/UDP pair needs one combined library entry, reused
when already present. Select the application in a routing section and Save & Apply.
Testing alone does not create persistent applications or profiles.

## Library and backups

Catalog entries are read-only; duplicate one to edit it locally. User entries can
be created, edited, imported and exported as JSON. Parameters and blob references
are validated and dry-run checked with the installed nfqws2 before saving.
This verifies syntax, not effectiveness against a particular ISP's DPI.

User entries live in `/etc/purewrt/zapret_user_candidates.json` (128 entries,
1 MiB maximum). Uploaded blobs live in `/etc/purewrt/blobs/` and are limited to
64 KiB each. JSON exports contain blob references, not the binary files: copy
custom blobs separately when moving a library to another router. Both paths are
included in OpenWrt sysupgrade backups when configuration preservation is enabled;
PureWRT's UCI export alone does not include these files. Referenced entries cannot be deleted or renamed.
Library edits take effect in production on the next apply.

## Upgrade from 0.8.x

Enabled old Zapret profile/inline-strategy configurations must be recreated as
applications with WAN-to-library assignments. There is no automatic migration.
Back up custom parameters and blobs before replacing those entries.

Routers without Zapret configuration, including old disabled default entries,
can upgrade without configuring Zapret. They do not launch nfqws or require mwan3.

## Validation scope

The shared daemon has been tested with router-originated IPv4 HTTPS, concurrent
WAN requests, and controlled mwan3 failover/recovery. Earlier client-tester runs
confirmed Android Discord chat and voice. Those results do not establish IPv6,
forwarded-client voice, or sustained-throughput coverage for the shared daemon.
See [engineering verification notes](zapret2-review.md) for the exact scope.
