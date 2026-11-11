# DNS classification when a section is disabled

An enabled rule provider assigned to an explicitly disabled section produces no
DNS, CIDR or native firewall output. The section's static and dynamic nftables
sets are absent, and apply does not snapshot or restore its dynamic members.
Virtual direct/reject provider targets still work when no explicit section exists.
Enabled sections retain section-local deduplication and priority dispatch.

Generation fingerprint version 6 invalidates earlier generated output even when
UCI inputs have not changed. Fragment reconciliation removes the old disabled
section fragment; apply replaces the nft table and restarts dnsmasq (not reload).
No UCI migration or provider reassignment is required.

## Classification verification

A disabled section's domain mappings can take precedence over an enabled
overlapping section, leaving resolved addresses in a set with no routing
consumer.

A temporary dnsmasq 2.93 process listened only on 127.0.0.1:15354, with no
DHCP, no hosts file, no cache, and upstream 127.0.0.1:53. Two separate
youtube.com directives targeted deliberately nonexistent probe sets A and B.
A fresh reply caused an insertion attempt only into A, even though A did not
exist. Removing A's directive and starting a fresh process caused an insertion
attempt into B. The logs therefore demonstrate mapping selection and fallback
after configuration removal, not successful kernel insertion or playback.
Both temporary processes and their files were removed. Production dnsmasq and
firewall configuration were unchanged.

Duplicate directives are not a reliable way to populate every overlapping set.
This fix preserves existing enabled-section output and ordering; it does not
change enabled overlap to multi-set classification or change suffix matching.

## Deployment and validation

Obtain approval before changing a production router. Save the installed
binary, UCI configuration and generated fragments/rules for rollback. Install
the validated build and run purewrt apply --force; do not reboot. Expect a DNS
interruption during the required dnsmasq restart.

Verify that no fragment references the disabled section's DNS sets, that
those sets no longer exist, and that the enabled section's domain mappings
and TPROXY dispatch remain. Perform fresh lookups of the affected service's
hostnames and check that returned addresses enter the enabled section's sets.
The client may retain old DNS answers: wait for expiry or restart its app/DNS
session before concluding fallback failed. Do not copy all disabled-set IPs
to another section: those addresses have no reliable domain provenance.

Test the affected service from the client while observing section counters,
Mihomo connections, and a bounded packet capture for WAN retransmissions.
Ping alone is insufficient. Classification verification does not establish
that the service issue is resolved; that requires a service-level test after
an approved deployment. Avoid broad conntrack flushes; any connection reset
should be scoped to the test client and approved.
