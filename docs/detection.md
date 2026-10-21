# Detection semantics and investigation notes

## Processing model

1. Read UTF-8 (optional BOM) input with a 65,536-character logical-line limit.
2. Validate records; normalize time to UTC and source IPs to canonical form. IPv4-mapped IPv6 addresses collapse to IPv4. Host and account names remain case-sensitive.
3. Sort by UTC timestamp, then original 1-based source line. Equal-timestamp records follow file order; a success cannot correlate with a later line at that timestamp.
4. Maintain failure windows for `(host, source_ip, user)` and `(host, source_ip)`. Window endpoints are inclusive: an event exactly 300 seconds old contributes with the default settings.
5. Evaluate rules at each applicable event. Evidence and counts reflect trigger time, not the entire later burst.

Window pruning uses queues and per-source user counters. Sorting is O(n log n); processing uses amortized queue updates, with additional work when materializing alerts. Input, scope state, and results remain in memory, so this is intentionally a bounded export analyzer.

## LW001 — repeated password failures

Five password, keyboard-interactive, or direct AWS console failures for the same source, host, and account within the window trigger a medium-severity alert. Public-key failures are excluded because they do not establish password guessing.

False positives include typing mistakes, stale automation credentials, account lockouts, and shared infrastructure. Review the owning service, source context, and surrounding records before deciding on a response.

## LW002 — multi-account guessing (spray-like)

Five distinct account names failing from the same source against one host trigger a medium-severity alert. Repeated failures for one name do not inflate the distinct count. Expired accounts are removed from the window.

This is a fan-out heuristic. MITRE describes password spraying as trying a small set of passwords across many accounts, but these records do not expose attempted passwords. The signal can also represent enumeration, credential stuffing, a shared egress address, scanning, or misconfiguration. It cannot distinguish these cases or identify slow distributed spraying.

## LW003 — success after repeated failures

A success with five earlier password, keyboard-interactive, or direct AWS console failures in the same source/host/account window triggers a high-severity triage alert. The successful method can be public key. The report retains that method so an analyst can distinguish a password login from a key-based login.

Every successful login clears that account scope's failure history, even when the success threshold was not reached or the alert was suppressed. A success from a different source, host, or account does not clear that scope.

The finding establishes temporal correlation only. Confirm the session with the account owner and inspect actual session activity before concluding that credentials were compromised.

## LW004 — distributed account guessing

Ten qualifying failures against one `(host, user)` from at least three distinct source IPs within the window trigger a high-severity signal. This catches patterns below individual source thresholds. Counters remove expired addresses as well as expired failures. Successful authentication clears the distributed history for that host/account, while its alert cooldown remains in effect.

The CloudTrail adapter encodes the AWS account ID as the host scope, preventing failures against identical IAM names in different AWS accounts from being combined. The rule does not establish that multiple addresses belong to the same actor. Rotating proxies, VPNs, and distributed clients can produce false positives.

## LW005 — AWS root sign-in without recorded MFA

A successful `aws-console` event with `identity_type: "Root"` and an explicit `mfa_used: false` triggers a high-severity control-review signal. Missing or unknown MFA values do not trigger this rule; neither do failed logins or IAM-user logins. It does not claim that a session is malicious.

## CloudTrail import

Use `--format cloudtrail` with an uncompressed JSON `Records` envelope or a single event. The 32 MiB input cap is checked before parsing. The entire export, including ignored records, is limited to 200,000 records.

The adapter reads direct `ConsoleLogin` records from `signin.amazonaws.com` for IAM and root identities. It maps the AWS account ID to `host: "aws:<accountId>"`, preserves explicit MFA evidence, and requires a valid source IP. Non-target events and known federated identity types are counted as ignored, including in strict mode. Malformed target records are rejected. Obscured IAM usernames are rejected to avoid merging unrelated identities.

AWS documents different MFA semantics for federated sessions. The adapter therefore does not apply these IAM/root rules to federation or IAM Identity Center sessions. It cannot evaluate MFA enforced by an external identity provider. It does not support Event History `CloudTrailEvent` wrappers, gzip input, or live AWS collection.

Cloud evidence refers to zero-based `Records[index]` positions; a single event object uses the reference `event`. Text evidence retains original 1-based line numbers. No access keys, user agents, login URLs, or raw CloudTrail records are copied to reports.

## Cooldowns and evidence

Each `(rule, scope)` emits at most once per configured window. A new qualifying event at or after the cooldown boundary can emit again. LW001, LW003, and LW005 use source/host/account scopes; LW002 uses source/host; LW004 uses host/account. A success clears the matching source/account failure history and host/account distributed history but does not clear cooldowns or the source-wide fan-out queue.

Overlapping alerts are retained because they answer different questions. Each includes a deterministic ID, UTC range, threshold-time failure count, source/host context, and source references. Up to 20 evidence events, 20 sorted source IPs, and 20 sorted account names are included per alert. Full distinct counts and sampling indicators remain available; the complete log is the source of truth. Success evidence includes the successful event and the latest contributing failure when one exists.

Input diagnostics keep the first 100 rejection reasons and the total rejection count. They do not copy raw rejected content. Normalized accepted fields can still contain sensitive information.

## Known limits

- No allowlists, baseline learning, external-identity-provider evaluation, or asset criticality enrichment.
- Long-running low-rate attempts can fall below the configured window and thresholds.
- Shared NAT addresses can combine unrelated activity; inconsistent host/account naming can split activity.
- Duplicate input records count as separate attempts. The tool does not deduplicate exports because no stable event identifier is available.
- Only the documented authentication formats are supported. Unsupported records and unrelated messages count as rejected input.
- Raw records are not included in reports. Use original line references for additional context.
- Per-file time ordering is deterministic, but it cannot correct inaccurate clocks or infer ordering beyond the recorded timestamp and file order.
- A report with no alerts is not evidence that a host is secure.

## References

- [MITRE ATT&CK T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [MITRE ATT&CK T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [AWS CloudTrail — Management Console sign-in events and MFA semantics](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html)

The implementations are project-specific heuristics. They do not reproduce or claim endorsement of MITRE detection analytics.
