"""Self-contained reports. Every value originating in a log is HTML escaped."""

from html import escape
from typing import Any


def _e(value: object) -> str:
    return escape(str(value), quote=True)


CSS = """
:root{color-scheme:dark;--bg:#0b1018;--panel:#141d29;--line:#2a3748;--ink:#edf4ff;--muted:#a6b4c7;--teal:#6ee7cd;--amber:#ffd186;--red:#ff9caa}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1200px;margin:auto;padding:44px 32px 64px}h1,h2,h3,p{margin:0}h1{font-size:clamp(30px,5vw,48px);line-height:1.15;letter-spacing:-1.5px;margin:10px 0 15px}h2{font-size:21px;margin-bottom:16px}h3{font-size:18px}
.eyebrow{color:var(--teal);font:700 12px/1.5 ui-monospace,monospace;letter-spacing:2px;text-transform:uppercase}.muted,small{color:var(--muted)}.intro{max-width:720px;color:var(--muted)}.header{display:flex;justify-content:space-between;gap:24px;align-items:flex-start}.chip{border:1px solid var(--line);padding:7px 12px;border-radius:100px;white-space:nowrap;color:var(--teal);font-size:12px}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:28px 0}.metric,.panel,.alert{border:1px solid var(--line);border-radius:14px;background:var(--panel)}.metric{padding:18px 22px}.metric strong{font-size:34px;display:block;line-height:1.3}.metric span{color:var(--muted);font-size:13px}.accent{color:var(--teal)}.high-text{color:var(--red)}
.layout{display:grid;grid-template-columns:minmax(0,2fr) minmax(260px,1fr);gap:24px}.panel{padding:22px;margin-bottom:20px}.alert{padding:22px;margin-bottom:16px;border-left:3px solid var(--amber)}.alert.high{border-left-color:var(--red)}.alert-head{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:12px}.badge{font:700 11px ui-monospace,monospace;color:var(--amber);background:#3a3023;border-radius:6px;padding:5px 8px;text-transform:uppercase}.high .badge{color:var(--red);background:#3d2632}
.meta{display:flex;flex-wrap:wrap;gap:8px 18px;margin:8px 0 12px;color:var(--muted);font-size:13px}code{font:13px ui-monospace,Consolas,monospace;overflow-wrap:anywhere;color:var(--teal)}.detail{font-size:14px;color:var(--muted);margin-top:12px}.time{font-size:12px;color:var(--muted);margin-top:12px}details{border-top:1px solid var(--line);margin-top:16px;padding-top:12px}summary{cursor:pointer;color:var(--teal);font-size:13px}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:12px;margin-top:10px}th,td{text-align:left;border-bottom:1px solid var(--line);padding:8px 6px;overflow-wrap:anywhere}th{color:var(--muted);font-weight:500}.source{display:flex;justify-content:space-between;gap:12px;margin:12px 0}.bar{height:5px;background:#243444;border-radius:4px;margin-bottom:18px}.fill{height:100%;background:var(--teal);border-radius:4px}.notice{border:1px solid #7c623b;color:var(--amber);padding:14px 18px;border-radius:10px;margin:20px 0}.footer{border-top:1px solid var(--line);padding-top:20px;margin-top:28px;font-size:12px;color:var(--muted)}.wrap{overflow-wrap:anywhere}
@media(max-width:800px){main{padding:24px 16px}.layout{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.header{display:block}.chip{display:inline-block;margin-top:18px}.alert-head{align-items:flex-start}h3{font-size:16px}}
@media print{body{background:white;color:black}main{max-width:none;padding:0}.metric,.panel,.alert{background:white;break-inside:avoid}details{display:block}.muted,.intro,.detail,.meta,.time,.footer,small{color:#444}code,.eyebrow,.accent,summary{color:#075e53}}
"""


def render_html(report: dict[str, Any]) -> str:
    stats, config = report["summary"], report["config"]
    cards = []
    for alert in sorted(report["alerts"], key=lambda a: (a["severity"] != "high", a["last_seen"], a["id"])):
        rows = "".join(
            "<tr>" + "".join(f"<td>{_e(event[key])}</td>" for key in ("location", "timestamp", "user", "source_ip", "outcome", "method"))
            + f'<td>{"Unknown" if event["mfa_used"] is None else "Yes" if event["mfa_used"] else "No"}</td></tr>'
            for event in alert["evidence"]
        )
        sample_note = " · sampled" if alert["evidence_sampled"] else ""
        user_note = f" (first {len(alert['users'])} of {alert['user_count']})" if alert["user_count"] > len(alert["users"]) else ""
        source_label = "Source" if alert["source_count"] == 1 else f"Sources ({alert['source_count']})"
        source_text = ", ".join(alert["source_ips"])
        if alert["source_count"] > len(alert["source_ips"]):
            source_text += " (sampled)"
        cards.append(f"""<article class="alert {_e(alert['severity'])}">
<div class="alert-head"><div><div class="eyebrow">{_e(alert['rule_id'])} / {_e(alert['technique'])}</div><h3>{_e(alert['title'])}</h3></div><span class="badge">{_e(alert['severity'])}</span></div>
<div class="meta"><span>{_e(source_label)} <code>{_e(source_text)}</code></span><span>Host <code>{_e(alert['host'])}</code></span><span>{alert['failure_count']} failures · {alert['user_count']} account(s)</span></div>
<p class="wrap">Accounts: <code>{_e(', '.join(alert['users']))}</code>{_e(user_note)}</p>
<p class="detail">{_e(alert['guidance'])}</p><p class="time">{_e(alert['first_seen'])} → {_e(alert['last_seen'])} · UTC</p>
<details><summary>Inspect {len(alert['evidence'])} evidence records{sample_note} · #{_e(alert['id'])}</summary><div class="table-wrap"><table><thead><tr><th>Reference</th><th>Timestamp</th><th>Account</th><th>Source IP</th><th>Outcome</th><th>Method</th><th>MFA used</th></tr></thead><tbody>{rows}</tbody></table></div></details></article>""")
    maximum = max((entry["failures"] for entry in report["top_sources"]), default=1)
    sources = "".join(
        f'<div class="source"><code>{_e(entry["source_ip"])}</code><span>{entry["failures"]}</span></div><div class="bar"><div class="fill" style="width:{entry["failures"] / maximum * 100:.1f}%"></div></div>'
        for entry in report["top_sources"]
    ) or '<p class="muted">No failed authentications.</p>'
    warning = ""
    if stats["rejected_records"]:
        warning = f'<div class="notice">Partial input: {stats["rejected_records"]} record(s) rejected. Review diagnostics before interpreting the findings.</div>'
    diagnostics = "".join(f'<li>{_e(entry["location"])}: {_e(entry["reason"])}</li>' for entry in report["diagnostics"])
    if report["diagnostics_truncated"]:
        diagnostics += '<li>Only the first 100 diagnostics are shown.</li>'
    diagnostics_panel = f'<section class="panel"><h2>Input diagnostics</h2><ul>{diagnostics}</ul></section>' if diagnostics else ""
    alerts_html = "".join(cards) or '<div class="panel"><h3>No rules triggered</h3><p class="detail">No configured thresholds were crossed in the parsed records. This does not establish that the environment is secure.</p></div>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>LogWatch — investigation report</title><style>{CSS}</style></head>
<body><main><header class="header"><div><p class="eyebrow">LogWatch / Cloud + SSH authentication</p><h1>Authentication investigation.</h1><p class="intro">Review distributed guessing, suspicious login sequences, and AWS root MFA signals with evidence from your log exports.</p></div><span class="chip">● Local analysis · v{_e(report['tool_version'])}</span></header>
<section class="metrics" aria-label="Analysis summary"><div class="metric"><strong>{stats['parsed_events']}</strong><span>Authentication events</span></div><div class="metric"><strong class="accent">{stats['alerts']}</strong><span>Detection signals</span></div><div class="metric"><strong class="high-text">{stats['high']}</strong><span>High severity signals</span></div><div class="metric"><strong>{stats['source_count']}</strong><span>Unique source addresses</span></div></section>{warning}
<div class="layout"><section><h2>Investigation queue</h2>{alerts_html}</section><aside><section class="panel"><p class="eyebrow">Source activity</p><h2>Failed authentications</h2>{sources}<small>Top 10 sources · all supported methods</small></section><section class="panel"><h2>Analysis context</h2><p class="detail wrap">File: <code>{_e(report['source'])}</code><br>{stats['failures']} failures / {stats['successes']} successes<br>{stats['host_count']} host(s) / {stats['rejected_records']} rejected record(s)<br>{stats['ignored_records']} non-target records ignored</p><p class="detail">Window: {config['window_seconds']} seconds<br>Repeated failures: ≥ {config['brute_force_threshold']}<br>Spray-like fan-out: ≥ {config['spray_user_threshold']} accounts<br>Success correlation: ≥ {config['success_failure_threshold']} failures<br>Distributed guessing: ≥ {config['distributed_failure_threshold']} failures / ≥ {config['distributed_source_threshold']} sources</p><p class="detail">Alerts capture evidence at trigger time. Each rule and scope has a one-window cooldown.</p></section><section class="panel"><p class="eyebrow">Analyst note</p><p class="detail">These heuristics identify patterns for review. They do not confirm compromise or reveal attempted passwords. No network requests or automated response actions are performed.</p></section>{diagnostics_panel}</aside></div>
<footer class="footer">LogWatch · UTC timestamps · schema {_e(report['schema_version'])} · Log-derived values are escaped. Reports can contain sensitive account and host information.</footer></main></body></html>
"""
