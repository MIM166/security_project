"""Generate a standalone, offline HTML report and CSV from measured lab evidence."""
import argparse
import csv
import html
import json
from pathlib import Path

from evidence import counter_points
from lab_common import read_events


def render(output):
    summary = json.loads((output / "summary.json").read_text())
    rows = summary["trials"]
    columns = ["condition", "repeat", "passed", "bytes_received", "complete", "elapsed_seconds",
               "overall_goodput_mbps", "pre_goodput_mbps", "post_goodput_mbps", "reduction_percent", "decision"]
    with (output / "summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    cards = []
    for row in rows:
        name = row["directory"]
        events = read_events(output / name / "receiver.jsonl")
        points = counter_points(events)
        series = [(b[0] - points[0][0], (b[1] - a[1]) * 8 / (b[0] - a[0]) / 1e6)
                  for a, b in zip(points, points[1:]) if b[0] > a[0]]
        duration = max(row["elapsed_seconds"], 0.01)
        peak = max([v for _, v in series] + [summary["config"]["rate"] * 8 / 1e6]) * 1.15
        coordinates = " ".join(f"{50 + t / duration * 670:.1f},{190 - v / peak * 155:.1f}" for t, v in series)
        attack_x = 50 + row["attack_elapsed_seconds"] / duration * 670 if row["attack_elapsed_seconds"] is not None else None
        marker = (f'<line x1="{attack_x:.1f}" x2="{attack_x:.1f}" y1="25" y2="190" stroke="#e7aa55" stroke-dasharray="5 5"/>'
                  f'<text x="{min(attack_x + 6, 610):.1f}" y="22" fill="#e7aa55">ICMP arrival</text>') if attack_x is not None else ""
        graph = f'''<svg viewBox="0 0 750 225" role="img" aria-label="Receiver goodput in megabits per second over elapsed seconds">
<path d="M50 30V190H720" fill="none" stroke="#627087"/><text x="6" y="38">{peak:.1f}</text>
<text x="25" y="194">0</text><text x="50" y="215">0 s</text><text x="660" y="215">{duration:.1f} s</text>
<text x="55" y="22">Received payload · Mbps</text>{marker}
<polyline points="{coordinates}" fill="none" stroke="#5dd8c4" stroke-width="2.5"/></svg>'''
        checks = "".join(f'<li class="{"ok" if value else "bad"}">{"PASS" if value else "FAIL"} · {html.escape(key.replace("_", " "))}</li>' for key, value in row["checks"].items())
        reduction = "—" if row["reduction_percent"] is None else f'{row["reduction_percent"]:.1f}%'
        cards.append(f'''<article><div class="cardtitle"><h2>{html.escape(row['condition'])} <small>run {row['repeat']}</small></h2>
<b class="{'ok' if row['passed'] else 'bad'}">{'PASS' if row['passed'] else 'FAIL'}</b></div>
<div class="stats"><span><strong>{row['bytes_received'] / 1048576:.2f} MiB</strong>received</span>
<span><strong>{row['elapsed_seconds']:.2f} s</strong>transfer duration</span>
<span><strong>{row['overall_goodput_mbps']:.2f} Mbps</strong>overall goodput</span>
<span><strong>{reduction}</strong>within-trial rate reduction</span></div>{graph}
<p>Policy: <code>{html.escape(row['decision'])}</code> · Payload complete: <b>{row['complete']}</b></p>
<details><summary>Evidence checks and files</summary><ul>{checks}</ul>
<p><a href="{name}/capture.pcap">PCAP</a> · <a href="{name}/capture.txt">tcpdump decode</a> ·
<a href="{name}/sender.jsonl">Sender events</a> · <a href="{name}/receiver.jsonl">Receiver events</a> ·
<a href="{name}/result.json">Trial result</a></p></details></article>''')
    comparisons = "".join(f'<tr><td>{html.escape(r["condition"])}</td><td>{r["repeat"]}</td><td>{r["overall_goodput_mbps"]:.2f}</td><td>{"—" if r.get("post_vs_baseline_percent") is None else format(r["post_vs_baseline_percent"], ".1f")}</td></tr>' for r in rows)
    passed = sum(row["passed"] for row in rows)
    document = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ICMP / TCP · Experiment report</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#0b1220;color:#dbe5f2;font:16px/1.6 system-ui,sans-serif}}
main{{max-width:1080px;margin:auto;padding:42px 24px}}header{{margin-bottom:32px}}h1{{font-size:clamp(28px,5vw,46px);line-height:1.15;margin:10px 0}}h2{{font-size:20px;margin:0}}small{{color:#91a3ba;font-weight:400}}.eyebrow{{color:#5dd8c4;letter-spacing:.16em;font-size:12px}}p{{color:#aebed2}}a{{color:#77d9ee}}article,.notice{{background:#131f31;border:1px solid #29374b;border-radius:12px;padding:24px;margin:20px 0}}.cardtitle{{display:flex;justify-content:space-between;gap:16px}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:24px 0}}.stats span{{color:#91a3ba;font-size:12px}}strong{{display:block;color:#e2edf8;font-size:20px}}.ok{{color:#5dd8c4}}.bad{{color:#ff9292}}svg{{width:100%;height:auto}}svg text{{fill:#91a3ba;font:11px system-ui}}li{{font-size:14px}}summary{{cursor:pointer}}table{{width:100%;border-collapse:collapse;font-size:14px}}th,td{{text-align:left;border-bottom:1px solid #29374b;padding:10px}}code{{color:#e7aa55}}@media(max-width:600px){{.stats{{grid-template-columns:repeat(2,1fr)}}main{{padding:24px 14px}}article{{padding:16px}}}}@media print{{:root{{color-scheme:light}}body{{background:white;color:black}}article,.notice{{background:white;break-inside:avoid}}p,strong,h2,td,th{{color:black}}details{{display:block}}}}
</style><main><header><span class="eyebrow">CSE 406 · PROJECT 12 · MEASURED LAB EVIDENCE</span>
<h1>ICMP blind attacks against TCP</h1><p>Connection abort, throughput reduction, and defensive policy comparison.<br>
Proposal: Shemanty Mahjabin (2105091) · Mahabuba Sharmin Mim (2105103).</p>
<strong>{passed} / {len(rows)} conditions passed</strong><p>{html.escape(summary['created_utc'])} · {html.escape(summary['kernel'])}</p></header>
<div class="notice"><b>How to interpret this experiment</b><p>Real TCP data and raw ICMP packets travel through isolated Linux namespaces. Legacy abort and reduced application pacing are user-space compatibility behavior. They do not demonstrate a vulnerable Linux TCP stack or a changed kernel congestion window. The quoted sequence is fixed before each trial; kernel SND.UNA/SND.NXT are unavailable to this harness. Optional kernel trials only observe this particular fixed quotation.</p></div>
<section><h2>Condition comparison</h2><p>Post-window reduction compares delivered-byte goodput with the baseline trial in the same repetition. Timing windows omit the ICMP transition. Overall goodput includes the full transfer duration.</p>
<table><thead><tr><th>Condition</th><th>Run</th><th>Overall Mbps</th><th>Post-window reduction vs baseline %</th></tr></thead><tbody>{comparisons}</tbody></table></section>
{''.join(cards)}<footer><p><a href="summary.csv">Download CSV</a> · <a href="summary.json">Summary JSON</a> · <a href="environment.json">Environment</a></p>
<p>Sources: <a href="https://www.rfc-editor.org/rfc/rfc792">RFC 792 packet format</a> · <a href="https://www.rfc-editor.org/rfc/rfc5927">RFC 5927 historical attacks and mitigations</a> · <a href="https://www.rfc-editor.org/rfc/rfc6633">RFC 6633 Source Quench deprecation</a>.</p></footer></main></html>'''
    (output / "report.html").write_text(document, encoding="utf-8")
    markdown = ["# ICMP/TCP experiment results", "", f"Measured on {summary['created_utc']} ({summary['kernel']}).",
                "", f"Passed: {passed}/{len(rows)} conditions.", "",
                "| Condition | Run | Complete | Received bytes | Duration s | Overall Mbps | Passed |",
                "|---|---:|---|---:|---:|---:|---|"]
    for row in rows:
        markdown.append(f"| {row['condition']} | {row['repeat']} | {row['complete']} | {row['bytes_received']} | {row['elapsed_seconds']:.2f} | {row['overall_goodput_mbps']:.2f} | {row['passed']} |")
    markdown += ["", "Legacy effects are application compatibility policies, not evidence of Linux kernel vulnerability.",
                 "See report.html, summary.json, and each condition's PCAP and endpoint logs for the underlying measurements."]
    (output / "RESULTS.md").write_text("\n".join(markdown) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    render(parser.parse_args().output)
