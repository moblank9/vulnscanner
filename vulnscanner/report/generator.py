"""HTML report generator - creates a detailed vulnerability assessment report."""
import json
from datetime import datetime
from typing import Any, Optional
from vulnscanner.risk.scorer import RiskScore, SEVERITY_COLORS

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Scan Report - {target}</title>
<style>
  :root {{
    --bg: #0d1117;
    --card: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --text-muted: #8b949e;
    --critical: {c_critical};
    --high: {c_high};
    --medium: {c_medium};
    --low: {c_low};
    --info: {c_info};
    --none: {c_none};
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6;
    padding: 20px;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1, h2, h3 {{ margin-bottom: 0.5em; }}
  h1 {{ font-size: 2em; }}
  h2 {{ font-size: 1.5em; border-bottom: 1px solid var(--border); padding-bottom: 0.3em; }}
  .header {{ text-align: center; padding: 40px 0; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 24px 0; }}
  .summary-card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 20px; text-align: center;
  }}
  .summary-card .value {{ font-size: 2.5em; font-weight: 700; }}
  .summary-card .label {{ color: var(--text-muted); font-size: 0.9em; }}
  .severity-badge {{
    display: inline-block; padding: 4px 12px; border-radius: 12px;
    font-size: 0.8em; font-weight: 600; text-transform: uppercase;
  }}
  .finding {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; margin: 12px 0; overflow: hidden; }}
  .finding-header {{ display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; cursor: pointer; }}
  .finding-header:hover {{ background: rgba(255,255,255,0.03); }}
  .finding-body {{ padding: 16px; border-top: 1px solid var(--border); display: none; }}
  .finding-body.open {{ display: block; }}
  .finding-body p {{ margin-bottom: 8px; }}
  .finding-body .label {{ color: var(--text-muted); font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }}
  .score-meter {{
    height: 24px; background: #21262d; border-radius: 12px; overflow: hidden;
    margin: 16px 0;
  }}
  .score-fill {{ height: 100%; border-radius: 12px; transition: width 0.5s; }}
  .open-ports-table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
  .open-ports-table th, .open-ports-table td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); }}
  .open-ports-table th {{ color: var(--text-muted); font-size: 0.85em; text-transform: uppercase; }}
  .meta {{ color: var(--text-muted); font-size: 0.9em; }}
  .footer {{ text-align: center; color: var(--text-muted); font-size: 0.8em; padding: 40px 0; }}
  .tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75em; margin: 2px; }}
  .btn {{ background: none; border: 1px solid var(--border); color: var(--text); padding: 8px 16px; border-radius: 6px; cursor: pointer; }}
  .btn:hover {{ background: rgba(255,255,255,0.05); }}
  .filter-bar {{ display: flex; gap: 8px; margin: 16px 0; flex-wrap: wrap; }}
  .critical {{ color: var(--critical); }} .high {{ color: var(--high); }} .medium {{ color: var(--medium); }} .low {{ color: var(--low); }} .info {{ color: var(--info); }} .none {{ color: var(--none); }}
  .bg-critical {{ background: var(--critical); }} .bg-high {{ background: var(--high); }} .bg-medium {{ background: var(--medium); }} .bg-low {{ background: var(--low); }} .bg-info {{ background: var(--info); }} .bg-none {{ background: var(--none); }}
  pre {{ background: #161b22; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 0.9em; }}
  @media print {{
    body {{ background: white; color: black; }}
    .finding {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1>Vulnerability Scan Report</h1>
  <p>Target: <strong>{target}</strong></p>
  <p class="meta">Scan Date: {scan_date} | IP: {ip_address}</p>
</div>

<div class="summary-grid">
  <div class="summary-card">
    <div class="value {risk_overall_severity}">{risk_score:.1f}</div>
    <div class="label">Risk Score (0-10)</div>
    <div><span class="severity-badge {risk_overall_severity}" style="background:{severity_color}22;color:{severity_color};border:1px solid {severity_color}">{risk_overall_severity}</span></div>
  </div>
  <div class="summary-card">
    <div class="value">{open_port_count}</div>
    <div class="label">Open Ports</div>
  </div>
  <div class="summary-card">
    <div class="value">{count_critical}</div>
    <div class="label">Critical</div>
  </div>
  <div class="summary-card">
    <div class="value">{count_high}</div>
    <div class="label">High</div>
  </div>
  <div class="summary-card">
    <div class="value">{count_medium}</div>
    <div class="label">Medium</div>
  </div>
  <div class="summary-card">
    <div class="value">{count_low}</div>
    <div class="label">Low</div>
  </div>
</div>

<div class="score-meter">
  <div class="score-fill" style="width:{score_pct:.1f}%;background:{severity_color};"></div>
</div>

<h2>Open Ports &amp; Services</h2>
{open_ports_section}

<h2>Findings by Severity</h2>
<div class="filter-bar">
  <button class="btn" onclick="filterFindings('all')">All</button>
  <button class="btn" onclick="filterFindings('critical')">Critical</button>
  <button class="btn" onclick="filterFindings('high')">High</button>
  <button class="btn" onclick="filterFindings('medium')">Medium</button>
  <button class="btn" onclick="filterFindings('low')">Low</button>
  <button class="btn" onclick="filterFindings('info')">Info</button>
</div>

{findings_section}

<h2>Open Ports Detail</h2>
{open_ports_detail}

<h2>CVE Matches</h2>
{cve_section}

<h2>SSL/TLS Certificate</h2>
{ssl_section}

<h2>HTTP Security Headers</h2>
{headers_section}

<h2>Discovered Paths</h2>
{dir_section}

<h2>Service Fingerprints</h2>
{fingerprint_section}

<div class="footer">
  <p>Generated by VulnScanner v1.0.0</p>
  <p><strong>Disclaimer:</strong> This report is for authorized security testing purposes only.
  The scan was performed against {target} with the permission of the owner.
  Unauthorized scanning is illegal and unethical.</p>
</div>

</div>

<script>
function toggleFinding(id) {{
  var el = document.getElementById('fb-' + id);
  if (el) el.classList.toggle('open');
}}
function filterFindings(sev) {{
  var items = document.querySelectorAll('.finding');
  items.forEach(function(item) {{
    if (sev === 'all' || item.dataset.severity === sev) {{
      item.style.display = '';
    }} else {{
      item.style.display = 'none';
    }}
  }});
}}
</script>
</body>
</html>
"""


class ReportGenerator:
    def __init__(self, risk_score: RiskScore):
        self.risk_score = risk_score

    def _escape(self, text: Any) -> str:
        s = str(text)
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    def _findings_html(self) -> str:
        parts = []
        for i, f in enumerate(self.risk_score.findings):
            sev = f.severity.lower()
            color = SEVERITY_COLORS.get(sev, "#6c757d")
            details_json = self._escape(json.dumps(f.details, indent=2))
            cvss_tag = f"CVSS: {f.cvss_score:.1f}" if f.cvss_score > 0 else ""

            parts.append(f'''
<div class="finding" data-severity="{sev}">
  <div class="finding-header" onclick="toggleFinding({i})">
    <div>
      <span class="severity-badge" style="background:{color}22;color:{color};border:1px solid {color}">{sev}</span>
      <strong>{self._escape(f.title)}</strong>
      <span class="meta"> | {self._escape(f.category)}</span>
    </div>
    <div>
      <span class="meta">{cvss_tag}</span>
      <span style="margin-left:8px;">&#9660;</span>
    </div>
  </div>
  <div class="finding-body" id="fb-{i}">
    <p><span class="label">Description</span><br>{self._escape(f.description)}</p>
    <p><span class="label">Remediation</span><br>{self._escape(f.remediation)}</p>
    {f'<pre>{details_json}</pre>' if f.details else ''}
  </div>
</div>''')
        return "\n".join(parts)

    def _open_ports_html(self, ports: list[dict]) -> str:
        if not ports:
            return "<p class='meta'>No open ports found.</p>"
        rows = ""
        for p in ports:
            banner = self._escape(p.get("banner", "")[:100])
            version = self._escape(p.get("version", ""))
            service = self._escape(p["service"])
            rows += f"<tr><td>{p['port']}</td><td>{service}</td><td>{banner}</td><td>{version}</td></tr>\n"
        return f'''<table class="open-ports-table">
<thead><tr><th>Port</th><th>Service</th><th>Banner</th><th>Version</th></tr></thead>
<tbody>{rows}</tbody></table>'''

    def _cve_section_html(self, cve_results: list[dict]) -> str:
        if not cve_results:
            return "<p class='meta'>No CVE matches found.</p>"
        parts = []
        for cr in cve_results:
            svc = self._escape(cr.get("service", ""))
            ver = self._escape(cr.get("version", ""))
            parts.append(f"<h3>{svc} ({ver})</h3>")
            for m in cr.get("matches", []):
                sev = m.get("severity", "info").lower()
                color = SEVERITY_COLORS.get(sev, "#6c757d")
                cve_id = self._escape(m.get("cve_id", ""))
                desc = self._escape(m.get("description", ""))
                affected = self._escape(m.get("affected_version", ""))
                remed = self._escape(m.get("remediation", ""))
                cvss = m.get("cvss_score", 0)
                parts.append(f'''
<div class="finding" data-severity="{sev}">
  <div class="finding-header">
    <div>
      <span class="severity-badge" style="background:{color}22;color:{color};border:1px solid {color}">{sev}</span>
      <strong>{cve_id}</strong>
      <span class="meta"> | CVSS: {cvss:.1f}</span>
    </div>
  </div>
  <div class="finding-body open">
    <p><span class="label">Description</span><br>{desc}</p>
    <p><span class="label">Affected</span><br>{affected}</p>
    <p><span class="label">Remediation</span><br>{remed}</p>
  </div>
</div>''')
        return "\n".join(parts)

    def _ssl_section_html(self, ssl_result: Any) -> str:
        if not ssl_result or not ssl_result.certificate:
            return "<p class='meta'>No SSL/TLS certificate information available.</p>"
        c = ssl_result.certificate
        expired_tag = '<span class="high">Yes</span>' if c.expired else '<span class="none">No</span>'
        selfsigned_tag = '<span class="medium">Yes</span>' if c.self_signed else '<span class="none">No</span>'
        tls12_tag = '<span class="none">Supported</span>' if ssl_result.supports_tls12 else '<span class="medium">Not Supported</span>'
        tls13_tag = '<span class="none">Supported</span>' if ssl_result.supports_tls13 else '<span class="medium">Not Supported</span>'

        html = f'''
<table class="open-ports-table">
<tr><th>Property</th><th>Value</th></tr>
<tr><td>Subject</td><td>{self._escape(c.subject)}</td></tr>
<tr><td>Issuer</td><td>{self._escape(c.issuer)}</td></tr>
<tr><td>Serial</td><td>{self._escape(c.serial)}</td></tr>
<tr><td>Valid From</td><td>{self._escape(c.not_before)}</td></tr>
<tr><td>Valid To</td><td>{self._escape(c.not_after)}</td></tr>
<tr><td>Days Remaining</td><td>{c.days_remaining}</td></tr>
<tr><td>Expired</td><td>{expired_tag}</td></tr>
<tr><td>Self-Signed</td><td>{selfsigned_tag}</td></tr>
<tr><td>Protocol</td><td>{self._escape(ssl_result.protocol_version)}</td></tr>
<tr><td>TLS 1.2</td><td>{tls12_tag}</td></tr>
<tr><td>TLS 1.3</td><td>{tls13_tag}</td></tr>
</table>'''
        if c.san:
            san_list = ", ".join(self._escape(s) for s in c.san)
            html += f"<h4>Subject Alternative Names</h4><p>{san_list}</p>"
        if ssl_result.weak_protocols:
            weak_list = ", ".join(self._escape(p) for p in ssl_result.weak_protocols)
            html += f'<p><span class="high">Weak protocols supported:</span> {weak_list}</p>'
        return html

    def _headers_section_html(self, header_result: Any) -> str:
        if not header_result:
            return "<p class='meta'>No HTTP header data available.</p>"
        parts = [f'<p class="meta">URL: {self._escape(header_result.url)} | Status: {header_result.status_code}</p>']
        for fh in header_result.findings:
            cls = "none" if fh.present else "high"
            icon = "&#10003;" if fh.present else "&#10007;"
            header_name = self._escape(fh.header)
            header_val = self._escape(fh.value[:80])
            parts.append(f'<div><span class="{cls}">{icon}</span> <strong>{header_name}</strong> <span class="meta">{header_val}</span></div>')
        return "\n".join(parts)

    def _dir_section_html(self, dir_result: Any) -> str:
        if not dir_result or not dir_result.findings:
            return "<p class='meta'>No interesting paths discovered.</p>"
        parts = [f'<p class="meta">{len(dir_result.findings)} paths found (checked {dir_result.total_checked}).</p>']
        for d in dir_result.findings:
            if d.status_code in (200, 201, 204):
                cls = "high"
            elif d.status_code in (301, 302, 303):
                cls = "medium"
            else:
                cls = "info"
            path = self._escape(d.path)
            title = f"<em>{self._escape(d.title)}</em>" if d.title else ""
            parts.append(f'<div><span class="{cls}">HTTP {d.status_code}</span> <strong>{path}</strong> <span class="meta">({d.content_length} bytes)</span> {title}</div>')
        return "\n".join(parts)

    def _fingerprint_section_html(self, fingerprints: list[dict]) -> str:
        if not fingerprints:
            return "<p class='meta'>No service fingerprints available.</p>"
        rows = ""
        for fp in fingerprints:
            svc = self._escape(fp.get("service_name", ""))
            ver = self._escape(fp.get("service_version", ""))
            conf = fp.get("confidence", 0)
            rows += f"<tr><td>{fp.get('port')}</td><td>{svc}</td><td>{ver}</td><td>{conf:.0%}</td></tr>\n"
        return f'''<table class="open-ports-table">
<thead><tr><th>Port</th><th>Service</th><th>Version</th><th>Confidence</th></tr></thead>
<tbody>{rows}</tbody></table>'''

    def _open_ports_detail(self, ports: list[dict]) -> str:
        if not ports:
            return "<p class='meta'>No open ports found.</p>"
        rows = ""
        for p in ports:
            banner = self._escape(p.get("banner", "")[:200])
            service = self._escape(p["service"])
            state = p.get("state", "open")
            rows += f"<tr><td>{p['port']}</td><td>{state}</td><td>{service}</td><td>{banner}</td></tr>\n"
        return f'''<table class="open-ports-table">
<thead><tr><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr></thead>
<tbody>{rows}</tbody></table>'''

    def generate(
        self,
        target: str,
        ip_address: str,
        open_ports: list[dict],
        ssl_result: Any = None,
        header_result: Any = None,
        cve_results: Optional[list[dict]] = None,
        dir_result: Any = None,
        fingerprints: Optional[list[dict]] = None,
    ) -> str:
        sev = self.risk_score.overall_severity.lower()
        color = SEVERITY_COLORS.get(sev, "#6c757d")
        fc = self.risk_score.finding_counts

        ctx = {
            "target": self._escape(target),
            "ip_address": self._escape(ip_address),
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "risk_score": self.risk_score.overall_score,
            "risk_overall_severity": sev,
            "severity_color": color,
            "score_pct": self.risk_score.overall_score * 10,
            "open_port_count": len(open_ports),
            "count_critical": fc.get("critical", 0),
            "count_high": fc.get("high", 0),
            "count_medium": fc.get("medium", 0),
            "count_low": fc.get("low", 0),
            "c_critical": SEVERITY_COLORS["critical"],
            "c_high": SEVERITY_COLORS["high"],
            "c_medium": SEVERITY_COLORS["medium"],
            "c_low": SEVERITY_COLORS["low"],
            "c_info": SEVERITY_COLORS["info"],
            "c_none": SEVERITY_COLORS["none"],
            "open_ports_section": self._open_ports_html(open_ports),
            "findings_section": self._findings_html(),
            "open_ports_detail": self._open_ports_detail(open_ports),
            "cve_section": self._cve_section_html(cve_results or []),
            "ssl_section": self._ssl_section_html(ssl_result),
            "headers_section": self._headers_section_html(header_result),
            "dir_section": self._dir_section_html(dir_result),
            "fingerprint_section": self._fingerprint_section_html(fingerprints or []),
        }
        return HTML_TEMPLATE.format(**ctx)
