from __future__ import annotations

import json
from pathlib import Path
from jinja2 import Template
from pq_surface_audit.models import ScanReport


HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PQ Surface Audit Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; color: #1f2937; }
    .card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; margin-bottom: 18px; }
    .high { color: #b91c1c; font-weight: bold; }
    .medium { color: #b45309; font-weight: bold; }
    .low { color: #15803d; font-weight: bold; }
    code { background: #f3f4f6; padding: 2px 6px; border-radius: 6px; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { text-align: left; border-bottom: 1px solid #e5e7eb; padding: 8px; vertical-align: top; }
    .muted { color: #6b7280; }
  </style>
</head>
<body>
  <h1>PQ Surface Audit Report</h1>
  <p class="muted">Generated at {{ report.generated_at }}</p>
  <p><strong>Assets scanned:</strong> {{ report.summary.assets_scanned }} | <strong>High:</strong> {{ report.summary.high_priority }} | <strong>Medium:</strong> {{ report.summary.medium_priority }} | <strong>Low:</strong> {{ report.summary.low_priority }}</p>

  {% for asset in report.assets %}
  <div class="card">
    <h2>{{ asset.target }}</h2>
    <p><strong>Hostname:</strong> {{ asset.hostname }} {% if asset.port %}| <strong>Port:</strong> {{ asset.port }}{% endif %}</p>
    <p><strong>Score:</strong> {{ asset.score }} | <strong>Priority:</strong> <span class="{{ asset.priority }}">{{ asset.priority|upper }}</span></p>

    <h3>Observations</h3>
    <table>
      <tr><th>Service</th><th>Status</th><th>Details</th></tr>
      {% for obs in asset.observations %}
      <tr>
        <td>{{ obs.service }}</td>
        <td>{{ obs.status }}</td>
        <td><code>{{ obs.details }}</code></td>
      </tr>
      {% endfor %}
    </table>

    <h3>Findings</h3>
    <table>
      <tr><th>Severity</th><th>Category</th><th>Title</th><th>Description</th><th>Recommendation</th></tr>
      {% for finding in asset.findings %}
      <tr>
        <td class="{{ finding.severity }}">{{ finding.severity }}</td>
        <td>{{ finding.category }}</td>
        <td>{{ finding.title }}</td>
        <td>{{ finding.description }}</td>
        <td>{{ finding.recommendation }}</td>
      </tr>
      {% endfor %}
    </table>

    {% if asset.notes %}
    <h3>Notes</h3>
    <ul>
      {% for note in asset.notes %}<li>{{ note }}</li>{% endfor %}
    </ul>
    {% endif %}
  </div>
  {% endfor %}
</body>
</html>
"""


def write_report(report: ScanReport, output_dir: str | Path) -> tuple[Path, Path]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    json_path = output / "report.json"
    html_path = output / "report.html"

    data = report.to_dict()
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    html = Template(HTML_TEMPLATE).render(report=data)
    html_path.write_text(html, encoding="utf-8")
    return json_path, html_path
