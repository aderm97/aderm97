"""
Report generation for security assessment findings
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, Any


class ReportGenerator:
    """Generate security assessment reports in various formats"""

    def __init__(self):
        self.severity_colors = {
            'critical': '#D32F2F',
            'high': '#F57C00',
            'medium': '#FFA000',
            'low': '#FBC02D',
            'info': '#0288D1'
        }

    def generate_json(self, results: Dict[str, Any], output_file: Path):
        """Generate JSON format report"""
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"JSON report saved to: {output_file}")

    def generate_html(self, results: Dict[str, Any], output_file: Path):
        """Generate HTML format report"""
        html_content = self._create_html_report(results)
        with open(output_file, 'w') as f:
            f.write(html_content)
        print(f"HTML report saved to: {output_file}")

    def generate_csv(self, results: Dict[str, Any], output_file: Path):
        """Generate CSV format report"""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)

            # Headers
            writer.writerow([
                'Module', 'Check', 'Target', 'Status',
                'Severity', 'Finding', 'Recommendation'
            ])

            # Data
            for module_name, module_data in results.get('findings', {}).items():
                if 'error' in module_data:
                    writer.writerow([
                        module_name, 'ERROR', '', 'error', 'high',
                        module_data['error'], 'Fix error and re-run'
                    ])
                    continue

                for check in module_data.get('checks', []):
                    writer.writerow([
                        module_name,
                        check.get('check', ''),
                        check.get('target', ''),
                        check.get('status', ''),
                        check.get('severity', ''),
                        check.get('finding', ''),
                        check.get('recommendation', '')
                    ])

        print(f"CSV report saved to: {output_file}")

    def generate_pdf(self, results: Dict[str, Any], output_file: Path):
        """Generate PDF format report"""
        # PDF generation requires additional libraries (reportlab)
        # For now, generate HTML and suggest conversion
        html_file = output_file.with_suffix('.html')
        self.generate_html(results, html_file)
        print(f"HTML report saved to: {html_file}")
        print(f"Note: For PDF generation, install 'weasyprint' and convert HTML to PDF")
        print(f"      pip install weasyprint")
        print(f"      weasyprint {html_file} {output_file}")

    def _create_html_report(self, results: Dict[str, Any]) -> str:
        """Create HTML report content"""

        scan_info = results.get('scan_info', {})
        findings = results.get('findings', {})
        summary = results.get('summary', {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FMDQ Security Assessment Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}

        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}

        .summary-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}

        .summary-card .label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .summary-card.critical .number {{ color: #D32F2F; }}
        .summary-card.high .number {{ color: #F57C00; }}
        .summary-card.medium .number {{ color: #FFA000; }}
        .summary-card.low .number {{ color: #FBC02D; }}
        .summary-card.passed .number {{ color: #388E3C; }}

        .module {{
            background: white;
            margin-bottom: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }}

        .module-header {{
            background: #2a5298;
            color: white;
            padding: 20px;
            font-size: 1.3em;
            font-weight: bold;
        }}

        .check {{
            padding: 20px;
            border-bottom: 1px solid #eee;
        }}

        .check:last-child {{
            border-bottom: none;
        }}

        .check-header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 10px;
        }}

        .check-title {{
            font-weight: bold;
            font-size: 1.1em;
            flex: 1;
        }}

        .badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
            margin-left: 10px;
        }}

        .badge.critical {{ background: #D32F2F; color: white; }}
        .badge.high {{ background: #F57C00; color: white; }}
        .badge.medium {{ background: #FFA000; color: white; }}
        .badge.low {{ background: #FBC02D; color: #333; }}
        .badge.info {{ background: #0288D1; color: white; }}

        .badge.passed {{ background: #388E3C; color: white; }}
        .badge.failed {{ background: #D32F2F; color: white; }}
        .badge.warning {{ background: #F57C00; color: white; }}
        .badge.manual {{ background: #757575; color: white; }}

        .check-target {{
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
        }}

        .check-finding {{
            margin-bottom: 10px;
            padding: 10px;
            background: #f9f9f9;
            border-left: 4px solid #2a5298;
            border-radius: 4px;
        }}

        .check-recommendation {{
            padding: 10px;
            background: #e8f5e9;
            border-left: 4px solid #388E3C;
            border-radius: 4px;
            white-space: pre-wrap;
        }}

        .metadata {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .metadata-item {{
            margin-bottom: 10px;
        }}

        .metadata-label {{
            font-weight: bold;
            display: inline-block;
            width: 150px;
        }}

        .footer {{
            text-align: center;
            color: #666;
            padding: 20px;
            margin-top: 40px;
        }}

        @media print {{
            body {{ background: white; }}
            .container {{ max-width: 100%; }}
            .module {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>FMDQ Network Infrastructure</h1>
            <div class="subtitle">Security Assessment Report</div>
        </div>

        <div class="metadata">
            <div class="metadata-item">
                <span class="metadata-label">Scan Date:</span>
                <span>{scan_info.get('start_time', 'N/A')}</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Duration:</span>
                <span>{scan_info.get('duration', 'N/A')}</span>
            </div>
        </div>
"""

        # Summary section
        if summary:
            html += f"""
        <div class="summary">
            <div class="summary-card">
                <div class="number">{summary.get('total_checks', 0)}</div>
                <div class="label">Total Checks</div>
            </div>
            <div class="summary-card passed">
                <div class="number">{summary.get('passed', 0)}</div>
                <div class="label">Passed</div>
            </div>
            <div class="summary-card critical">
                <div class="number">{summary.get('failed', 0)}</div>
                <div class="label">Failed</div>
            </div>
            <div class="summary-card critical">
                <div class="number">{summary.get('critical', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="number">{summary.get('high', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="number">{summary.get('medium', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="number">{summary.get('low', 0)}</div>
                <div class="label">Low</div>
            </div>
        </div>
"""

        # Findings by module
        for module_name, module_data in findings.items():
            html += f"""
        <div class="module">
            <div class="module-header">{module_data.get('module', module_name)}</div>
"""

            if 'error' in module_data:
                html += f"""
            <div class="check">
                <div class="check-finding">
                    <strong>Error:</strong> {module_data['error']}
                </div>
            </div>
"""
            else:
                for check in module_data.get('checks', []):
                    status_class = check.get('status', 'unknown')
                    severity_class = check.get('severity', 'info')

                    html += f"""
            <div class="check">
                <div class="check-header">
                    <div class="check-title">{check.get('check', 'Unknown Check')}</div>
                    <div>
                        <span class="badge {status_class}">{check.get('status', 'unknown')}</span>
                        <span class="badge {severity_class}">{check.get('severity', 'info')}</span>
                    </div>
                </div>
                <div class="check-target">
                    <strong>Target:</strong> {check.get('target', 'N/A')}
                </div>
                <div class="check-finding">
                    <strong>Finding:</strong> {check.get('finding', 'N/A')}
                </div>
                <div class="check-recommendation">
                    <strong>Recommendation:</strong> {check.get('recommendation', 'N/A')}
                </div>
            </div>
"""

            html += """
        </div>
"""

        # Footer
        html += f"""
        <div class="footer">
            <p>Generated by FMDQ Security Checker on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>This report is confidential and intended for authorized personnel only.</p>
        </div>
    </div>
</body>
</html>
"""

        return html
