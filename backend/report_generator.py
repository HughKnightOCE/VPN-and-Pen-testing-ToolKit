"""
Report Generator Module
Generate PDF and HTML reports from test results
"""

import os
from datetime import datetime
from typing import List, Dict
import logging
import json

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate security reports in PDF and HTML formats"""
    
    def __init__(self, output_dir: str = './reports'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_report(self, report_id: int, title: str, test_results: List[Dict],
                       report_type: str = 'summary', company_name: str = 'Security Team',
                       include_html: bool = True, include_pdf: bool = False) -> Dict:
        """Generate security report"""
        
        try:
            # Analyze results
            analysis = self._analyze_results(test_results)
            
            # Generate HTML
            html_path = None
            if include_html:
                html_path = self._generate_html(
                    report_id, title, test_results, analysis, 
                    report_type, company_name
                )
            
            # Generate PDF (if reportlab available)
            pdf_path = None
            if include_pdf:
                try:
                    pdf_path = self._generate_pdf(
                        report_id, title, test_results, analysis, 
                        report_type, company_name
                    )
                except ImportError:
                    logger.warning("reportlab not installed, skipping PDF generation")
            
            logger.info(f"Report {report_id} generated successfully")
            
            return {
                'success': True,
                'report_id': report_id,
                'html_path': html_path,
                'pdf_path': pdf_path,
                'analysis': analysis
            }
        
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _analyze_results(self, results: List[Dict]) -> Dict:
        """Analyze test results"""
        analysis = {
            'total_tests': len(results),
            'total_vulnerabilities': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'by_type': {}
        }
        
        for result in results:
            test_type = result.get('test_type', 'unknown')
            vulnerabilities = result.get('vulnerabilities_found', 0)
            severity = result.get('severity', 'LOW')
            status = result.get('status', 'unknown')
            
            # Count vulnerabilities
            analysis['total_vulnerabilities'] += vulnerabilities
            
            # Count by severity
            if severity == 'CRITICAL':
                analysis['critical'] += vulnerabilities
            elif severity == 'HIGH':
                analysis['high'] += vulnerabilities
            elif severity == 'MEDIUM':
                analysis['medium'] += vulnerabilities
            else:
                analysis['low'] += vulnerabilities
            
            # Count passes/failures
            if status == 'completed':
                if vulnerabilities == 0:
                    analysis['passed_tests'] += 1
                else:
                    analysis['failed_tests'] += 1
            
            # Aggregate by type
            if test_type not in analysis['by_type']:
                analysis['by_type'][test_type] = {
                    'count': 0,
                    'vulnerabilities': 0
                }
            
            analysis['by_type'][test_type]['count'] += 1
            analysis['by_type'][test_type]['vulnerabilities'] += vulnerabilities
        
        return analysis
    
    def _generate_html(self, report_id: int, title: str, results: List[Dict],
                      analysis: Dict, report_type: str, company_name: str) -> str:
        """Generate HTML report"""
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            color: #333;
            line-height: 1.6;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        .header {{
            border-bottom: 3px solid #0066ff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #0066ff;
            font-size: 28px;
            margin-bottom: 5px;
        }}
        .header p {{
            color: #666;
            font-size: 14px;
        }}
        .meta {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }}
        .meta-item {{
            background: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #0066ff;
        }}
        .meta-item .label {{
            font-size: 12px;
            color: #999;
            text-transform: uppercase;
        }}
        .meta-item .value {{
            font-size: 24px;
            font-weight: bold;
            color: #333;
            margin-top: 5px;
        }}
        .summary {{
            background: #f0f7ff;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
            border-left: 4px solid #0066ff;
        }}
        .summary h2 {{
            color: #0066ff;
            margin-bottom: 15px;
            font-size: 18px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
        }}
        .summary-stat {{
            text-align: center;
        }}
        .summary-stat .label {{
            font-size: 12px;
            color: #666;
        }}
        .summary-stat .count {{
            font-size: 24px;
            font-weight: bold;
            margin-top: 5px;
        }}
        .critical {{ color: #ff0000; }}
        .high {{ color: #ff6600; }}
        .medium {{ color: #ffaa00; }}
        .low {{ color: #00cc00; }}
        .results {{
            margin-bottom: 30px;
        }}
        .results h2 {{
            color: #0066ff;
            margin-bottom: 15px;
            font-size: 18px;
        }}
        .result-item {{
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            border-left: 4px solid #ddd;
        }}
        .result-item.critical {{
            border-left-color: #ff0000;
            background: #fff5f5;
        }}
        .result-item.high {{
            border-left-color: #ff6600;
            background: #fff8f0;
        }}
        .result-item.medium {{
            border-left-color: #ffaa00;
            background: #fffaf0;
        }}
        .result-item.low {{
            border-left-color: #00cc00;
            background: #f0fff0;
        }}
        .result-title {{
            font-weight: bold;
            margin-bottom: 5px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .result-type {{
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
        }}
        .result-target {{
            color: #666;
            font-size: 14px;
            margin: 5px 0;
        }}
        .result-details {{
            font-size: 13px;
            color: #666;
            margin-top: 10px;
            padding: 10px;
            background: rgba(0,0,0,0.02);
            border-radius: 3px;
        }}
        .footer {{
            border-top: 1px solid #ddd;
            padding-top: 20px;
            margin-top: 30px;
            color: #999;
            font-size: 12px;
            text-align: center;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
            color: white;
        }}
        .badge.critical {{ background: #ff0000; }}
        .badge.high {{ background: #ff6600; }}
        .badge.medium {{ background: #ffaa00; color: #000; }}
        .badge.low {{ background: #00cc00; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Assessment Report</h1>
            <p>{title}</p>
        </div>
        
        <div class="meta">
            <div class="meta-item">
                <div class="label">Report ID</div>
                <div class="value">{report_id}</div>
            </div>
            <div class="meta-item">
                <div class="label">Organization</div>
                <div class="value">{company_name}</div>
            </div>
            <div class="meta-item">
                <div class="label">Report Date</div>
                <div class="value">{datetime.now().strftime('%Y-%m-%d')}</div>
            </div>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-stat">
                    <div class="label">Total Vulnerabilities</div>
                    <div class="count">{analysis['total_vulnerabilities']}</div>
                </div>
                <div class="summary-stat">
                    <div class="label critical">Critical</div>
                    <div class="count critical">{analysis['critical']}</div>
                </div>
                <div class="summary-stat">
                    <div class="label high">High</div>
                    <div class="count high">{analysis['high']}</div>
                </div>
                <div class="summary-stat">
                    <div class="label medium">Medium</div>
                    <div class="count medium">{analysis['medium']}</div>
                </div>
                <div class="summary-stat">
                    <div class="label low">Low</div>
                    <div class="count low">{analysis['low']}</div>
                </div>
            </div>
        </div>
        
        <div class="results">
            <h2>Detailed Test Results</h2>
"""
        
        # Add results
        for result in results:
            severity = result.get('severity', 'LOW').lower()
            test_type = result.get('test_type', 'Unknown')
            target = result.get('target', 'N/A')
            vulns = result.get('vulnerabilities_found', 0)
            
            html_content += f"""
            <div class="result-item {severity}">
                <div class="result-title">
                    <span>{test_type.upper()}</span>
                    <span class="badge {severity}">{result.get('severity', 'LOW')}</span>
                </div>
                <div class="result-type">Test Type: {test_type}</div>
                <div class="result-target">Target: {target}</div>
                <div class="result-details">
                    <strong>Vulnerabilities Found:</strong> {vulns}<br>
                    <strong>Status:</strong> {result.get('status', 'Unknown')}<br>
"""
            
            if result.get('result'):
                html_content += f"<strong>Details:</strong> {json.dumps(result.get('result'), indent=2)}<br>"
            
            if result.get('notes'):
                html_content += f"<strong>Notes:</strong> {result.get('notes')}<br>"
            
            html_content += """
                </div>
            </div>
"""
        
        html_content += """
        </div>
        
        <div class="footer">
            <p>This report was automatically generated by the VPN Proxy + Pentesting Toolkit</p>
            <p>For authorized security testing only. Unauthorized access is illegal.</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Save HTML file
        filename = f"report_{report_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {filepath}")
        return filepath
    
    def _generate_pdf(self, report_id: int, title: str, results: List[Dict],
                     analysis: Dict, report_type: str, company_name: str) -> str:
        """Generate PDF report (requires reportlab)"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.lib import colors
            
            # Create PDF
            filename = f"report_{report_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            filepath = os.path.join(self.output_dir, filename)
            
            doc = SimpleDocTemplate(filepath, pagesize=letter)
            story = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = styles['Heading1']
            story.append(Paragraph(f"Security Assessment Report: {title}", title_style))
            story.append(Spacer(1, 0.3*inch))
            
            # Metadata
            meta_data = [
                ['Report ID', str(report_id)],
                ['Organization', company_name],
                ['Date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Report Type', report_type]
            ]
            meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
            meta_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            story.append(meta_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Summary
            summary_title = Paragraph("Executive Summary", styles['Heading2'])
            story.append(summary_title)
            
            summary_data = [
                ['Metric', 'Count'],
                ['Total Vulnerabilities', str(analysis['total_vulnerabilities'])],
                ['Critical', str(analysis['critical'])],
                ['High', str(analysis['high'])],
                ['Medium', str(analysis['medium'])],
                ['Low', str(analysis['low'])]
            ]
            summary_table = Table(summary_data, colWidths=[3*inch, 3*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Build PDF
            doc.build(story)
            logger.info(f"PDF report generated: {filepath}")
            return filepath
        
        except ImportError:
            raise ImportError("reportlab is required for PDF generation")


# Global instance
report_generator = ReportGenerator()
