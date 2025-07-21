"""Report generation module for CVEScannerX."""

import os
import json
import datetime
import shutil
from pathlib import Path
from typing import Dict, Optional, List, Union
from jinja2 import Environment, FileSystemLoader, select_autoescape
import subprocess
from ..utils.logger import get_logger
from ..utils.progress import ScanProgress

logger = get_logger(__name__)

# Define severity levels and their colors
SEVERITY_LEVELS = {
    'CRITICAL': '#dc3545',
    'HIGH': '#dc3545',
    'MEDIUM': '#ffc107',
    'LOW': '#28a745',
    'NONE': '#6c757d',
    'UNKNOWN': '#6c757d'
}

def calculate_severity(cvss_score: Optional[float]) -> str:
    """Calculate severity level from CVSS score."""
    if cvss_score is None:
        return 'UNKNOWN'
    elif cvss_score >= 9.0:
        return 'CRITICAL'
    elif cvss_score >= 7.0:
        return 'HIGH'
    elif cvss_score >= 4.0:
        return 'MEDIUM'
    elif cvss_score > 0:
        return 'LOW'
    else:
        return 'NONE'

class ReportGenerator:
    """Generator for various report formats."""
    
    def __init__(self, config: Dict):
        """Initialize report generator with configuration."""
        self.config = config['features']['reporting']
        
        # Set up Jinja2 environment with autoescape
        template_dir = os.path.dirname(self.config['html_template'])
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Add custom filters
        self.env.filters['severity_color'] = lambda s: SEVERITY_LEVELS.get(s, '#6c757d')
        self.env.filters['format_date'] = lambda d: datetime.datetime.fromisoformat(d).strftime('%Y-%m-%d %H:%M:%S')
        self.env.filters['calculate_severity'] = calculate_severity
        
        # Load template
        self.template = self.env.get_template(
            os.path.basename(self.config['html_template'])
        )
        
        # Create output directory if it doesn't exist
        os.makedirs(self.config['output_directory'], exist_ok=True)
        
        # Create assets directory for CSS and JS
        self.assets_dir = os.path.join(self.config['output_directory'], 'assets')
        os.makedirs(self.assets_dir, exist_ok=True)
        
        # Copy static assets if they exist
        static_dir = os.path.join(template_dir, 'static')
        if os.path.exists(static_dir):
            for item in os.listdir(static_dir):
                src = os.path.join(static_dir, item)
                dst = os.path.join(self.assets_dir, item)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)

    def _get_output_path(self, target: str, report_type: str) -> str:
        """Generate output file path based on naming pattern."""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = self.config['naming_pattern'].format(
            target=target,
            timestamp=timestamp,
            type=report_type
        )
        return os.path.join(self.config['output_directory'], filename)

    def generate_json(self, data: Dict, target: str) -> str:
        """Generate JSON report with metadata."""
        output_path = f"{self._get_output_path(target, 'json')}.json"
        
        try:
            with ScanProgress("Generating JSON report") as progress:
                # Add metadata
                report_data = {
                    'metadata': {
                        'generator': 'CVEScannerX',
                        'generated_at': datetime.datetime.now().isoformat(),
                        'target': target,
                        'scan_type': 'Local' if target == 'local' else 'Remote',
                        'version': '1.0.0'  # TODO: Get from config
                    },
                    'data': data
                }
                
                # Write JSON with proper formatting
                with open(output_path, 'w') as f:
                    json.dump(report_data, f, indent=2, sort_keys=True)
                
                logger.info(f"JSON report saved to {output_path}")
                return output_path
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            raise

    def generate_html(self, data: Dict, target: str) -> str:
        """Generate HTML report with enhanced styling and formatting."""
        output_path = f"{self._get_output_path(target, 'html')}.html"
        
        try:
            with ScanProgress("Generating HTML report") as progress:
                # Process vulnerability data
                vulnerabilities = data.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    vuln['severity'] = calculate_severity(vuln.get('cvss_score'))
                
                # Prepare template data
                template_data = {
                    'target': target,
                    'scan_date': datetime.datetime.now().isoformat(),
                    'scan_type': 'Local' if target == 'local' else 'Remote',
                    'vulnerabilities': vulnerabilities,
                    'stats': {
                        'total': len(vulnerabilities),
                        'by_severity': {
                            severity: len([v for v in vulnerabilities if calculate_severity(v.get('cvss_score')) == severity])
                            for severity in SEVERITY_LEVELS.keys()
                        }
                    },
                    'raw_data': data  # Include raw data for detailed view
                }
                
                # Render template
                html_content = self.template.render(**template_data)
                
                # Write HTML file
                with open(output_path, 'w') as f:
                    f.write(html_content)
                
                logger.info(f"HTML report saved to {output_path}")
                return output_path
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            raise

    def generate_pdf(self, data: Dict, target: str) -> str:
        """Generate PDF report with enhanced styling and proper error handling."""
        try:
            with ScanProgress("Generating PDF report") as progress:
                # Generate HTML first
                progress.update(description="Generating HTML content...")
                html_path = self.generate_html(data, target)
                output_path = f"{self._get_output_path(target, 'pdf')}.pdf"
                
                progress.update(description="Converting to PDF...")
                # Use wkhtmltopdf with optimized settings
                result = subprocess.run([
                    'wkhtmltopdf',
                    '--quiet',
                    '--enable-local-file-access',
                    '--encoding', 'UTF-8',
                    '--footer-right', '[page]/[topage]',
                    '--footer-font-size', '8',
                    '--margin-top', '20',
                    '--margin-bottom', '20',
                    '--margin-left', '20',
                    '--margin-right', '20',
                    html_path,
                    output_path
                ], capture_output=True, text=True, check=True)
                
                logger.info(f"PDF report saved to {output_path}")
                return output_path
                
        except subprocess.CalledProcessError as e:
            error_msg = f"Error generating PDF report: {e.stderr}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        except Exception as e:
            logger.error(f"Unexpected error generating PDF report: {e}")
            raise

    def generate(self, data: Dict, target: str, format: str) -> str:
        """Generate report in specified format."""
        if format not in self.config['formats']:
            raise ValueError(f"Unsupported format: {format}")
            
        if format == 'json':
            return self.generate_json(data, target)
        elif format == 'html':
            return self.generate_html(data, target)
        elif format == 'pdf':
            return self.generate_pdf(data, target)
