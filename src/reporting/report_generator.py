"""Report generation module for CVEScannerX."""

import os
import json
import datetime
from typing import Dict, Optional
from jinja2 import Environment, FileSystemLoader
import subprocess
from ..utils.logger import get_logger

logger = get_logger(__name__)

class ReportGenerator:
    """Generator for various report formats."""
    
    def __init__(self, config: Dict):
        """Initialize report generator with configuration."""
        self.config = config['features']['reporting']
        self.env = Environment(
            loader=FileSystemLoader(os.path.dirname(self.config['html_template']))
        )
        self.template = self.env.get_template(
            os.path.basename(self.config['html_template'])
        )
        
        # Create output directory if it doesn't exist
        os.makedirs(self.config['output_directory'], exist_ok=True)

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
        """Generate JSON report."""
        output_path = f"{self._get_output_path(target, 'json')}.json"
        
        try:
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"JSON report saved to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            raise

    def generate_html(self, data: Dict, target: str) -> str:
        """Generate HTML report."""
        output_path = f"{self._get_output_path(target, 'html')}.html"
        
        try:
            html_content = self.template.render(
                target=target,
                scan_date=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                scan_type='Local' if target == 'local' else 'Remote',
                **data
            )
            
            with open(output_path, 'w') as f:
                f.write(html_content)
            logger.info(f"HTML report saved to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            raise

    def generate_pdf(self, data: Dict, target: str) -> str:
        """Generate PDF report from HTML."""
        html_path = self.generate_html(data, target)
        output_path = f"{self._get_output_path(target, 'pdf')}.pdf"
        
        try:
            subprocess.run([
                'wkhtmltopdf',
                '--quiet',
                html_path,
                output_path
            ], check=True)
            logger.info(f"PDF report saved to {output_path}")
            return output_path
        except subprocess.CalledProcessError as e:
            logger.error(f"Error generating PDF report: {e}")
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
