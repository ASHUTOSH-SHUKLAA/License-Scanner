"""
Report service for generating compliance reports from scan results.

This module provides the ReportService class for creating structured
compliance reports with summary statistics and warnings.
"""

import json
import logging
from datetime import datetime
from typing import Optional
from app.api_models import ComplianceReport, LicenseMatch
from app.scan_repository import ScanRepository


logger = logging.getLogger(__name__)


class ReportService:
    """Service for generating compliance reports from scan results."""
    
    def __init__(self, scan_repository: ScanRepository):
        """
        Initialize the ReportService with a scan repository.
        
        Args:
            scan_repository: Repository for accessing scan data
        """
        self.scan_repository = scan_repository
        
        # Define problematic licenses that should generate warnings
        self.problematic_licenses = {
            "GPL-3.0": "GPL-3.0 requires derivative works to be open-sourced under GPL",
            "AGPL-3.0": "AGPL-3.0 requires source code disclosure for network use",
            "GPL-2.0": "GPL-2.0 requires derivative works to be open-sourced under GPL",
            "LGPL-3.0": "LGPL-3.0 has specific requirements for dynamic linking",
            "LGPL-2.1": "LGPL-2.1 has specific requirements for dynamic linking"
        }
    
    def generate_report(self, scan_id: int, user_id: int) -> Optional[ComplianceReport]:
        """
        Generate a compliance report for a completed scan.
        
        Args:
            scan_id: The ID of the scan to generate a report for
            user_id: The ID of the user requesting the report (for authorization)
            
        Returns:
            ComplianceReport if scan exists and belongs to user, None otherwise
        """
        logger.info(
            f"Generating compliance report for scan {scan_id}",
            extra={"scan_id": scan_id, "user_id": user_id}
        )
        
        # Retrieve the scan
        scan = self.scan_repository.get_by_id(scan_id)
        
        # Check if scan exists and belongs to the user
        if not scan or scan.user_id != user_id:
            logger.warning(
                f"Report generation failed: Scan {scan_id} not found or unauthorized",
                extra={"scan_id": scan_id, "user_id": user_id}
            )
            return None
        
        # Parse the results JSON
        licenses = []
        if scan.results_json:
            try:
                results_data = json.loads(scan.results_json)
                licenses = [LicenseMatch(**match) for match in results_data.get("licenses", [])]
            except (json.JSONDecodeError, TypeError, ValueError) as e:
                # If parsing fails, return empty licenses list
                logger.error(
                    f"Failed to parse scan results JSON for scan {scan_id}: {str(e)}",
                    extra={"scan_id": scan_id, "error": str(e)}
                )
                licenses = []
        
        # Calculate summary statistics
        total_licenses_found = len(licenses)
        unique_license_types = set(license.license_type for license in licenses)
        
        # Calculate average confidence
        avg_confidence = 0.0
        if licenses:
            avg_confidence = sum(license.confidence for license in licenses) / len(licenses)
        
        summary = {
            "total_licenses": total_licenses_found,
            "unique_license_types": len(unique_license_types),
            "license_types": sorted(list(unique_license_types)),
            "average_confidence": round(avg_confidence, 2)
        }
        
        # Generate warnings for problematic licenses
        warnings = []
        for license in licenses:
            if license.license_type in self.problematic_licenses:
                warning = f"{license.license_type}: {self.problematic_licenses[license.license_type]}"
                if warning not in warnings:  # Avoid duplicate warnings
                    warnings.append(warning)
        
        logger.info(
            f"Report generated for scan {scan_id}: {total_licenses_found} licenses, {len(warnings)} warnings",
            extra={
                "scan_id": scan_id,
                "total_licenses": total_licenses_found,
                "unique_types": len(unique_license_types),
                "warnings_count": len(warnings)
            }
        )
        
        # Create and return the compliance report
        report = ComplianceReport(
            scan_id=scan.id,
            user_id=scan.user_id,
            timestamp=scan.completed_at or scan.created_at,
            total_licenses_found=total_licenses_found,
            licenses=licenses,
            warnings=warnings,
            summary=summary
        )
        
        return report