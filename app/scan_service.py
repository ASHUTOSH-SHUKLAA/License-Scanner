"""
Scan service for managing license scan operations.

This module provides the ScanService class that orchestrates scan creation,
execution, and result storage.
"""

import json
import logging
from datetime import datetime
from typing import Optional
from sqlmodel import Session

from app.models import Scan
from app.scan_repository import ScanRepository
from app.license_engine import LicenseEngine


logger = logging.getLogger(__name__)


class ScanService:
    """
    Service for managing license scan operations.
    
    Handles scan creation, input validation, license detection,
    and result persistence.
    """
    
    # Maximum size for license text input (100KB as per requirements)
    MAX_INPUT_SIZE = 100 * 1024  # 100KB in bytes
    
    def __init__(self, session: Session, license_engine: LicenseEngine):
        """
        Initialize the ScanService.
        
        Args:
            session: SQLModel database session
            license_engine: LicenseEngine instance for license detection
        """
        self.session = session
        self.license_engine = license_engine
        self.scan_repository = ScanRepository(session)
    
    def create_scan(self, user_id: int, license_text: str) -> Scan:
        """
        Create a new scan with input validation.
        
        Validates the input and creates a scan record in pending status.
        
        Args:
            user_id: ID of the user creating the scan
            license_text: License text to analyze
            
        Returns:
            Scan: The created scan object
            
        Raises:
            ValueError: If input validation fails
        """
        logger.info(
            f"Creating scan for user {user_id}",
            extra={
                "user_id": user_id,
                "text_size_bytes": len(license_text.encode('utf-8'))
            }
        )
        
        # Validate input
        try:
            self._validate_input(license_text)
        except ValueError as e:
            logger.warning(
                f"Scan creation failed for user {user_id}: Input validation error",
                extra={"user_id": user_id, "error": str(e)}
            )
            raise
        
        # Create scan in pending status
        scan = Scan(
            user_id=user_id,
            license_text=license_text,
            status="pending",
            results_json=None,
            created_at=datetime.utcnow(),
            completed_at=None
        )
        
        # Persist to database
        created_scan = self.scan_repository.create(scan)
        logger.info(
            f"Scan created successfully: ID {created_scan.id} for user {user_id}",
            extra={"scan_id": created_scan.id, "user_id": user_id}
        )
        
        return created_scan
    
    def execute_scan(self, scan_id: int) -> Scan:
        """
        Execute license detection on a scan and update results.
        
        Retrieves the scan, runs license detection, and stores results.
        Updates scan status to completed or failed.
        
        Args:
            scan_id: ID of the scan to execute
            
        Returns:
            Scan: The updated scan with results
            
        Raises:
            ValueError: If scan not found
            Exception: If scan execution fails
        """
        logger.info(f"Executing scan: ID {scan_id}", extra={"scan_id": scan_id})
        
        # Retrieve the scan
        scan = self.scan_repository.get_by_id(scan_id)
        if not scan:
            logger.error(f"Scan not found: ID {scan_id}", extra={"scan_id": scan_id})
            raise ValueError(f"Scan with id {scan_id} not found")
        
        try:
            # Execute license detection
            matches = self.license_engine.detect_licenses(scan.license_text)
            
            logger.info(
                f"License detection completed for scan {scan_id}: {len(matches)} licenses found",
                extra={
                    "scan_id": scan_id,
                    "licenses_found": len(matches),
                    "license_types": [m.license_type for m in matches]
                }
            )
            
            # Convert matches to dict format for JSON storage
            results = {
                "licenses": [
                    {
                        "license_type": match.license_type,
                        "confidence": match.confidence,
                        "matched_text": match.matched_text,
                        "start_position": match.start_position,
                        "end_position": match.end_position
                    }
                    for match in matches
                ]
            }
            
            # Update scan with results
            updated_scan = self.scan_repository.update_results(scan_id, results)
            logger.info(
                f"Scan completed successfully: ID {scan_id}",
                extra={"scan_id": scan_id, "status": updated_scan.status}
            )
            
            return updated_scan
            
        except Exception as e:
            logger.error(
                f"Scan execution failed for scan {scan_id}: {str(e)}",
                extra={"scan_id": scan_id, "error": str(e)},
                exc_info=True
            )
            
            # Mark scan as failed
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            self.session.add(scan)
            self.session.commit()
            self.session.refresh(scan)
            
            raise Exception(f"Scan execution failed: {str(e)}") from e
    
    def _validate_input(self, license_text: str) -> None:
        """
        Validate license text input.
        
        Checks for:
        - Non-empty text
        - Size limits
        - Format validity (basic string validation)
        
        Args:
            license_text: The license text to validate
            
        Raises:
            ValueError: If validation fails with specific error message
        """
        # Check if text is empty or only whitespace
        if not license_text or not license_text.strip():
            raise ValueError("License text cannot be empty")
        
        # Check size limits
        text_size = len(license_text.encode('utf-8'))
        if text_size > self.MAX_INPUT_SIZE:
            raise ValueError(
                f"License text exceeds maximum size of {self.MAX_INPUT_SIZE} bytes "
                f"(provided: {text_size} bytes)"
            )
        
        # Basic format validation - ensure it's a valid string
        if not isinstance(license_text, str):
            raise ValueError("License text must be a string")
