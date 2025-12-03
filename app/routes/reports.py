"""
Report API endpoints for the License Compliance Scanner.

This module provides REST API endpoints for generating and retrieving
compliance reports from scan results.

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session

from app.api_models import ComplianceReport
from app.dependencies import CurrentUser
from app.database import get_session
from app.report_service import ReportService
from app.scan_repository import ScanRepository


router = APIRouter(prefix="/api/reports", tags=["reports"])
logger = logging.getLogger(__name__)


@router.get(
    "/{scan_id}",
    response_model=ComplianceReport,
    summary="Generate compliance report",
    response_description="Structured compliance report with licenses and warnings",
    responses={
        200: {
            "description": "Report generated successfully",
            "content": {
                "application/json": {
                    "example": {
                        "scan_id": 42,
                        "user_id": 1,
                        "timestamp": "2024-01-15T10:30:00Z",
                        "total_licenses_found": 2,
                        "licenses": [
                            {
                                "license_type": "MIT",
                                "confidence": 0.95,
                                "matched_text": "MIT License",
                                "start_position": 0,
                                "end_position": 11
                            },
                            {
                                "license_type": "Apache-2.0",
                                "confidence": 0.88,
                                "matched_text": "Apache License, Version 2.0",
                                "start_position": 150,
                                "end_position": 177
                            }
                        ],
                        "warnings": [
                            "Multiple licenses detected - review compatibility"
                        ],
                        "summary": {
                            "unique_license_types": 2,
                            "highest_confidence": 0.95,
                            "average_confidence": 0.915
                        }
                    }
                }
            }
        },
        401: {
            "description": "Authentication required"
        },
        403: {
            "description": "Access denied - scan belongs to another user",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "AUTHORIZATION_ERROR",
                            "message": "Access denied",
                            "details": {
                                "reason": "You can only access reports for your own scans"
                            }
                        }
                    }
                }
            }
        },
        404: {
            "description": "Scan not found",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "NOT_FOUND",
                            "message": "Scan not found",
                            "details": {
                                "scan_id": 42,
                                "reason": "The requested scan does not exist"
                            }
                        }
                    }
                }
            }
        }
    }
)
async def get_report(
    scan_id: int,
    current_user: CurrentUser,
    session: Session = Depends(get_session)
) -> ComplianceReport:
    """
    Generate and retrieve a compliance report for a completed scan.
    
    Returns a structured compliance report containing:
    - All detected licenses with confidence scores
    - Summary statistics (total licenses, unique types, confidence metrics)
    - Compliance warnings for potential issues
    - Scan metadata (timestamp, user ID)
    
    **Authentication required** - Include JWT token in Authorization header.
    
    The report is formatted as JSON following a defined schema, suitable for
    legal review and documentation purposes. Users can only access reports
    for their own scans.
    
    Args:
        scan_id: The scan ID to generate a report for
        current_user: Authenticated user (from JWT token)
        session: Database session
        
    Returns:
        ComplianceReport: The compliance report with licenses and warnings
        
    Raises:
        HTTPException 401: If authentication fails
        HTTPException 403: If user tries to access another user's scan
        HTTPException 404: If scan not found
        
    Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
    """
    logger.info(
        f"Generating report for scan {scan_id} requested by user {current_user.id}",
        extra={"scan_id": scan_id, "user_id": current_user.id}
    )
    
    # Initialize services
    scan_repository = ScanRepository(session)
    report_service = ReportService(scan_repository)
    
    # Generate report (includes authorization check)
    report = report_service.generate_report(scan_id, current_user.id)
    
    if report is None:
        # Check if scan exists at all
        scan = scan_repository.get_by_id(scan_id)
        
        if scan is None:
            # Scan doesn't exist
            logger.warning(
                f"Report generation failed: Scan {scan_id} not found",
                extra={"scan_id": scan_id, "user_id": current_user.id}
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "NOT_FOUND",
                        "message": "Scan not found",
                        "details": {
                            "scan_id": scan_id,
                            "reason": "The requested scan does not exist"
                        }
                    }
                }
            )
        else:
            # Scan exists but belongs to another user
            logger.warning(
                f"Unauthorized report access attempt: User {current_user.id} tried to access report for scan {scan_id} owned by user {scan.user_id}",
                extra={"scan_id": scan_id, "requesting_user_id": current_user.id, "scan_owner_id": scan.user_id}
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "AUTHORIZATION_ERROR",
                        "message": "Access denied",
                        "details": {
                            "reason": "You can only access reports for your own scans"
                        }
                    }
                }
            )
    
    logger.info(
        f"Report generated successfully for scan {scan_id}",
        extra={
            "scan_id": scan_id,
            "user_id": current_user.id,
            "total_licenses": report.total_licenses_found,
            "warnings_count": len(report.warnings)
        }
    )
    
    return report
