"""
Scan API endpoints for the License Compliance Scanner.

This module provides REST API endpoints for submitting license scans,
retrieving scan results, and viewing scan history.

Requirements: 2.1, 2.4, 4.1, 4.2, 4.3, 6.1, 6.2, 6.3, 6.5
"""

import json
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File, Form
from sqlmodel import Session

from config import get_settings
from app.api_models import ScanRequest, ScanResult, LicenseMatch
from app.dependencies import CurrentUser
from app.database import get_session
from app.scan_service import ScanService
from app.scan_repository import ScanRepository
from app.license_engine import LicenseEngine


router = APIRouter(prefix="/api/scans", tags=["scans"])
logger = logging.getLogger(__name__)


def get_license_engine() -> LicenseEngine:
    """
    Dependency to get the LicenseEngine instance.
    
    Returns:
        LicenseEngine: Configured license engine with loaded rules
    """
    settings = get_settings()
    return LicenseEngine(rules_path=settings.rules_file_path)


@router.post(
    "",
    response_model=ScanResult,
    status_code=status.HTTP_201_CREATED,
    summary="Submit license text or file for scanning",
    response_description="Scan results with detected licenses",
    responses={
        201: {
            "description": "Scan created and executed successfully",
            "content": {
                "application/json": {
                    "example": {
                        "scan_id": 42,
                        "status": "completed",
                        "licenses": [
                            {
                                "license_type": "MIT",
                                "confidence": 0.95,
                                "matched_text": "MIT License",
                                "start_position": 0,
                                "end_position": 11
                            }
                        ],
                        "created_at": "2024-01-15T10:30:00Z",
                        "completed_at": "2024-01-15T10:30:01Z"
                    }
                }
            }
        },
        400: {
            "description": "Validation error - invalid input",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": "Invalid input data",
                            "details": {
                                "reason": "License text exceeds maximum size of 1MB"
                            }
                        }
                    }
                }
            }
        },
        401: {
            "description": "Authentication required",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "AUTHENTICATION_ERROR",
                            "message": "Invalid or missing authentication token"
                        }
                    }
                }
            }
        }
    }
)
async def create_scan(
    current_user: CurrentUser,
    session: Session = Depends(get_session),
    license_engine: LicenseEngine = Depends(get_license_engine),
    license_text: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None)
) -> ScanResult:
    """
    Submit license text or file for scanning.
    
    Creates a new scan, executes license detection using rule-based pattern matching,
    and returns results immediately. The scan is associated with the authenticated user
    and can be retrieved later.
    
    **Authentication required** - Include JWT token in Authorization header.
    
    **Two input methods:**
    1. **JSON text** (Content-Type: application/json):
       ```json
       {"license_text": "MIT License\\n\\nPermission is hereby granted..."}
       ```
    
    2. **File upload** (Content-Type: multipart/form-data):
       - Supported formats: .txt, .md, .license, LICENSE (no extension)
       - Maximum file size: 100KB
       - File parameter name: `file`
    
    The license detection engine applies all configured rules and returns:
    - Detected license types
    - Confidence scores (0.0 to 1.0)
    - Matched text snippets
    - Position information (start/end)
    
    Args:
        current_user: Authenticated user (from JWT token)
        session: Database session
        license_engine: License detection engine
        license_text: License text (for JSON input)
        file: License file (for file upload)
        
    Returns:
        ScanResult: The scan results with detected licenses
        
    Raises:
        HTTPException 400: If input validation fails
        HTTPException 401: If authentication fails
        
    Requirements: 2.1, 2.4, 4.1
    """
    scan_service = ScanService(session, license_engine)
    
    # Determine input source and extract text
    text_to_scan = None
    
    try:
        # Check if file was uploaded
        if file is not None:
            logger.info(
                f"Processing file upload: {file.filename}",
                extra={"user_id": current_user.id, "uploaded_filename": file.filename}
            )
            
            # Validate file type
            allowed_extensions = {'.txt', '.md', '.license', ''}
            file_ext = ''
            if file.filename:
                parts = file.filename.rsplit('.', 1)
                if len(parts) > 1:
                    file_ext = '.' + parts[1].lower()
                # Allow files named exactly "LICENSE" with no extension
                if file.filename.upper() != 'LICENSE' and file_ext not in allowed_extensions:
                    raise ValueError(
                        f"Unsupported file type. Allowed: .txt, .md, .license, or LICENSE (no extension). "
                        f"Got: {file.filename}"
                    )
            
            # Read file content
            content_bytes = await file.read()
            
            # Validate file size (100KB limit)
            if len(content_bytes) > 100 * 1024:
                raise ValueError(
                    f"File size exceeds maximum of 100KB (got {len(content_bytes)} bytes)"
                )
            
            # Decode file content (try UTF-8 first, fallback to latin-1)
            try:
                text_to_scan = content_bytes.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    text_to_scan = content_bytes.decode('latin-1')
                    logger.warning(
                        f"File decoded using latin-1 fallback: {file.filename}",
                        extra={"user_id": current_user.id, "uploaded_filename": file.filename}
                    )
                except Exception:
                    raise ValueError("Unable to decode file. Please ensure it's a text file with UTF-8 or Latin-1 encoding.")
            
            logger.info(
                f"File uploaded successfully: {file.filename} ({len(content_bytes)} bytes)",
                extra={"user_id": current_user.id, "uploaded_filename": file.filename, "size_bytes": len(content_bytes)}
            )
        
        # Check if text was provided via form/JSON (not None and not empty string)
        elif license_text is not None and license_text.strip():
            text_to_scan = license_text
            logger.info(
                f"Processing text input",
                extra={"user_id": current_user.id, "text_size": len(license_text)}
            )
        
        # Neither file nor text provided
        else:
            raise ValueError(
                "No input provided. Please provide either 'license_text' (text) or 'file' (file upload)."
            )
        
        # Create scan (validates input)
        scan = scan_service.create_scan(current_user.id, text_to_scan)
        
        # Execute scan immediately
        scan = scan_service.execute_scan(scan.id)
        
        # Parse results and convert to response model
        licenses = []
        if scan.results_json:
            results_data = json.loads(scan.results_json)
            licenses = [
                LicenseMatch(**license_data)
                for license_data in results_data.get("licenses", [])
            ]
        
        return ScanResult(
            scan_id=scan.id,
            status=scan.status,
            licenses=licenses,
            created_at=scan.created_at,
            completed_at=scan.completed_at
        )
        
    except ValueError as e:
        # Input validation errors
        logger.warning(
            f"Scan creation failed: {str(e)}",
            extra={"user_id": current_user.id, "error": str(e)}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Invalid input data",
                    "details": {
                        "reason": str(e)
                    }
                }
            }
        )
    except Exception as e:
        # Internal errors
        logger.error(
            f"Scan processing failed: {str(e)}",
            extra={"user_id": current_user.id, "error": str(e)},
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An internal error occurred",
                    "details": {
                        "reason": "Failed to process scan"
                    }
                }
            }
        )


@router.get(
    "/{scan_id}",
    response_model=ScanResult,
    summary="Retrieve a specific scan",
    response_description="Complete scan results",
    responses={
        200: {
            "description": "Scan retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "scan_id": 42,
                        "status": "completed",
                        "licenses": [
                            {
                                "license_type": "MIT",
                                "confidence": 0.95,
                                "matched_text": "MIT License",
                                "start_position": 0,
                                "end_position": 11
                            }
                        ],
                        "created_at": "2024-01-15T10:30:00Z",
                        "completed_at": "2024-01-15T10:30:01Z"
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
                                "reason": "You can only access your own scans"
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
async def get_scan(
    scan_id: int,
    current_user: CurrentUser,
    session: Session = Depends(get_session)
) -> ScanResult:
    """
    Retrieve a specific scan by ID.
    
    Returns complete scan results including all detected licenses with their
    confidence scores and position information. Users can only access their
    own scans for security and privacy.
    
    **Authentication required** - Include JWT token in Authorization header.
    
    Args:
        scan_id: The scan ID to retrieve
        current_user: Authenticated user (from JWT token)
        session: Database session
        
    Returns:
        ScanResult: The scan results with detected licenses
        
    Raises:
        HTTPException 401: If authentication fails
        HTTPException 403: If user tries to access another user's scan
        HTTPException 404: If scan not found
        
    Requirements: 4.1, 4.2, 4.3, 6.1
    """
    logger.info(
        f"Retrieving scan {scan_id} for user {current_user.id}",
        extra={"scan_id": scan_id, "user_id": current_user.id}
    )
    
    scan_repository = ScanRepository(session)
    
    # Retrieve scan
    scan = scan_repository.get_by_id(scan_id)
    
    if not scan:
        logger.warning(
            f"Scan not found: ID {scan_id}",
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
    
    # Authorization check: users can only access their own scans
    if scan.user_id != current_user.id:
        logger.warning(
            f"Unauthorized scan access attempt: User {current_user.id} tried to access scan {scan_id} owned by user {scan.user_id}",
            extra={"scan_id": scan_id, "requesting_user_id": current_user.id, "scan_owner_id": scan.user_id}
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": {
                    "code": "AUTHORIZATION_ERROR",
                    "message": "Access denied",
                    "details": {
                        "reason": "You can only access your own scans"
                    }
                }
            }
        )
    
    # Parse results and convert to response model
    licenses = []
    if scan.results_json:
        results_data = json.loads(scan.results_json)
        licenses = [
            LicenseMatch(**license_data)
            for license_data in results_data.get("licenses", [])
        ]
    
    logger.info(
        f"Scan retrieved successfully: ID {scan_id}",
        extra={"scan_id": scan_id, "user_id": current_user.id, "licenses_count": len(licenses)}
    )
    
    return ScanResult(
        scan_id=scan.id,
        status=scan.status,
        licenses=licenses,
        created_at=scan.created_at,
        completed_at=scan.completed_at
    )


@router.get(
    "",
    response_model=List[dict],
    summary="Get scan history",
    response_description="Paginated list of user's scans",
    responses={
        200: {
            "description": "Scan history retrieved successfully",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "scan_id": 42,
                            "status": "completed",
                            "created_at": "2024-01-15T10:30:00Z",
                            "completed_at": "2024-01-15T10:30:01Z"
                        },
                        {
                            "scan_id": 41,
                            "status": "completed",
                            "created_at": "2024-01-14T15:20:00Z",
                            "completed_at": "2024-01-14T15:20:02Z"
                        }
                    ]
                }
            }
        },
        401: {
            "description": "Authentication required"
        }
    }
)
async def get_scan_history(
    current_user: CurrentUser,
    session: Session = Depends(get_session),
    skip: int = Query(0, ge=0, description="Number of records to skip for pagination"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return (1-100)")
) -> List[dict]:
    """
    Retrieve scan history for the authenticated user.
    
    Returns a paginated list of scans with metadata only (no full results).
    Scans are ordered chronologically with most recent first. Use this endpoint
    to browse your scan history before retrieving full results.
    
    **Authentication required** - Include JWT token in Authorization header.
    
    **Pagination**: Use `skip` and `limit` parameters to paginate through results.
    - Default: skip=0, limit=10
    - Maximum limit: 100
    
    **Note**: This endpoint returns metadata only. To get full scan results with
    detected licenses, use `GET /api/scans/{scan_id}`.
    
    Args:
        current_user: Authenticated user (from JWT token)
        session: Database session
        skip: Number of records to skip (for pagination)
        limit: Maximum number of records to return (1-100)
        
    Returns:
        List of scan metadata dictionaries
        
    Raises:
        HTTPException 401: If authentication fails
        
    Requirements: 6.1, 6.2, 6.3, 6.5
    """
    logger.info(
        f"Retrieving scan history for user {current_user.id}",
        extra={"user_id": current_user.id, "skip": skip, "limit": limit}
    )
    
    scan_repository = ScanRepository(session)
    
    # Get user's scans with pagination
    scans = scan_repository.get_by_user(current_user.id, skip=skip, limit=limit)
    
    logger.info(
        f"Scan history retrieved for user {current_user.id}: {len(scans)} scans",
        extra={"user_id": current_user.id, "scans_count": len(scans)}
    )
    
    # Return metadata only (no full results_json)
    return [
        {
            "scan_id": scan.id,
            "status": scan.status,
            "created_at": scan.created_at.isoformat(),
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
        }
        for scan in scans
    ]
