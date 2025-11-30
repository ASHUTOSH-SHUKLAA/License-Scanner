"""
API request and response models for the License Compliance Scanner.

This module defines Pydantic models used for API request validation
and response serialization.
"""

from typing import List
from datetime import datetime
from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    """Request model for user registration."""
    
    username: str = Field(..., min_length=1, description="Username for the new account")
    password: str = Field(..., min_length=1, description="Password for the new account")
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "john_doe",
                "password": "SecurePass123!"
            }
        }


class LoginRequest(BaseModel):
    """Request model for user login."""
    
    username: str = Field(..., min_length=1, description="Username")
    password: str = Field(..., min_length=1, description="Password")
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "john_doe",
                "password": "SecurePass123!"
            }
        }


class TokenResponse(BaseModel):
    """Response model for successful authentication."""
    
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type (always 'bearer')")
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                "token_type": "bearer"
            }
        }



class LicenseMatch(BaseModel):
    """Response model for a detected license match."""
    
    license_type: str = Field(..., description="The detected license type")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0 and 1")
    matched_text: str = Field(..., description="The actual text that matched")
    start_position: int = Field(..., ge=0, description="Start position of the match in the input text")
    end_position: int = Field(..., ge=0, description="End position of the match in the input text")
    
    class Config:
        json_schema_extra = {
            "example": {
                "license_type": "MIT",
                "confidence": 0.95,
                "matched_text": "MIT License",
                "start_position": 0,
                "end_position": 11
            }
        }


class ScanRequest(BaseModel):
    """Request model for submitting license text for scanning."""
    
    license_text: str = Field(..., min_length=1, description="License text to analyze")
    
    class Config:
        json_schema_extra = {
            "example": {
                "license_text": "MIT License\n\nCopyright (c) 2024 Example Corp\n\nPermission is hereby granted, free of charge, to any person obtaining a copy..."
            }
        }


class ScanResult(BaseModel):
    """Response model for scan results."""
    
    scan_id: int = Field(..., description="Unique identifier for the scan")
    status: str = Field(..., description="Scan status (pending, completed, failed)")
    licenses: List[LicenseMatch] = Field(default_factory=list, description="Detected licenses")
    created_at: datetime = Field(..., description="Timestamp when scan was created")
    completed_at: datetime | None = Field(None, description="Timestamp when scan completed")
    
    class Config:
        json_schema_extra = {
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


class ComplianceReport(BaseModel):
    """Response model for compliance reports."""
    
    scan_id: int = Field(..., description="Scan identifier")
    user_id: int = Field(..., description="User who created the scan")
    timestamp: datetime = Field(..., description="Report generation timestamp")
    total_licenses_found: int = Field(..., description="Total number of licenses detected")
    licenses: List[LicenseMatch] = Field(default_factory=list, description="All detected licenses")
    warnings: List[str] = Field(default_factory=list, description="Compliance warnings")
    summary: dict = Field(default_factory=dict, description="Summary statistics")
    
    class Config:
        json_schema_extra = {
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
