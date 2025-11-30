"""
Scan repository for database operations related to scans.

This module provides the ScanRepository class for CRUD operations on Scan entities.
"""

from typing import Optional, List
from sqlmodel import Session, select, desc
from app.models import Scan


class ScanRepository:
    """Repository for scan database operations."""
    
    def __init__(self, session: Session):
        """
        Initialize the ScanRepository with a database session.
        
        Args:
            session: SQLModel database session for executing queries
        """
        self.session = session
    
    def create(self, scan: Scan) -> Scan:
        """
        Create a new scan in the database.
        
        Args:
            scan: Scan object to create
            
        Returns:
            Scan: The created scan with populated id
        """
        self.session.add(scan)
        self.session.commit()
        self.session.refresh(scan)
        return scan
    
    def get_by_id(self, scan_id: int) -> Optional[Scan]:
        """
        Retrieve a scan by its ID.
        
        Args:
            scan_id: The scan ID to search for
            
        Returns:
            Scan if found, None otherwise
        """
        return self.session.get(Scan, scan_id)
    
    def get_by_user(self, user_id: int, skip: int = 0, limit: int = 10) -> List[Scan]:
        """
        Retrieve scans for a specific user with pagination.
        
        Returns scans in chronological order (most recent first).
        
        Args:
            user_id: The user ID to filter scans by
            skip: Number of records to skip (for pagination)
            limit: Maximum number of records to return
            
        Returns:
            List of Scan objects belonging to the user
        """
        statement = (
            select(Scan)
            .where(Scan.user_id == user_id)
            .order_by(desc(Scan.created_at))
            .offset(skip)
            .limit(limit)
        )
        result = self.session.exec(statement)
        return list(result.all())
    
    def update_results(self, scan_id: int, results: dict) -> Optional[Scan]:
        """
        Update the results of a scan.
        
        Args:
            scan_id: The ID of the scan to update
            results: Dictionary containing the scan results
            
        Returns:
            Updated Scan if found, None otherwise
        """
        scan = self.session.get(Scan, scan_id)
        if scan:
            import json
            from datetime import datetime
            
            scan.results_json = json.dumps(results)
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            
            self.session.add(scan)
            self.session.commit()
            self.session.refresh(scan)
        
        return scan
