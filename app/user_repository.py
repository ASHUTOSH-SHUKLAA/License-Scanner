"""
User repository for database operations related to users.

This module provides the UserRepository class for CRUD operations on User entities.
"""

from typing import Optional
from sqlmodel import Session, select
from sqlalchemy.exc import IntegrityError
from app.models import User


class DuplicateUsernameError(Exception):
    """Exception raised when attempting to create a user with a duplicate username."""
    
    def __init__(self, username: str):
        self.username = username
        super().__init__(f"Username '{username}' already exists")


class UserRepository:
    """Repository for user database operations."""
    
    def __init__(self, session: Session):
        """
        Initialize the UserRepository with a database session.
        
        Args:
            session: SQLModel database session for executing queries
        """
        self.session = session
    
    def create(self, user: User) -> User:
        """
        Create a new user in the database.
        
        Args:
            user: User object to create
            
        Returns:
            User: The created user with populated id
            
        Raises:
            DuplicateUsernameError: If a user with the same username already exists
        """
        try:
            self.session.add(user)
            self.session.commit()
            self.session.refresh(user)
            return user
        except IntegrityError as e:
            self.session.rollback()
            # Check if it's a duplicate username error
            if "UNIQUE constraint failed" in str(e) or "username" in str(e).lower():
                raise DuplicateUsernameError(user.username)
            # Re-raise if it's a different integrity error
            raise
    
    def get_by_username(self, username: str) -> Optional[User]:
        """
        Retrieve a user by username.
        
        Args:
            username: The username to search for
            
        Returns:
            User if found, None otherwise
        """
        statement = select(User).where(User.username == username)
        result = self.session.exec(statement)
        return result.first()
    
    def get_by_id(self, user_id: int) -> Optional[User]:
        """
        Retrieve a user by their ID.
        
        Args:
            user_id: The user ID to search for
            
        Returns:
            User if found, None otherwise
        """
        return self.session.get(User, user_id)
