"""
Database connection and initialization for the License Compliance Scanner.

This module handles SQLite database setup, connection management, and schema initialization.
"""

from sqlmodel import SQLModel, create_engine, Session
from typing import Generator
from config import get_settings


# Get database URL from configuration
settings = get_settings()
DATABASE_URL = settings.database_url

# Create engine
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args=connect_args
)


def init_db() -> None:
    """
    Initialize the database by creating all tables.
    
    This function should be called on application startup to ensure
    the database schema exists.
    """
    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    """
    Dependency function to get a database session.
    
    Yields a SQLModel Session that can be used for database operations.
    The session is automatically closed after use. Transactions are
    automatically rolled back on errors to prevent data corruption.
    
    Yields:
        Session: A SQLModel database session
        
    Requirements: 7.4
    """
    session = Session(engine)
    try:
        yield session
    except Exception:
        # Rollback transaction on any error to prevent data corruption
        session.rollback()
        raise
    finally:
        session.close()
