"""
Database connection and initialization for the License Compliance Scanner.

This module handles SQLite database setup, connection management, and schema initialization.
"""

from sqlmodel import SQLModel, create_engine, Session
from typing import Generator, Optional
from config import get_settings


# Lazy engine - created on first use to avoid import-time connection errors
_engine = None


def get_engine():
    """Get or create the database engine (lazy initialization)."""
    global _engine
    if _engine is None:
        import os
        import logging
        logger = logging.getLogger(__name__)

        settings = get_settings()
        database_url = settings.database_url

        # Safety fallback: if URL is postgres but psycopg2 fails, use SQLite
        # Also handle Render injecting postgres:// instead of postgresql://
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)

        logger.info(f"Initializing database engine with URL type: {database_url.split('://')[0]}")

        connect_args = {}
        if database_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False

        _engine = create_engine(
            database_url,
            echo=False,
            connect_args=connect_args
        )
    return _engine


def init_db() -> None:
    """
    Initialize the database by creating all tables.

    This function should be called on application startup to ensure
    the database schema exists.
    """
    SQLModel.metadata.create_all(get_engine())


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
    session = Session(get_engine())
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
