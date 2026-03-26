"""
Database connection and initialization for the License Compliance Scanner.

This module handles database setup, connection management, and schema initialization.
Supports SQLite (default) with automatic fallback if configured DB is unavailable.
"""

import logging
from sqlmodel import SQLModel, create_engine, Session
from typing import Generator

logger = logging.getLogger(__name__)

# Lazy engine - created on first use
_engine = None

SQLITE_FALLBACK_URL = "sqlite:///./lcs.db"


def _build_engine(database_url: str):
    """Build a SQLAlchemy engine for the given URL."""
    # Normalize postgres:// → postgresql://
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    connect_args = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    return create_engine(database_url, echo=False, connect_args=connect_args)


def get_engine():
    """
    Get or create the database engine (lazy initialization).

    Tries the configured DATABASE_URL first. If it fails (e.g. stale
    PostgreSQL URL on Render free tier), falls back to SQLite automatically.
    """
    global _engine
    if _engine is not None:
        return _engine

    from config import get_settings
    settings = get_settings()
    database_url = settings.database_url

    logger.info(f"Connecting to database: {database_url.split('://')[0]}")

    # If it's already SQLite, just use it directly
    if database_url.startswith("sqlite"):
        _engine = _build_engine(database_url)
        logger.info("SQLite engine created successfully")
        return _engine

    # For non-SQLite (e.g. PostgreSQL), try to connect and fall back to SQLite on failure
    try:
        engine = _build_engine(database_url)
        # Test the connection immediately so we catch errors here, not later
        with engine.connect() as conn:
            conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        _engine = engine
        logger.info(f"Database engine created: {database_url.split('://')[0]}")
    except Exception as e:
        logger.warning(
            f"Could not connect to configured database ({database_url.split('://')[0]}): {e}. "
            f"Falling back to SQLite: {SQLITE_FALLBACK_URL}"
        )
        _engine = _build_engine(SQLITE_FALLBACK_URL)
        logger.info("SQLite fallback engine created successfully")

    return _engine


def init_db() -> None:
    """
    Initialize the database by creating all tables.

    Called on application startup to ensure the schema exists.
    """
    SQLModel.metadata.create_all(get_engine())
    logger.info("Database tables initialized")


def get_session() -> Generator[Session, None, None]:
    """
    Dependency function to get a database session.

    Yields a SQLModel Session for database operations.
    Automatically rolls back on errors and closes on completion.

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
