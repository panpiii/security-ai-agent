"""
Database connection and session management.
"""
from __future__ import annotations

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from typing import Generator

from .models import Base


class DatabaseManager:
    """Manages database connections and sessions."""
    
    def __init__(self, database_url: str = None):
        if database_url is None:
            # Default to SQLite for development
            db_path = os.getenv("SECAGENT_DB_PATH", "secagent.db")
            database_url = f"sqlite:///{db_path}"
        
        self.database_url = database_url
        self.engine = create_engine(
            database_url,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False} if "sqlite" in database_url else {}
        )
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
    
    def create_tables(self):
        """Create all database tables."""
        Base.metadata.create_all(bind=self.engine)
    
    def get_session(self) -> Generator[Session, None, None]:
        """Get database session."""
        db = self.SessionLocal()
        try:
            yield db
        finally:
            db.close()
    
    def get_session_sync(self) -> Session:
        """Get synchronous database session."""
        return self.SessionLocal()


# Global database manager instance
db_manager = DatabaseManager()
