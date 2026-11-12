import os
from collections.abc import Generator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from security_platform.persistence.models import Base

DEFAULT_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///:memory:")

_engine: Engine | None = None
_SessionFactory: sessionmaker[Session] | None = None


def get_db_engine(db_url: str | None = None) -> Engine:
    global _engine, _SessionFactory
    url = db_url or DEFAULT_DATABASE_URL
    if _engine is None or db_url is not None:
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        _engine = create_engine(url, connect_args=connect_args, pool_pre_ping=True)
        _SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    return _engine


def init_db(engine: Engine | None = None) -> None:
    """Initializes tables in database using Declarative Base metadata."""
    eng = engine or get_db_engine()
    Base.metadata.create_all(bind=eng)


def get_db_session(engine: Engine | None = None) -> Generator[Session, None, None]:
    """Dependency helper yielding a managed database session."""
    global _SessionFactory
    if _SessionFactory is None:
        get_db_engine()
    assert _SessionFactory is not None
    session = _SessionFactory()
    try:
        yield session
    finally:
        session.close()
