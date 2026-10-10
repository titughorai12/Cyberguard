import logging

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import declarative_base, sessionmaker

from app.core.config import settings

logger = logging.getLogger(__name__)


def build_database_url():
    """Build a PostgreSQL URL safely."""

    # Read the existing database URL.
    database_url = settings.DATABASE_URL

    # Render Postgres supplies postgresql://; this project installs psycopg 3,
    # so select its SQLAlchemy dialect explicitly instead of requiring psycopg2.
    if database_url.startswith("postgres://"):
        database_url = "postgresql+psycopg://" + database_url[len("postgres://"):]
    elif database_url.startswith("postgresql://"):
        database_url = "postgresql+psycopg://" + database_url[len("postgresql://"):]

    # If the password contains special characters, use the
    # separate DB_USER and DB_PASSWORD settings instead.
    db_user = settings.model_config.get("DB_USER")
    db_password = settings.model_config.get("DB_PASSWORD")

    if db_user and db_password:
        return URL.create(
            drivername="postgresql+psycopg",
            username=db_user,
            password=db_password,
            host="localhost",
            port=5432,
            database="cyberguard",
        )

    return database_url


DATABASE_URL = build_database_url()

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)

Base = declarative_base()


def get_db():
    """Provide a database session to FastAPI endpoints."""

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


def check_database_connection() -> bool:
    """Check whether PostgreSQL is reachable."""

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        return True

    except Exception:
        logger.exception("PostgreSQL connection failed")
        return False
