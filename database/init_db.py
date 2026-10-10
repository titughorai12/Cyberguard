
import logging

from app.database.connection import Base, engine
import app.models


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def initialize_database():
    """Create missing CyberGuard database tables."""

    try:
        Base.metadata.create_all(bind=engine)

        logger.info("CyberGuard database initialized successfully.")

        logger.info("Available tables:")

        for table_name in Base.metadata.tables:
            logger.info("- %s", table_name)

    except Exception:
        logger.exception("Database initialization failed.")
        raise


if __name__ == "__main__":
    initialize_database()


