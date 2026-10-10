
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.connection import Base


class SecurityHistory(Base):
    """Store historical security scores."""

    __tablename__ = "security_history"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    security_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )

    risk_level: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    total_scans: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    threats_detected: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    source: Mapped[str] = mapped_column(
        String(50),
        default="system",
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
