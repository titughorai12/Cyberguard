
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.connection import Base


class Incident(Base):
    """Store reported cyber-fraud incidents."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    incident_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    affected_platform: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    financial_loss: Mapped[str] = mapped_column(
        String(50),
        default="unknown",
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="reported",
        nullable=False,
    )

    reference_number: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
