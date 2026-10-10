
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.connection import Base


class ThreatAnalysis(Base):
    """Store URL threat analysis results."""

    __tablename__ = "threat_analyses"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    domain: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    threat_type: Mapped[str] = mapped_column(
        String(100),
        default="unknown",
        nullable=False,
    )

    risk_score: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(30),
        default="low",
        nullable=False,
    )

    confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    explanation: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    recommended_action: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    evidence_json: Mapped[str] = mapped_column(
        Text,
        default="[]",
        nullable=False,
    )

    analysis_type: Mapped[str] = mapped_column(
        String(80),
        default="rules_only",
        nullable=False,
    )

    ai_provider: Mapped[str] = mapped_column(
        String(50),
        default="rules",
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )
