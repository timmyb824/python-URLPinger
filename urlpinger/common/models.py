from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from sqlalchemy.sql.expression import text
from sqlalchemy.sql.sqltypes import TIMESTAMP

from urlpinger.common.db import Base


class UrlConfig(Base):
    __tablename__ = "url_config"

    id = Column(
        Integer,
        primary_key=True,
        server_default=text("generated always as identity"),
    )
    name = Column(String, nullable=True)
    url = Column(String, nullable=False)
    acceptable_status_codes = Column(JSONB, nullable=True)
    retries = Column(Integer, nullable=True)
    retry_interval_seconds = Column(Integer, nullable=True)
    consecutive_failures = Column(Integer, default=0)
    check_type = Column(String, nullable=True, default="http")
    check_interval_seconds = Column(Integer, nullable=True, default=60)
    maintenance = Column(Boolean, default=False)
    status = Column(Boolean, default=True)
    created_at = Column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at = Column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=func.now(),
    )


class SSLCertificate(Base):
    __tablename__ = "ssl_certificates"

    id = Column(
        Integer,
        primary_key=True,
        server_default=text("generated always as identity"),
    )
    domain = Column(String, nullable=False, unique=True)
    expiry_date = Column(DateTime(timezone=True), nullable=False)
    last_checked = Column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=func.now(),
    )
    last_notification_sent = Column(DateTime(timezone=True), nullable=True)
    days_until_expiry = Column(Integer)
