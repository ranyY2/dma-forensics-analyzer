from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship, DeclarativeBase


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="user", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    scans: Mapped[list["Scan"]] = relationship(back_populates="user")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="user")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="CREATED", nullable=False)
    scan_mode: Mapped[str] = mapped_column(String(32), default="QUICK", nullable=False)
    platform: Mapped[str] = mapped_column(String(32), default="windows", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scanner_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    report_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    user: Mapped[User] = relationship(back_populates="scans")
    tokens: Mapped[list["ScanToken"]] = relationship(back_populates="scan")
    systems: Mapped[list["SystemRecord"]] = relationship(back_populates="scan")
    devices: Mapped[list["DeviceRecord"]] = relationship(back_populates="scan")
    drivers: Mapped[list["DriverRecord"]] = relationship(back_populates="scan")
    events: Mapped[list["EventRecord"]] = relationship(back_populates="scan")
    findings: Mapped[list["FindingRecord"]] = relationship(back_populates="scan")
    timelines: Mapped[list["TimelineRecord"]] = relationship(back_populates="scan")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="scan")


class ScanToken(Base):
    __tablename__ = "scan_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="tokens")


class SystemRecord(Base):
    __tablename__ = "systems"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    computer_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(32), nullable=True)
    secure_boot: Mapped[bool | None] = mapped_column(nullable=True)
    vbs_state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="systems")


class DeviceRecord(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    vendor_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    pnp_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    class_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    friendly_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="devices")


class DriverRecord(Base):
    __tablename__ = "drivers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signer: Mapped[str | None] = mapped_column(String(128), nullable=True)
    hash_sha256: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="drivers")


class EventRecord(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="events")


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    evidence_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class TimelineRecord(Base):
    __tablename__ = "timelines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="timelines")


class ScannerVersion(Base):
    __tablename__ = "scanner_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    version: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    minimum_supported: Mapped[str] = mapped_column(String(32), nullable=False)
    latest: Mapped[bool] = mapped_column(default=False, nullable=False)
    release_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    user: Mapped[User | None] = relationship(back_populates="audit_logs")
    scan: Mapped[Scan | None] = relationship(back_populates="audit_logs")
