from __future__ import annotations

from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from typing import Any
import base64
import hashlib
import hmac
import json
import os
import uuid

from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import SessionLocal, init_db
from app.models import Scan as ScanRecord, ScanToken, User

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FRONTEND_ROOT = os.path.join(PROJECT_ROOT, "frontend")
AUTH_SECRET = os.getenv("DMA_AUTH_SECRET", "development-secret-change-me").encode("utf-8")
SESSION_TTL = timedelta(hours=8)

@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="DMA Forensics API", version="0.2.0", lifespan=lifespan)


class ScanCreateRequest(BaseModel):
    user_id: str | None = Field(default=None, min_length=1)
    scan_mode: str = Field(default="QUICK")
    platform: str = Field(default="windows")
    locale: str | None = None


class ScanResultPayload(BaseModel):
    schema_version: int = Field(default=1, ge=1)
    scan: dict[str, Any]
    system: dict[str, Any] = Field(default_factory=dict)
    security: dict[str, Any] = Field(default_factory=dict)
    pci_devices: list[dict[str, Any]] = Field(default_factory=list)
    drivers: list[dict[str, Any]] = Field(default_factory=list)
    kernel_events: list[dict[str, Any]] = Field(default_factory=list)
    device_history: list[dict[str, Any]] = Field(default_factory=list)
    execution_artifacts: list[dict[str, Any]] = Field(default_factory=list)
    event_logs: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    statistics: dict[str, Any] = Field(default_factory=dict)
    result_hash: str | None = None


class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=8, max_length=256)


class LoginRequest(RegisterRequest):
    pass


SCANNER_VERSION = {
    "latest_version": "0.2.0",
    "minimum_supported": "0.2.0",
}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


init_db()


def canonicalize_json(value: Any) -> str:
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def calculate_hash(payload: dict[str, Any]) -> str:
    canonical = canonicalize_json(payload).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def calculate_file_hash(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return "scrypt$16384$8$1${}${}".format(
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, n, r, p, salt_text, digest_text = stored.split("$", 5)
        if algorithm != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def encode_session(user: User) -> str:
    payload = {
        "sub": user.id,
        "role": user.role,
        "exp": int((now_utc() + SESSION_TTL).timestamp()),
    }
    encoded = base64.urlsafe_b64encode(canonicalize_json(payload).encode("utf-8")).rstrip(b"=")
    signature = hmac.new(AUTH_SECRET, encoded, hashlib.sha256).digest()
    return f"{encoded.decode('ascii')}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')}"


def decode_session(token: str) -> dict[str, Any]:
    try:
        encoded_text, signature_text = token.split(".", 1)
        encoded = encoded_text.encode("ascii")
        expected = hmac.new(AUTH_SECRET, encoded, hashlib.sha256).digest()
        actual = base64.urlsafe_b64decode(signature_text + "=" * (-len(signature_text) % 4))
        if not hmac.compare_digest(actual, expected):
            raise ValueError
        payload = json.loads(base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4)))
        if int(payload["exp"]) <= int(now_utc().timestamp()):
            raise ValueError
        return payload
    except (ValueError, KeyError, TypeError, json.JSONDecodeError, UnicodeError):
        raise HTTPException(status_code=401, detail="Invalid or expired session")


def get_current_user(authorization: str | None) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    return decode_session(authorization.split(" ", 1)[1].strip())


def require_scan_access(scan: ScanRecord, user: dict[str, Any]) -> None:
    if user.get("role") != "admin" and scan.user_id != user.get("sub"):
        raise HTTPException(status_code=403, detail="Scan access denied")


def normalize_iso_datetime(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def get_scan_record(db: Session, scan_id: str) -> ScanRecord:
    scan = db.scalar(select(ScanRecord).where(ScanRecord.scan_id == scan_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


def validate_upload_token(db: Session, scan: ScanRecord, token: str) -> None:
    scan_token = db.scalar(
        select(ScanToken).where(
            ScanToken.scan_id == scan.id,
            ScanToken.token_hash == hash_token(token),
            ScanToken.revoked_at.is_(None),
        )
    )
    if scan_token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid scan token")

    expires_at = scan_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now_utc():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Upload token expired")


@app.get("/health")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/auth/register")
def register(request: RegisterRequest) -> dict[str, Any]:
    email = request.email.strip().lower()
    db = SessionLocal()
    try:
        if db.scalar(select(User).where(User.email == email)) is not None:
            raise HTTPException(status_code=409, detail="Email already registered")
        user = User(id=str(uuid.uuid4()), email=email, password_hash=hash_password(request.password), role="user")
        db.add(user)
        db.commit()
        db.refresh(user)
        return {"user_id": user.id, "email": user.email, "role": user.role, "access_token": encode_session(user)}
    finally:
        db.close()


@app.post("/api/v1/auth/login")
def login(request: LoginRequest) -> dict[str, Any]:
    db = SessionLocal()
    try:
        user = db.scalar(select(User).where(User.email == request.email.strip().lower()))
        if user is None or not verify_password(request.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return {"user_id": user.id, "email": user.email, "role": user.role, "access_token": encode_session(user)}
    finally:
        db.close()


@app.get("/api/v1/auth/me")
def current_user(authorization: str | None = Header(default=None, alias="Authorization")) -> dict[str, Any]:
    session = get_current_user(authorization)
    db = SessionLocal()
    try:
        user = db.get(User, session["sub"])
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return {"user_id": user.id, "email": user.email, "role": user.role}
    finally:
        db.close()


@app.post("/api/v1/scans")
def create_scan(
    request: ScanCreateRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    session = get_current_user(authorization)
    if request.user_id and request.user_id != session["sub"] and session.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Cannot create a scan for another user")
    user_id = request.user_id or session["sub"]
    scan_id = str(uuid.uuid4())
    now = now_utc()
    expires_at = (now + timedelta(minutes=60)).isoformat().replace("+00:00", "Z")
    token = f"scan_token_{uuid.uuid4()}"

    db = SessionLocal()
    try:
        user = db.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")

        db_scan = ScanRecord(
            scan_id=scan_id,
            user_id=user_id,
            status="CREATED",
            scan_mode=request.scan_mode,
            platform=request.platform,
            created_at=now,
            started_at=None,
            completed_at=None,
            scanner_version=SCANNER_VERSION["latest_version"],
            error_message=None,
        )
        db.add(db_scan)
        db.flush()

        db_token = ScanToken(
            scan_id=db_scan.id,
            token_hash=hash_token(token),
            expires_at=normalize_iso_datetime(expires_at),
            used_at=None,
            revoked_at=None,
        )
        db.add(db_token)
        db.commit()
    finally:
        db.close()

    return {
        "scan_id": scan_id,
        "status": "CREATED",
        "upload_token": token,
        "expires_at": expires_at,
        "download_url": "/api/v1/scanner/download",
        "created_at": now.isoformat().replace("+00:00", "Z"),
    }


@app.get("/api/v1/scans")
def list_scans(authorization: str | None = Header(default=None, alias="Authorization")) -> list[dict[str, Any]]:
    session = get_current_user(authorization)
    db = SessionLocal()
    try:
        return [
            {
                "scan_id": scan.scan_id,
                "user_id": scan.user_id,
                "status": scan.status,
                "scan_mode": scan.scan_mode,
                "platform": scan.platform,
                "created_at": scan.created_at.isoformat().replace("+00:00", "Z"),
            }
            for scan in db.scalars(
                select(ScanRecord)
                .where(ScanRecord.user_id == session["sub"] if session.get("role") != "admin" else True)
                .order_by(ScanRecord.created_at)
            ).all()
        ]
    finally:
        db.close()


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: str, authorization: str | None = Header(default=None, alias="Authorization")) -> dict[str, Any]:
    session = get_current_user(authorization)
    db = SessionLocal()
    try:
        scan = get_scan_record(db, scan_id)
        require_scan_access(scan, session)
        token = db.scalar(select(ScanToken).where(ScanToken.scan_id == scan.id).order_by(ScanToken.expires_at.desc()))
        return {
            "scan_id": scan.scan_id,
            "user_id": scan.user_id,
            "status": scan.status,
            "scan_mode": scan.scan_mode,
            "platform": scan.platform,
            "created_at": scan.created_at.isoformat().replace("+00:00", "Z"),
            "expires_at": token.expires_at.isoformat().replace("+00:00", "Z") if token else None,
        }
    finally:
        db.close()


@app.get("/api/v1/scanner/version")
def scanner_version() -> dict[str, str]:
    scanner_path = os.path.join(PROJECT_ROOT, "DmaForensicsScanner.exe")
    result = dict(SCANNER_VERSION)
    result["filename"] = "DmaForensicsScanner.exe"
    result["sha256"] = calculate_file_hash(scanner_path) if os.path.isfile(scanner_path) else ""
    result["signature_status"] = "unsigned"
    return result


@app.get("/api/v1/scanner/download")
def scanner_download(authorization: str | None = Header(default=None, alias="Authorization")) -> FileResponse:
    get_current_user(authorization)
    scanner_path = os.path.join(PROJECT_ROOT, "DmaForensicsScanner.exe")
    if not os.path.isfile(scanner_path):
        raise HTTPException(status_code=404, detail="Scanner package unavailable")
    return FileResponse(scanner_path, media_type="application/vnd.microsoft.portable-executable", filename="DmaForensicsScanner.exe")


@app.post("/api/v1/scans/{scan_id}/results")
def upload_results(
    scan_id: str,
    payload: ScanResultPayload,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = authorization.split(" ", 1)[1].strip()
    db = SessionLocal()
    try:
        scan = get_scan_record(db, scan_id)
        validate_upload_token(db, scan, token)

        if payload.scan.get("scan_id") != scan_id:
            raise HTTPException(status_code=400, detail="Payload scan_id does not match route")

        payload_dict = payload.model_dump(mode="json")
        provided_hash = payload_dict.get("result_hash")
        if provided_hash is None:
            payload_dict["result_hash"] = calculate_hash({k: v for k, v in payload_dict.items() if k != "result_hash"})
        else:
            computed_hash = calculate_hash({k: v for k, v in payload_dict.items() if k != "result_hash"})
            if provided_hash != computed_hash:
                raise HTTPException(status_code=400, detail="Invalid result hash")

        scan.status = "COMPLETED"
        scan.completed_at = now_utc()
        scan.result_json = payload_dict
        scan.report_json = {
            "scan_id": scan_id,
            "status": "COMPLETED",
            "finding_count": len(payload_dict.get("findings", [])),
            "timeline_count": len(payload_dict.get("timeline", [])),
        }
        db.commit()
        return {"status": "COMPLETED", "scan_id": scan_id, "result_hash": payload_dict["result_hash"]}
    finally:
        db.close()


@app.get("/api/v1/scans/{scan_id}/report")
def get_report(
    scan_id: str,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    session = get_current_user(authorization)
    db = SessionLocal()
    try:
        scan = get_scan_record(db, scan_id)
        require_scan_access(scan, session)
        report = dict(scan.report_json or {"scan_id": scan_id, "status": scan.status, "findings": []})
        result = scan.result_json or {}
        report["timeline"] = result.get("timeline", [])
        report["security"] = result.get("security", {})
        report["statistics"] = result.get("statistics", {})
        report["system"] = result.get("system", {})
        return report
    finally:
        db.close()


@app.get("/api/v1/scans/{scan_id}/findings")
def get_findings(
    scan_id: str,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    session = get_current_user(authorization)
    db = SessionLocal()
    try:
        scan = get_scan_record(db, scan_id)
        require_scan_access(scan, session)
        return {"scan_id": scan_id, "findings": (scan.result_json or {}).get("findings", [])}
    finally:
        db.close()


if os.path.isdir(FRONTEND_ROOT):
    app.mount("/", StaticFiles(directory=FRONTEND_ROOT, html=True), name="frontend")
