import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import SessionLocal
from app.main import app
from app.models import Scan, ScanToken, User

client = TestClient(app)


def create_authenticated_scan(mode="QUICK"):
    email = f"{uuid.uuid4()}@example.test"
    auth = client.post("/api/v1/auth/register", json={"email": email, "password": "correct horse battery"})
    assert auth.status_code == 200, auth.text
    token = auth.json()["access_token"]
    response = client.post(
        "/api/v1/scans",
        json={"scan_mode": mode, "platform": "windows"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text
    return response, {"Authorization": f"Bearer {token}"}, auth.json()["user_id"]


def test_authentication_register_login_and_me():
    email = f"{uuid.uuid4()}@example.test"
    password = "correct horse battery"
    registered = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    assert registered.status_code == 200, registered.text
    token = registered.json()["access_token"]
    logged_in = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert logged_in.status_code == 200, logged_in.text
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200, me.text
    assert me.json()["email"] == email


def test_web_console_and_scanner_download_are_available():
    console = client.get("/")
    assert console.status_code == 200
    assert "DMA Forensics" in console.text

    assert client.get("/api/v1/scanner/download").status_code == 401
    auth = client.post("/api/v1/auth/register", json={"email": f"{uuid.uuid4()}@example.test", "password": "correct horse battery"})
    download = client.get("/api/v1/scanner/download", headers={"Authorization": f"Bearer {auth.json()['access_token']}"})
    assert download.status_code == 200
    assert "DmaForensicsScanner.exe" in download.headers.get("content-disposition", "")
    assert download.content.startswith(b"MZ")
    version = client.get("/api/v1/scanner/version").json()
    assert hashlib.sha256(download.content).hexdigest() == version["sha256"]


def test_scan_history_requires_authentication():
    response = client.get("/api/v1/scans")
    assert response.status_code == 401, response.text


def test_create_scan_returns_session_payload():
    response, headers, user_id = create_authenticated_scan()

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == "CREATED"
    assert payload["scan_id"]
    assert payload["upload_token"]
    assert payload["expires_at"]

    db = SessionLocal()
    try:
        scan = db.scalar(select(Scan).where(Scan.scan_id == payload["scan_id"]))
        assert scan is not None
        assert scan.user_id == user_id
        assert db.scalar(select(User).where(User.id == user_id)) is not None
        assert db.scalar(select(ScanToken).where(ScanToken.scan_id == scan.id)) is not None
    finally:
        db.close()


def test_scan_result_upload_requires_valid_token():
    create, _, _ = create_authenticated_scan("STANDARD")
    scan_id = create.json()["scan_id"]
    token = create.json()["upload_token"]

    response = client.post(
        f"/api/v1/scans/{scan_id}/results",
        json={"schema_version": 1, "scan": {"scan_id": scan_id, "scanner_version": "1.4.2"}, "system": {}, "security": {}, "pci_devices": [], "drivers": [], "kernel_events": [], "device_history": [], "execution_artifacts": [], "event_logs": [], "timeline": [], "findings": [], "statistics": {}},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "COMPLETED"


def test_expired_scan_token_is_rejected():
    create, _, _ = create_authenticated_scan()
    scan_id = create.json()["scan_id"]
    token = create.json()["upload_token"]

    db = SessionLocal()
    try:
        token_record = db.scalar(select(ScanToken).join(Scan).where(Scan.scan_id == scan_id))
        assert token_record is not None
        token_record.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        db.commit()
    finally:
        db.close()

    response = client.post(
        f"/api/v1/scans/{scan_id}/results",
        json={
            "schema_version": 1,
            "scan": {"scan_id": scan_id, "scanner_version": "1.4.2"},
            "system": {},
            "security": {},
            "pci_devices": [],
            "drivers": [],
            "kernel_events": [],
            "device_history": [],
            "execution_artifacts": [],
            "event_logs": [],
            "timeline": [],
            "findings": [],
            "statistics": {},
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401, response.text
    assert "expired" in response.json()["detail"].lower()


def test_invalid_result_hash_is_rejected():
    create, _, _ = create_authenticated_scan("DEEP")
    scan_id = create.json()["scan_id"]
    token = create.json()["upload_token"]

    payload = {
        "schema_version": 1,
        "scan": {"scan_id": scan_id, "scanner_version": "1.4.2"},
        "system": {},
        "security": {},
        "pci_devices": [],
        "drivers": [],
        "kernel_events": [],
        "device_history": [],
        "execution_artifacts": [],
        "event_logs": [],
        "timeline": [],
        "findings": [],
        "statistics": {},
        "result_hash": "invalid-hash",
    }

    response = client.post(
        f"/api/v1/scans/{scan_id}/results",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 400, response.text
    assert "hash" in response.json()["detail"].lower()


def test_completed_result_is_available_from_persistent_endpoints():
    create, headers, _ = create_authenticated_scan()
    scan_id = create.json()["scan_id"]
    token = create.json()["upload_token"]
    payload = {
        "schema_version": 1,
        "scan": {"scan_id": scan_id, "scanner_version": "1.4.2"},
        "findings": [{"category": "TEST", "severity": "INFO"}],
        "timeline": [{"category": "TEST"}],
    }

    response = client.post(
        f"/api/v1/scans/{scan_id}/results",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text
    assert client.get(f"/api/v1/scans/{scan_id}", headers=headers).json()["status"] == "COMPLETED"
    report = client.get(f"/api/v1/scans/{scan_id}/report", headers=headers).json()
    assert report["finding_count"] == 1
    assert report["timeline"] == payload["timeline"]
    assert client.get(f"/api/v1/scans/{scan_id}/findings", headers=headers).json()["findings"] == payload["findings"]


def test_get_scanner_version():
    response = client.get("/api/v1/scanner/version")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["latest_version"]
    assert payload["minimum_supported"]
    assert payload["filename"] == "DmaForensicsScanner.exe"
    assert len(payload["sha256"]) == 64
    assert payload["signature_status"] == "unsigned"


def test_scan_history_list():
    _, headers, _ = create_authenticated_scan()
    response = client.get("/api/v1/scans", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert isinstance(payload, list)
