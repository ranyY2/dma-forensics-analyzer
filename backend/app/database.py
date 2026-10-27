from __future__ import annotations

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from app.models import Base

DATABASE_URL = "sqlite:///./dma_forensics.db"

engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    columns = {column["name"] for column in inspect(engine).get_columns("scans")}
    with engine.begin() as connection:
        if "result_json" not in columns:
            connection.execute(text("ALTER TABLE scans ADD COLUMN result_json JSON"))
        if "report_json" not in columns:
            connection.execute(text("ALTER TABLE scans ADD COLUMN report_json JSON"))
