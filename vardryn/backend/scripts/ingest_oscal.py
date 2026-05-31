#!/usr/bin/env python3
"""
OSCAL catalog ingestion script.

Usage:
    python scripts/ingest_oscal.py --catalog /path/to/oscal-catalog.json \
        --db-url postgresql+asyncpg://user:pass@/vardryn?host=/cloudsql/...

Download OSCAL catalogs from:
    NIST SP 800-53 Rev 5: https://github.com/usnistgov/oscal-content
    CMMC 2.0 mapping:     https://www.acq.osd.mil/cmmc/

Run this once to seed the controls table, then re-run when framework updates are released.
"""

import argparse
import asyncio
import sys
from pathlib import Path

# Ensure the app package is importable when running from repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.models.control import Control
from app.models.evidence import Base
from app.services.oscal_service import iter_controls


async def ingest(catalog_path: Path, db_url: str, dry_run: bool) -> None:
    controls = list(iter_controls(catalog_path))
    print(f"Parsed {len(controls)} controls from {catalog_path.name}")

    if dry_run:
        for c in controls[:5]:
            print(" ", c)
        print("  ... (dry-run, not writing to DB)")
        return

    engine = create_async_engine(db_url, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSession(engine) as session:
        for batch_start in range(0, len(controls), 100):
            batch = controls[batch_start : batch_start + 100]
            stmt = pg_insert(Control).values(batch)
            stmt = stmt.on_conflict_do_update(
                index_elements=["scf_id"],
                set_={
                    "title": stmt.excluded.title,
                    "description": stmt.excluded.description,
                    "frameworks": stmt.excluded.frameworks,
                    "domain": stmt.excluded.domain,
                },
            )
            await session.execute(stmt)

        await session.commit()

    print(f"Upserted {len(controls)} controls into the database.")
    await engine.dispose()


def main():
    parser = argparse.ArgumentParser(description="Ingest OSCAL catalog into Vardryn DB")
    parser.add_argument("--catalog", required=True, help="Path to OSCAL JSON catalog file")
    parser.add_argument("--db-url", required=True, help="Async SQLAlchemy DB URL")
    parser.add_argument("--dry-run", action="store_true", help="Parse only, do not write to DB")
    args = parser.parse_args()

    asyncio.run(ingest(Path(args.catalog), args.db_url, args.dry_run))


if __name__ == "__main__":
    main()
