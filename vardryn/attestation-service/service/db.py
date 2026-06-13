"""
Database session management — RLS tenant context.

Every `attestation_*` table has Row-Level Security enabled, gated on
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
(db/migrations/001, 002). `tenant_session()` sets that setting via
`set_config(..., is_local=true)` at the start of each transaction, so RLS
confines every statement in that transaction to one tenant — even if
application code forgets a `WHERE tenant_id = ...` clause. If
`app.current_tenant_id` is never set, `current_setting(..., true)` returns
NULL, `NULL::uuid` is NULL, and the RLS predicate is NULL (not true) for
every row — i.e. the failure mode is "see nothing", not "see everything".

`set_config()` is used (not a literal `SET LOCAL ... = :value`) because
`SET` is a utility statement and most drivers will not bind parameters into
it; `set_config()` is an ordinary function call and accepts a normal bind
parameter, so `tenant_id` cannot be used for SQL injection here.

`DATABASE_URL` (e.g.
`postgresql+psycopg2://attestation_app:...@host/dbname`) is read from the
environment. How that URL is constructed (Cloud SQL Auth Proxy, Cloud SQL
Python Connector, IAM DB auth, etc.) is a deployment concern outside this
module's scope.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _SessionLocal


@contextmanager
def tenant_session(tenant_id: UUID | str) -> Iterator[Session]:
    """
    Yields a `Session` whose current transaction has `app.current_tenant_id`
    set to `tenant_id`. Commits on clean exit, rolls back on exception.

    `set_config('app.current_tenant_id', <tenant_id>, true)` — the `true`
    (is_local) makes this transaction-scoped: it resets automatically on
    commit/rollback, so a pooled connection can never leak one request's
    tenant context into the next.
    """
    session = get_session_factory()()
    try:
        session.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
            {"tenant_id": str(tenant_id)},
        )
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
