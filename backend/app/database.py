"""Async database setup — PostgreSQL in Docker, SQLite fallback for local dev."""

import os
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

_url = os.getenv("DATABASE_URL", "postgresql+asyncpg://aso:aso@db:5432/aso")

# If running locally without Docker, auto-fallback to SQLite
if _url.startswith("postgresql") and os.getenv("ASO_LOCAL_DEV"):
    _url = "sqlite+aiosqlite:///./aso.db"

DATABASE_URL = _url

_engine_kwargs: dict = {"echo": False}
if not DATABASE_URL.startswith("sqlite"):
    _engine_kwargs.update(pool_size=10, max_overflow=20)

engine = create_async_engine(DATABASE_URL, **_engine_kwargs)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    from . import models  # noqa: F401
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
