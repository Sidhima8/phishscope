import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.base import Base
from app.db.session import engine
from app.models.user import User
from app.core.security import get_password_hash

logger = logging.getLogger(__name__)


async def init_db() -> None:
    async with engine.begin() as conn:
        # Create all tables if they do not exist
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Database schema initialized.")

    # Seed initial users
    from app.db.session import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        # Check if users already exist
        res = await session.execute(select(User).limit(1))
        existing_user = res.scalars().first()
        if not existing_user:
            default_users = [
                User(
                    email="admin@phishscope.local",
                    full_name="SOC Administrator",
                    hashed_password=get_password_hash("AdminPass123!"),
                    role="ADMIN",
                    is_active=True,
                ),
                User(
                    email="analyst@phishscope.local",
                    full_name="Lead SOC Analyst",
                    hashed_password=get_password_hash("AnalystPass123!"),
                    role="ANALYST",
                    is_active=True,
                ),
                User(
                    email="viewer@phishscope.local",
                    full_name="Incident Response Viewer",
                    hashed_password=get_password_hash("ViewerPass123!"),
                    role="VIEWER",
                    is_active=True,
                )
            ]
            session.add_all(default_users)
            await session.commit()
            logger.info("Default seed users created successfully.")
