# backend/app/core/database.py

from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings

client = AsyncIOMotorClient(settings.get_mongo_uri())
db = client[settings.get_mongo_db()]


async def get_db():
    return db
