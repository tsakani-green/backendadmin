# backend/app/api/assets.py

from fastapi import APIRouter

router = APIRouter(prefix="/api/assets", tags=["assets"])


@router.get("/")
async def list_assets():
    return {"message": "Assets router is live"}
