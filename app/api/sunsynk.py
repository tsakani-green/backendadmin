# backend/app/api/sunsynk.py

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any
import logging

from ..services.sunsynk_service import sunsynk_service
from ..api.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter()

@router.get("/bertha-house/data")
async def get_bertha_house_data(current_user: Dict = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Get Bertha House energy data from Sunsynk API
    Returns current power (kW) and energy usage (kWh)
    """
    try:
        # Check if user is authenticated
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Get data from Sunsynk service
        data = await sunsynk_service.get_bertha_house_data()
        
        if not data:
            raise HTTPException(status_code=500, detail="Failed to retrieve data from Sunsynk API")
        
        return {
            "success": True,
            "data": data,
            "message": "Bertha House energy data retrieved successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting Bertha House data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/bertha-house/realtime")
async def get_bertha_house_realtime(current_user: Dict = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Get real-time Bertha House data only
    """
    try:
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        data = await sunsynk_service.get_bertha_house_data()
        
        return {
            "success": True,
            "data": {
                "current_power_kw": data.get("current_power_kw", 0),
                "timestamp": data.get("timestamp"),
                "device_name": data.get("device_info", {}).get("name", "Unknown")
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting Bertha House realtime data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/devices")
async def get_devices(current_user: Dict = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Get list of available devices from Sunsynk API
    """
    try:
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        devices = await sunsynk_service.get_device_list()
        
        return {
            "success": True,
            "data": devices,
            "count": len(devices)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting devices: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
