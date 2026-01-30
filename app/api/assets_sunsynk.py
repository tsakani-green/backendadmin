# backend/app/api/assets.py

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List
from datetime import datetime, timedelta
import logging

from ..core.database import db
from ..services.sunsynk_service import sunsynk_service
from ..api.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/sunsynk/add-to-bertha-house")
async def add_sunsynk_to_bertha_house(current_user: Dict = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Add Sunsynk energy monitoring as an asset to Bertha House portfolio
    """
    try:
        # Check if user is authenticated
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Get Sunsynk data
        sungsynk_data = await sunsynk_service.get_bertha_house_data()
        if not sungsynk_data:
            raise HTTPException(status_code=500, detail="Failed to retrieve Sunsynk data")
        
        # Calculate carbon emissions
        # Formula: CO₂ (kg) = Energy (kWh) × 0.93
        current_power_kw = sungsynk_data.get("current_power_kw", 0)
        daily_energy_kwh = sungsynk_data.get("daily_energy_kwh", 0)
        total_energy_kwh = sungsynk_data.get("total_energy_kwh", 0)
        
        # Carbon emissions
        daily_emissions_kg = daily_energy_kwh * 0.93
        total_emissions_kg = total_energy_kwh * 0.93
        total_emissions_tonnes = total_emissions_kg / 1000
        
        # Create asset object
        sunsynk_asset = {
            "id": "bertha-house-sunsynk-inverter",
            "name": "Bertha House Sunsynk Inverter",
            "type": "Energy Monitor",
            "category": "Renewable Energy",
            "status": "active",
            "location": "Bertha House",
            "device_info": sungsynk_data.get("device_info", {}),
            "energy_data": {
                "current_power_kw": current_power_kw,
                "daily_energy_kwh": daily_energy_kwh,
                "total_energy_kwh": total_energy_kwh,
                "last_updated": sungsynk_data.get("timestamp")
            },
            "emissions": {
                "daily_emissions_kg": round(daily_emissions_kg, 2),
                "total_emissions_kg": round(total_emissions_kg, 2),
                "total_emissions_tonnes": round(total_emissions_tonnes, 3),
                "carbon_factor_kg_per_kwh": 0.93
            },
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        # Add to Bertha House portfolio in database
        await db.users.update_one(
            {"username": {"$in": ["bertha", "bertha-house", "bertha-user"]}},
            {
                "$push": {
                    "portfolios": {
                        "id": "bertha-house-sunsynk",
                        "name": "Bertha House Energy Monitor",
                        "type": "Asset",
                        "asset_id": "bertha-house-sunsynk-inverter",
                        "status": "active",
                        "created_at": datetime.utcnow()
                    }
                }
            }
        )
        
        # Store asset data in a separate collection for detailed tracking
        await db.assets.update_one(
            {"asset_id": "bertha-house-sunsynk-inverter"},
            {
                "$set": sunsynk_asset,
                "$setOnInsert": {
                    "asset_id": "bertha-house-sunsynk-inverter",
                    "created_at": datetime.utcnow()
                }
            },
            upsert=True
        )
        
        logger.info(f"Added Sunsynk asset to Bertha House: {sungsynk_asset['name']}")
        
        return {
            "success": True,
            "message": "Sunsynk energy monitor added to Bertha House portfolio",
            "asset": sunsynk_asset
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding Sunsynk asset to Bertha House: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/sunsynk/bertha-house-asset")
async def get_bertha_house_sunsynk_asset(current_user: Dict = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Get Sunsynk asset data for Bertha House including carbon emissions
    """
    try:
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Get latest Sunsynk data
        sungsynk_data = await sunsynk_service.get_bertha_house_data()
        if not sungsynk_data:
            raise HTTPException(status_code=500, detail="Failed to retrieve Sunsynk data")
        
        # Calculate carbon emissions
        current_power_kw = sungsynk_data.get("current_power_kw", 0)
        daily_energy_kwh = sungsynk_data.get("daily_energy_kwh", 0)
        total_energy_kwh = sungsynk_data.get("total_energy_kwh", 0)
        
        # Carbon emissions calculations
        daily_emissions_kg = daily_energy_kwh * 0.93
        total_emissions_kg = total_energy_kwh * 0.93
        total_emissions_tonnes = total_emissions_kg / 1000
        
        # Calculate monthly emissions estimate (based on daily average)
        monthly_emissions_kg = daily_emissions_kg * 30
        monthly_emissions_tonnes = monthly_emissions_kg / 1000
        
        # Calculate annual emissions estimate
        annual_emissions_kg = daily_emissions_kg * 365
        annual_emissions_tonnes = annual_emissions_kg / 1000
        
        asset_data = {
            "asset_id": "bertha-house-sunsynk-inverter",
            "name": "Bertha House Sunsynk Inverter",
            "type": "Energy Monitor",
            "status": "online",
            "real_time_data": {
                "current_power_kw": current_power_kw,
                "daily_energy_kwh": daily_energy_kwh,
                "total_energy_kwh": total_energy_kwh,
                "timestamp": sungsynk_data.get("timestamp")
            },
            "carbon_emissions": {
                "current_power_emissions_kg_per_hour": round(current_power_kw * 0.93, 3),
                "daily_emissions_kg": round(daily_emissions_kg, 2),
                "daily_emissions_tonnes": round(daily_emissions_kg / 1000, 3),
                "monthly_emissions_kg": round(monthly_emissions_kg, 2),
                "monthly_emissions_tonnes": round(monthly_emissions_tonnes, 2),
                "annual_emissions_kg": round(annual_emissions_kg, 2),
                "annual_emissions_tonnes": round(annual_emissions_tonnes, 2),
                "total_emissions_kg": round(total_emissions_kg, 2),
                "total_emissions_tonnes": round(total_emissions_tonnes, 3),
                "carbon_factor_kg_per_kwh": 0.93
            },
            "device_info": sungsynk_data.get("device_info", {}),
            "last_updated": datetime.utcnow().isoformat()
        }
        
        return {
            "success": True,
            "data": asset_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting Bertha House Sunsynk asset: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/assets/bertha-house")
async def get_bertha_house_assets(current_user: Dict = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Get all assets for Bertha House including the Sunsynk energy monitor
    """
    try:
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Get Sunsynk asset data
        sungsynk_asset = None
        try:
            sungsynk_response = await get_bertha_house_sunsynk_asset(current_user)
            if sungsynk_response["success"]:
                sungsynk_asset = sungsynk_response["data"]
        except:
            pass
        
        # Get other assets from database
        other_assets = []
        try:
            cursor = db.assets.find({"location": "Bertha House"})
            async for asset in cursor:
                if asset.get("asset_id") != "bertha-house-sunsynk-inverter":
                    asset_dict = dict(asset)
                    asset_dict.pop("_id", None)
                    other_assets.append(asset_dict)
        except:
            pass
        
        all_assets = []
        if sungsynk_asset:
            all_assets.append(sungsynk_asset)
        all_assets.extend(other_assets)
        
        return {
            "success": True,
            "data": {
                "assets": all_assets,
                "total_count": len(all_assets),
                "sunsynk_asset": sungsynk_asset
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting Bertha House assets: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
