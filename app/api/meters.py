# backend/app/api/meters.py

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List
import logging
from datetime import datetime, timezone

from app.services.egauge_poller import (
    LATEST, 
    get_egauge_status, 
    force_poll,
    get_cached_data,
    STATUS,
)
from app.services.egauge_client import (
    diagnose_egauge_connection, 
    test_egauge_auth,
    fetch_check_page_register_watts,
)
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/bertha-house/latest")
async def get_bertha_house_latest(force: bool = False):
    """
    Get latest meter reading for Bertha House.
    
    Parameters:
    - force: If True, force a fresh poll before returning data
    """
    asset_id = "bertha-house"
    
    # Force fresh poll if requested
    if force:
        logger.info(f"Forcing fresh poll for {asset_id}")
        result = await force_poll(asset_id)
        if result["status"] == "error":
            raise HTTPException(
                status_code=503,
                detail={
                    "message": "Failed to fetch fresh data",
                    "error": result.get("error"),
                    "suggestion": "Try without force parameter or check eGauge connection"
                }
            )
        data = result["data"]
    else:
        # Try to get latest data
        data = LATEST.get(asset_id)
        
        # If no data, try cache
        if not data:
            cached = await get_cached_data(asset_id, max_age=None)  # Any cache
            if cached:
                data = cached
                logger.debug(f"Using cached data for {asset_id}")
            else:
                # Last resort: try to poll once
                logger.info(f"No data available for {asset_id}, attempting poll")
                success = await force_poll(asset_id)
                if not success and LAST_ERROR.get(asset_id):
                    raise HTTPException(
                        status_code=503,
                        detail={
                            "message": "No data available",
                            "error": LAST_ERROR.get(asset_id),
                            "status": get_egauge_status(asset_id)["status"]["health"]
                        }
                    )
                data = LATEST.get(asset_id)
    
    if not data:
        raise HTTPException(
            status_code=503,
            detail="No data available for Bertha House. eGauge may be offline."
        )
    
    # Add calculated fields if not present
    if "energy_kwh_delta" not in data or data["energy_kwh_delta"] == 0:
        # Calculate approximate energy if we have power
        if "power_kw" in data:
            # Approximate energy as power * time (1 hour default)
            data["energy_kwh_delta"] = round(data["power_kw"] * 1.0, 3)
            data["cost_zar_delta"] = round(
                data["energy_kwh_delta"] * settings.BERTHA_HOUSE_COST_PER_KWH, 2
            )
    
    # Calculate live carbon emissions using the formula: tCO₂e = kWh × 0.93 ÷ 1000
    if "energy_kwh_delta" in data and data["energy_kwh_delta"] > 0:
        data["carbon_emissions_tco2e"] = round(data["energy_kwh_delta"] * settings.CARBON_FACTOR_KG_PER_KWH / 1000, 6)
        data["carbon_emissions_kg_co2e"] = round(data["energy_kwh_delta"] * settings.CARBON_FACTOR_KG_PER_KWH, 3)
    
    # Calculate current carbon emission rate (tCO₂e per hour) based on current power
    if "power_kw" in data and data["power_kw"] > 0:
        # Assuming current power consumption for 1 hour
        data["carbon_emission_rate_tco2e_per_hour"] = round(data["power_kw"] * settings.CARBON_FACTOR_KG_PER_KWH / 1000, 6)
    
    # Add status information
    status = get_egauge_status(asset_id)
    return {
        **data,
        "_status": {
            "source": data.get("source", "unknown"),
            "health": status["status"]["health"],
            "data_freshness_seconds": status["status"]["data_freshness_seconds"],
            "poll_success": data.get("_metadata", {}).get("poll_success", True),
            "cached": data.get("_metadata", {}).get("poll_timestamp") != data.get("ts_utc"),
        }
    }


@router.get("/status")
async def get_meter_status(asset_id: str = "bertha-house"):
    """Get status of meter polling"""
    return get_egauge_status(asset_id)


@router.get("/diagnose")
async def diagnose_meter_connection():
    """Run diagnostic on eGauge connection"""
    try:
        # Run diagnostics
        connection_diag = await diagnose_egauge_connection(settings.EGAUGE_BASE_URL)
        auth_diag = await test_egauge_auth(settings.EGAUGE_BASE_URL)
        current_status = get_egauge_status()
        
        # Analyze results
        working_urls = [r for r in connection_diag if r.get("status") == 200]
        auth_required = any(r.get("status") == 401 for r in connection_diag)
        
        return {
            "summary": {
                "has_working_endpoints": len(working_urls) > 0,
                "auth_required": auth_required,
                "auth_configured": auth_diag.get("auth_configured", False),
                "auth_working": auth_diag.get("with_auth", {}).get("success", False),
                "current_health": current_status["status"]["health"],
            },
            "config": {
                "base_url": settings.EGAUGE_BASE_URL,
                "poll_interval": settings.EGAUGE_POLL_INTERVAL_SECONDS,
                "has_auth": bool(settings.EGAUGE_USERNAME and settings.EGAUGE_PASSWORD),
            },
            "connection_tests": connection_diag,
            "auth_test": auth_diag,
            "current_status": current_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"Diagnostic failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/test-auth")
async def test_egauge_authentication():
    """Test eGauge authentication"""
    return await test_egauge_auth(settings.EGAUGE_BASE_URL)


@router.post("/force-poll")
async def trigger_force_poll():
    """Manually trigger a poll (for testing)"""
    result = await force_poll("bertha-house")
    return result


@router.get("/health")
async def get_meter_health():
    """Get health status of all meters"""
    results = {}
    for asset_id in STATUS.keys():
        results[asset_id] = get_egauge_status(asset_id)
    
    # Overall health (worst of all assets)
    all_health = [status["status"]["health"] for status in results.values()]
    overall_health = "healthy"
    if "offline" in all_health:
        overall_health = "offline"
    elif "degraded" in all_health:
        overall_health = "degraded"
    
    return {
        "overall": overall_health,
        "assets": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/history/errors")
async def get_polling_errors(limit: int = 50):
    """Get recent polling errors from database"""
    try:
        from app.core.database import db
        errors = await db.polling_errors.find(
            {},
            {"_id": 0}
        ).sort("timestamp", -1).limit(limit).to_list(length=limit)
        
        return {
            "count": len(errors),
            "errors": errors,
        }
    except Exception as e:
        logger.error(f"Failed to fetch errors: {e}")
        raise HTTPException(status_code=500, detail="Database error")


@router.get("/test-direct")
async def test_direct_fetch():
    """Test direct eGauge fetch (bypasses cache and scheduler)"""
    try:
        data = await fetch_check_page_register_watts(settings.EGAUGE_BASE_URL)
        return {
            "success": True,
            "data": data,
            "message": "Direct fetch successful",
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": "Direct fetch failed",
            "config": {
                "base_url": settings.EGAUGE_BASE_URL,
                "has_auth": bool(settings.EGAUGE_USERNAME and settings.EGAUGE_PASSWORD),
            }
        }