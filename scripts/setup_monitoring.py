# backend/scripts/setup_monitoring.py

import asyncio
import logging
from datetime import datetime, timezone

from app.core.config import settings
from app.services.egauge_client import diagnose_egauge_connection, test_egauge_auth
from app.core.database import db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def setup_monitoring_collections():
    """Create necessary MongoDB collections for monitoring"""
    collections = await db.list_collection_names()
    
    # Create polling_errors collection with indexes
    if "polling_errors" not in collections:
        logger.info("Creating polling_errors collection...")
        await db.create_collection("polling_errors")
        await db.polling_errors.create_index([("timestamp", -1)])
        await db.polling_errors.create_index([("asset_id", 1)])
        logger.info("Created polling_errors collection with indexes")
    
    # Create meter_readings collection with indexes
    if "meter_readings" not in collections:
        logger.info("Creating meter_readings collection...")
        await db.create_collection("meter_readings")
        await db.meter_readings.create_index([("timestamp", -1)])
        await db.meter_readings.create_index([("asset_id", 1)])
        logger.info("Created meter_readings collection with indexes")
    
    # Create health_checks collection
    if "health_checks" not in collections:
        logger.info("Creating health_checks collection...")
        await db.create_collection("health_checks")
        await db.health_checks.create_index([("timestamp", -1)])
        await db.health_checks.create_index([("check_type", 1)])
        logger.info("Created health_checks collection with indexes")


async def test_full_connection():
    """Test the entire eGauge connection pipeline"""
    logger.info("Testing eGauge connection pipeline...")
    
    # Test 1: Configuration
    logger.info(f"1. Configuration check:")
    logger.info(f"   Base URL: {settings.EGAUGE_BASE_URL}")
    logger.info(f"   Auth configured: {bool(settings.EGAUGE_USERNAME and settings.EGAUGE_PASSWORD)}")
    logger.info(f"   Poll interval: {settings.EGAUGE_POLL_INTERVAL_SECONDS}s")
    
    # Test 2: Authentication
    logger.info(f"2. Authentication test:")
    auth_test = await test_egauge_auth(settings.EGAUGE_BASE_URL)
    if auth_test.get("error"):
        logger.error(f"   Auth test error: {auth_test['error']}")
    else:
        logger.info(f"   Without auth: HTTP {auth_test.get('without_auth', {}).get('status')}")
        if auth_test.get('with_auth'):
            logger.info(f"   With auth: HTTP {auth_test['with_auth'].get('status')}")
    
    # Test 3: Endpoint discovery
    logger.info(f"3. Endpoint discovery:")
    diag = await diagnose_egauge_connection(settings.EGAUGE_BASE_URL)
    working = [r for r in diag if r.get("status") == 200]
    logger.info(f"   Found {len(working)} working endpoints")
    
    for result in working[:3]:  # Show first 3
        logger.info(f"   ✓ {result['url']}")
    
    # Test 4: Direct fetch
    logger.info(f"4. Direct fetch test:")
    try:
        from app.services.egauge_client import fetch_check_page_register_watts
        data = await fetch_check_page_register_watts(settings.EGAUGE_BASE_URL)
        logger.info(f"   Success! Power: {data.get('power_kw')} kW")
        logger.info(f"   Raw watts: {data.get('raw_local_mains_w')} W")
    except Exception as e:
        logger.error(f"   Failed: {e}")
    
    return {
        "config": {
            "base_url": settings.EGAUGE_BASE_URL,
            "has_auth": bool(settings.EGAUGE_USERNAME and settings.EGAUGE_PASSWORD),
        },
        "auth_test": auth_test,
        "working_endpoints": len(working),
        "diagnostics": diag,
    }


async def main():
    """Main setup function"""
    logger.info("Starting monitoring setup...")
    
    # Setup database collections
    await setup_monitoring_collections()
    
    # Test connection
    results = await test_full_connection()
    
    # Summary
    logger.info("\n" + "="*60)
    logger.info("SETUP SUMMARY")
    logger.info("="*60)
    logger.info(f"eGauge URL: {results['config']['base_url']}")
    logger.info(f"Authentication: {'Configured' if results['config']['has_auth'] else 'Not configured'}")
    logger.info(f"Working endpoints: {results['working_endpoints']}")
    
    if results['working_endpoints'] > 0:
        logger.info("✅ Setup complete - eGauge connection appears to be working")
    else:
        logger.warning("⚠️  Setup complete - No working endpoints found")
        logger.warning("   Check your eGauge configuration and network connectivity")
    
    logger.info("="*60)


if __name__ == "__main__":
    asyncio.run(main())