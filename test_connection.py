# test_connection.py

import asyncio
import sys
import os

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def quick_test():
    """Quick test of the eGauge connection"""
    from app.core.config import settings
    from app.services.egauge_client import (
        diagnose_egauge_connection,
        test_egauge_auth,
        fetch_check_page_register_watts
    )
    
    print(f"Testing eGauge connection to: {settings.EGAUGE_BASE_URL}")
    print(f"Auth configured: {bool(settings.EGAUGE_USERNAME and settings.EGAUGE_PASSWORD)}")
    
    try:
        # Test 1: Direct fetch
        print("\n1. Testing direct fetch...")
        data = await fetch_check_page_register_watts(settings.EGAUGE_BASE_URL)
        print(f"   ✓ Success! Power: {data.get('power_kw')} kW")
        
        # Test 2: Status
        from app.services.egauge_poller import get_egauge_status
        status = get_egauge_status()
        print(f"\n2. Current status:")
        print(f"   Health: {status['status']['health']}")
        print(f"   Last success: {status['status']['last_success']}")
        
        return True
        
    except Exception as e:
        print(f"\n✗ Failed: {e}")
        
        # Run diagnostics
        print("\nRunning diagnostics...")
        diag = await diagnose_egauge_connection(settings.EGAUGE_BASE_URL)
        for result in diag[:5]:  # Show first 5
            status = result.get('status', 'ERROR')
            symbol = '✓' if status == 200 else '✗'
            print(f"   {symbol} {result['url']} -> {status}")
        
        return False

if __name__ == "__main__":
    success = asyncio.run(quick_test())
    sys.exit(0 if success else 1)