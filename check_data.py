import requests
from datetime import datetime, timedelta

# Check what real data we have available
try:
    # Get meter data history
    print('=== Checking available data sources ===')
    
    # Check if we have historical meter data endpoint
    try:
        response = requests.get('http://localhost:8002/api/meters/bertha-house/history?days=365')
        print(f'Meter history endpoint: {response.status_code}')
        if response.status_code == 200:
            data = response.json()
            print(f'  Data points: {len(data.get("data", []))}')
            if data.get("data"):
                print(f'  Latest: {data["data"][0]}')
    except Exception as e:
        print(f'Meter history error: {e}')
    
    # Check ESG metrics structure
    esg_response = requests.get('http://localhost:8002/api/invoices/esg/metrics?months=12')
    print(f'\nESG metrics structure: {esg_response.status_code}')
    if esg_response.status_code == 200:
        esg_data = esg_response.json()
        print(f'  Energy array length: {len(esg_data.get("metrics", {}).get("energy_kwh", []))}')
        print(f'  CO2 array length: {len(esg_data.get("metrics", {}).get("co2e_tons", []))}')
        print(f'  Water array length: {len(esg_data.get("metrics", {}).get("water_m3", []))}')
        print(f'  Note: {esg_data.get("note", "No note")}')
    
    # Check database stats
    stats_response = requests.get('http://localhost:8002/api/invoices/mongodb-stats')
    print(f'\nDatabase stats: {stats_response.status_code}')
    if stats_response.status_code == 200:
        stats = stats_response.json()
        print(f'  Total documents: {stats.get("total_documents", 0)}')
        print(f'  Collection: {stats.get("collection", "Unknown")}')

except Exception as e:
    print(f'Error checking data: {e}')
