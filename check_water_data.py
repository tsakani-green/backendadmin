import requests
from datetime import datetime, timedelta

# Check for water data in Bertha House
try:
    print('=== Checking Bertha House Water Data ===')
    
    # Check ESG metrics for water data
    esg_response = requests.get('http://localhost:8002/api/invoices/esg/metrics?months=12')
    print(f'ESG metrics status: {esg_response.status_code}')
    if esg_response.status_code == 200:
        esg_data = esg_response.json()
        print(f'Water array length: {len(esg_data.get("metrics", {}).get("water_m3", []))}')
        if esg_data.get("metrics", {}).get("water_m3"):
            print(f'Water data: {esg_data["metrics"]["water_m3"][:6]}...') # First 6 values
        else:
            print('No water data in ESG metrics')
    
    # Check database stats for water-related fields
    stats_response = requests.get('http://localhost:8002/api/invoices/mongodb-stats')
    print(f'\nDatabase stats status: {stats_response.status_code}')
    if stats_response.status_code == 200:
        stats = stats_response.json()
        print(f'Total documents: {stats.get("total_documents", 0)}')
        print(f'Collection: {stats.get("collection", "Unknown")}')
        
        # Check if there are any water-related fields
        if 'fields' in stats:
            water_fields = [field for field in stats['fields'] if 'water' in field.lower()]
            if water_fields:
                print(f'Water-related fields found: {water_fields}')
            else:
                print('No water-related fields found in database schema')
    
    # Check if we can get sample invoice data to see water usage
    try:
        # Try to get a few sample invoices to check for water data
        sample_response = requests.get('http://localhost:8002/api/invoices/sample?limit=5')
        print(f'\nSample invoices status: {sample_response.status_code}')
        if sample_response.status_code == 200:
            sample_data = sample_response.json()
            if sample_data.get('invoices'):
                print(f'Sample invoices: {len(sample_data["invoices"])}')
                for i, invoice in enumerate(sample_data['invoices'][:2]):
                    print(f'  Invoice {i+1} keys: {list(invoice.keys())}')
                    # Look for water-related keys
                    water_keys = [k for k in invoice.keys() if 'water' in k.lower()]
                    if water_keys:
                        print(f'    Water keys: {water_keys}')
                        for key in water_keys:
                            print(f'    {key}: {invoice[key]}')
    except Exception as e:
        print(f'Error checking sample invoices: {e}')
    
    # Check analytics endpoints for water data
    try:
        analytics_response = requests.get('http://localhost:8002/api/analytics/energy-insights')
        print(f'\nAnalytics insights status: {analytics_response.status_code}')
        if analytics_response.status_code == 200:
            analytics_data = analytics_response.json()
            print(f'Analytics keys: {list(analytics_data.keys())}')
            if 'water_usage' in analytics_data:
                print(f'Water usage data: {analytics_data["water_usage"]}')
    except Exception as e:
        print(f'Error checking analytics: {e}')

except Exception as e:
    print(f'Error checking water data: {e}')
