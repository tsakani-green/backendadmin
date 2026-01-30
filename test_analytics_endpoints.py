import requests

# Test all analytics endpoints
endpoints = [
    '/api/analytics/energy-insights',
    '/api/analytics/carbon-analysis', 
    '/api/analytics/performance-metrics',
    '/api/analytics/anomaly-detection'
]

for endpoint in endpoints:
    try:
        response = requests.get(f'http://localhost:8002{endpoint}')
        print(f'{endpoint}: {response.status_code}')
        if response.status_code == 200:
            data = response.json()
            print(f'  Keys: {list(data.keys())}')
            if 'metrics' in data:
                metrics_keys = list(data["metrics"].keys()) if data["metrics"] else "None"
                print(f'  Metrics keys: {metrics_keys}')
        else:
            print(f'  Error: {response.text}')
    except Exception as e:
        print(f'{endpoint}: Error - {e}')
    print()
