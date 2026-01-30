import requests

try:
    response = requests.get('http://localhost:8002/api/analytics/anomaly-detection', timeout=10)
    print(f'Anomaly Detection Status: {response.status_code}')
    if response.status_code == 200:
        data = response.json()
        print(f'  Data Points: {data.get("data_points", 0)}')
        print(f'  Average Power: {data.get("average_power_kw", 0)} kW')
        print(f'  Std Deviation: {data.get("std_deviation", 0)}')
        print(f'  Anomalies Detected: {data.get("anomalies_detected", 0)}')
        
        anomalies = data.get('anomalies', [])
        if anomalies:
            print(f'  Latest Anomaly: {anomalies[0].get("description", "No description")}')
        
        summary = data.get('analysis_summary', {})
        print(f'  Pattern: {summary.get("pattern", "No pattern")}')
        print(f'  Risk Level: {summary.get("risk_level", "unknown")}')
    else:
        print(f'Error: {response.text}')
except Exception as e:
    print(f'Request error: {e}')
