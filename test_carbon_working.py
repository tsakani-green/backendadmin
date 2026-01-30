import requests

# Test carbon analysis (working)
try:
    response = requests.get('http://localhost:8002/api/analytics/carbon-analysis')
    print(f'Carbon Analysis Status: {response.status_code}')
    if response.status_code == 200:
        data = response.json()
        analysis = data.get('analysis', {})
        print(f'  Total Carbon: {analysis.get("total_carbon_tco2e", 0)} tCO₂e')
        print(f'  Carbon Intensity: {analysis.get("carbon_intensity", "N/A")}')
        print(f'  Compliance Status: {analysis.get("compliance_status", "unknown")}')
        print(f'  Data Points: {analysis.get("data_points", 0)}')
except Exception as e:
    print(f'Carbon error: {e}')

# Test energy insights (still failing)
try:
    response = requests.get('http://localhost:8002/api/analytics/energy-insights')
    print(f'\nEnergy Insights Status: {response.status_code}')
    if response.status_code != 200:
        print(f'  Error: {response.text}')
except Exception as e:
    print(f'Energy error: {e}')
