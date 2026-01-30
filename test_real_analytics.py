import requests
import json

# Test energy insights with real data
try:
    response = requests.get('http://localhost:8002/api/analytics/energy-insights')
    print(f'Energy Insights: {response.status_code}')
    if response.status_code == 200:
        data = response.json()
        insights = data.get('insights', {})
        print(f'  Summary: {insights.get("summary", "No summary")}')
        print(f'  Data Points: {data.get("data_points", 0)}')
        print(f'  Live Available: {data.get("live_available", False)}')
        print(f'  Efficiency Score: {insights.get("efficiency_score", 0)}')
        print(f'  Cost Savings: {insights.get("cost_savings_potential", "N/A")}')
        print(f'  Trends: {insights.get("trends", [])[:2]}')
except Exception as e:
    print(f'Error: {e}')

# Test performance metrics
try:
    response = requests.get('http://localhost:8002/api/analytics/performance-metrics')
    print(f'\nPerformance Metrics: {response.status_code}')
    if response.status_code == 200:
        data = response.json()
        metrics = data.get('metrics', {})
        current_perf = metrics.get('current_performance', {})
        print(f'  Current Power: {current_perf.get("power_kw", 0)} kW')
        print(f'  Efficiency Score: {current_perf.get("efficiency_score", 0)}%')
        print(f'  Performance Level: {current_perf.get("performance_level", "unknown")}')
        print(f'  Energy Delta: {current_perf.get("energy_delta_kwh", 0)} kWh')
        print(f'  Cost Delta: R{current_perf.get("cost_delta_zar", 0)}')
except Exception as e:
    print(f'Error: {e}')
