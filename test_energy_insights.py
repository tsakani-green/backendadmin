import requests

try:
    response = requests.get('http://localhost:8002/api/analytics/energy-insights', timeout=10)
    print(f'Energy Insights Status: {response.status_code}')
    if response.status_code == 200:
        data = response.json()
        insights = data.get('insights', {})
        print(f'  Data Points: {data.get("data_points", 0)}')
        summary = insights.get('summary', 'No summary')
        print(f'  Summary: {summary[:80]}...')
        print(f'  Efficiency Score: {insights.get("efficiency_score", 0)}')
        print(f'  Cost Savings: {insights.get("cost_savings_potential", "N/A")}')
        print(f'  Trends Count: {len(insights.get("trends", []))}')
    else:
        print(f'Error: {response.text}')
except Exception as e:
    print(f'Request error: {e}')
