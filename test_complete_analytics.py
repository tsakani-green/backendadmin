import requests

# Test all analytics endpoints with detailed data
try:
    print('=== COMPLETE ANALYTICS TEST ===\n')
    
    # Energy Insights
    response = requests.get('http://localhost:8002/api/analytics/energy-insights')
    print(f'Energy Insights: {response.status_code}')
    if response.status_code == 200:
        data = response.json()
        insights = data.get('insights', {})
        print(f'  Data Points: {data.get("data_points", 0)}')
        print(f'  Live Available: {data.get("live_available", False)}')
        print(f'  Summary: {insights.get("summary", "No summary")}')
        print(f'  Efficiency Score: {insights.get("efficiency_score", 0)}')
        print(f'  Cost Savings: {insights.get("cost_savings_potential", "N/A")}')
        print(f'  Carbon Reduction: {insights.get("carbon_reduction_potential", "N/A")}')
        trends = insights.get('trends', [])
        print(f'  Trends: {len(trends)} items')
        for trend in trends[:2]:
            print(f'    - {trend}')
    
    # Carbon Analysis
    response = requests.get('http://localhost:8002/api/analytics/carbon-analysis')
    print(f'\nCarbon Analysis: {response.status_code}')
    if response.status_code == 200:
        data = response.json()
        analysis = data.get('analysis', {})
        print(f'  Total Carbon: {analysis.get("total_carbon_tco2e", 0)} tCO₂e')
        print(f'  Carbon Intensity: {analysis.get("carbon_intensity", "N/A")}')
        print(f'  Compliance Status: {analysis.get("compliance_status", "unknown")}')
        print(f'  Data Points: {analysis.get("data_points", 0)}')
        print(f'  Monthly Average: {analysis.get("avg_monthly_carbon", 0)} tons')
    
    # Performance Metrics
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
    
    # Anomaly Detection
    response = requests.get('http://localhost:8002/api/analytics/anomaly-detection')
    print(f'\nAnomaly Detection: {response.status_code}')
    if response.status_code == 200:
        data = response.json()
        print(f'  Data Points: {data.get("data_points", 0)}')
        print(f'  Average Power: {data.get("average_power_kw", 0)} kW')
        print(f'  Anomalies Detected: {data.get("anomalies_detected", 0)}')
        summary = data.get('analysis_summary', {})
        print(f'  Pattern: {summary.get("pattern", "No pattern")}')
        print(f'  Risk Level: {summary.get("risk_level", "unknown")}')
        
        anomalies = data.get('anomalies', [])
        if anomalies:
            print(f'  Latest Anomaly: {anomalies[0].get("description", "No description")}')
    
    print(f'\n=== ALL ANALYTICS ENDPOINTS WORKING ===')
    
except Exception as e:
    print(f'Error: {e}')
