import requests
import json

# Test the reports endpoints
try:
    print('=== Testing Reports Endpoints ===\n')
    
    # Test report templates
    response = requests.get('http://localhost:8002/api/reports/report-templates')
    print(f'Report Templates: {response.status_code}')
    if response.status_code == 200:
        data = response.json()
        templates = data.get('templates', {})
        print(f'  Available templates: {list(templates.keys())}')
        for name, template in templates.items():
            print(f'    - {template.get("name", name)}: {template.get("estimated_time", "N/A")}')
    else:
        print(f'  Error: {response.text}')
    
    # Test generate ESG report
    print(f'\nGenerate ESG Report:')
    try:
        response = requests.post(
            'http://localhost:8002/api/reports/generate-esg-report',
            json={
                "report_type": "comprehensive",
                "format": "json",
                "include_charts": True
            },
            timeout=10
        )
        print(f'  Status: {response.status_code}')
        if response.status_code == 200:
            data = response.json()
            print(f'  Report ID: {data.get("report_id", "N/A")}')
            print(f'  Status: {data.get("status", "N/A")}')
            print(f'  Message: {data.get("message", "N/A")}')
            print(f'  Estimated time: {data.get("estimated_time", "N/A")}')
            
            # Test report status
            report_id = data.get('report_id')
            if report_id:
                print(f'\n  Checking report status...')
                status_response = requests.get(f'http://localhost:8002/api/reports/report-status/{report_id}')
                print(f'  Status check: {status_response.status_code}')
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    print(f'  Report status: {status_data.get("status", "unknown")}')
                    print(f'  Progress: {status_data.get("progress", 0)}%')
                    print(f'  Message: {status_data.get("message", "No message")}')
        else:
            print(f'  Error: {response.text}')
    except Exception as e:
        print(f'  Request error: {e}')
    
    # Test quick report
    print(f'\nGenerate Quick Report:')
    try:
        response = requests.post(
            'http://localhost:8002/api/reports/quick-report',
            json={
                "metrics": ["energy", "carbon", "efficiency"]
            },
            timeout=10
        )
        print(f'  Status: {response.status_code}')
        if response.status_code == 200:
            data = response.json()
            print(f'  Report ID: {data.get("report_id", "N/A")}')
            print(f'  Status: {data.get("status", "N/A")}')
            print(f'  Metrics: {data.get("metrics", [])}')
        else:
            print(f'  Error: {response.text}')
    except Exception as e:
        print(f'  Request error: {e}')
    
    print(f'\n=== Reports Test Complete ===')
    
except Exception as e:
    print(f'Test error: {e}')
