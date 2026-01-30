import requests
import time

# Check the status of the report we just started
report_id = 'esg_report_20260128_053350'

for i in range(5):
    try:
        response = requests.get(f'http://localhost:8002/api/reports/report-status/{report_id}')
        print(f'Check {i+1}: Status Code:', response.status_code)
        if response.status_code == 200:
            status = response.json()
            print(f'  Status: {status["status"]}')
            print(f'  Progress: {status["progress"]}%')
            print(f'  Message: {status["message"]}')
            if status['status'] in ['completed', 'failed']:
                break
        else:
            print(f'  Error: {response.text}')
    except Exception as e:
        print(f'  Error: {e}')
    
    time.sleep(2)

print('Status check complete')
