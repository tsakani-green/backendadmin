import requests
import json

# Test the download functionality
try:
    print('=== Testing Report Download ===\n')
    
    # First generate a quick report to get a report ID
    print('1. Generating quick report...')
    response = requests.post(
        'http://localhost:8002/api/reports/quick-report',
        json={
            "metrics": ["energy", "carbon", "efficiency"]
        },
        timeout=10
    )
    
    if response.status_code == 200:
        data = response.json()
        report_id = data.get('report_id')
        print(f'   Report ID: {report_id}')
        
        if report_id:
            # Wait a moment for report generation
            import time
            time.sleep(2)
            
            # Check report status
            print(f'\n2. Checking report status...')
            status_response = requests.get(f'http://localhost:8002/api/reports/report-status/{report_id}')
            print(f'   Status: {status_response.status_code}')
            if status_response.status_code == 200:
                status_data = status_response.json()
                print(f'   Report status: {status_data.get("status", "unknown")}')
                print(f'   Progress: {status_data.get("progress", 0)}%')
                
                if status_data.get('status') == 'completed':
                    # Test download
                    print(f'\n3. Testing JSON download...')
                    download_response = requests.get(f'http://localhost:8002/api/reports/download/{report_id}?format=json')
                    print(f'   Download status: {download_response.status_code}')
                    
                    if download_response.status_code == 200:
                        print(f'   Content type: {download_response.headers.get("content-type", "unknown")}')
                        print(f'   Content length: {len(download_response.content)} bytes')
                        
                        # Try to parse JSON content
                        try:
                            content = download_response.json()
                            print(f'   JSON content keys: {list(content.keys())[:5]}...')
                            print('   ✅ JSON download successful!')
                        except:
                            print('   ⚠️  Content is not valid JSON')
                    else:
                        print(f'   Download error: {download_response.text}')
                        
                    print(f'\n4. Testing PDF download...')
                    pdf_response = requests.get(f'http://localhost:8002/api/reports/download/{report_id}?format=pdf')
                    print(f'   PDF download status: {pdf_response.status_code}')
                    
                    if pdf_response.status_code == 200:
                        print(f'   Content type: {pdf_response.headers.get("content-type", "unknown")}')
                        print(f'   Content length: {len(pdf_response.content)} bytes')
                        print('   ✅ PDF download successful!')
                    else:
                        print(f'   PDF download error: {pdf_response.text}')
                else:
                    print(f'   Report not completed yet, status: {status_data.get("status")}')
            else:
                print(f'   Status check error: {status_response.text}')
        else:
            print('   No report ID received')
    else:
        print(f'   Quick report error: {response.text}')
    
    print(f'\n=== Download Test Complete ===')
    
except Exception as e:
    print(f'Test error: {e}')
    import traceback
    traceback.print_exc()
