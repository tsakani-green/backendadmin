import requests
import json
import time

def test_report_generation():
    print("Testing AI Report Generation...")
    
    # Test 1: Get report templates
    print("\n1. Testing report templates...")
    response = requests.get('http://localhost:8002/api/reports/report-templates')
    if response.status_code == 200:
        templates = response.json()['templates']
        print(f"✓ Found {len(templates)} templates: {list(templates.keys())}")
    else:
        print(f"✗ Error getting templates: {response.status_code}")
        return

    # Test 2: Start quick report generation
    print("\n2. Starting quick report generation...")
    response = requests.post('http://localhost:8002/api/reports/quick-report', 
                            json={'metrics': ['energy', 'carbon', 'efficiency']})
    
    if response.status_code == 200:
        report_id = response.json()['report_id']
        print(f"✓ Quick report started with ID: {report_id}")
        
        # Test 3: Poll for completion
        print("\n3. Monitoring report generation...")
        for i in range(15):
            status_response = requests.get(f'http://localhost:8002/api/reports/report-status/{report_id}')
            if status_response.status_code == 200:
                status = status_response.json()
                print(f"   Status: {status['status']} - {status['progress']}% - {status['message']}")
                
                if status['status'] == 'completed':
                    print("✓ Report generation completed successfully!")
                    
                    # Test 4: Download report
                    print("\n4. Testing report download...")
                    download_response = requests.get(f'http://localhost:8002/api/reports/download/{report_id}')
                    if download_response.status_code == 200:
                        print("✓ Report downloaded successfully")
                        print(f"   Content type: {download_response.headers.get('content-type')}")
                    else:
                        print(f"✗ Download failed: {download_response.status_code}")
                    break
                    
                elif status['status'] == 'failed':
                    print(f"✗ Report generation failed: {status['message']}")
                    break
                    
            else:
                print(f"✗ Error checking status: {status_response.status_code}")
                break
                
            time.sleep(2)
        else:
            print("⚠ Report generation timed out")
            
    else:
        print(f"✗ Error starting report: {response.status_code}")
        print(f"   Response: {response.text}")

    print("\n" + "="*50)
    print("AI Report Generation Test Complete")
    print("="*50)

if __name__ == "__main__":
    test_report_generation()
