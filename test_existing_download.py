import requests

# Test download with existing report
try:
    print('=== Testing Download with Existing Report ===\n')
    
    # Use an existing report ID
    report_id = "quick_report_20260128_082502"
    print(f'Testing with report ID: {report_id}')
    
    # Test JSON download
    print(f'\n1. Testing JSON download...')
    json_response = requests.get(f'http://localhost:8002/api/reports/download/{report_id}?format=json')
    print(f'   Status: {json_response.status_code}')
    
    if json_response.status_code == 200:
        print(f'   Content type: {json_response.headers.get("content-type", "unknown")}')
        print(f'   Content length: {len(json_response.content)} bytes')
        print('   ✅ JSON download successful!')
    else:
        print(f'   Error: {json_response.text}')
    
    # Test PDF download (should now be .txt)
    print(f'\n2. Testing PDF/Text download...')
    pdf_response = requests.get(f'http://localhost:8002/api/reports/download/{report_id}?format=pdf')
    print(f'   Status: {pdf_response.status_code}')
    
    if pdf_response.status_code == 200:
        print(f'   Content type: {pdf_response.headers.get("content-type", "unknown")}')
        print(f'   Content length: {len(pdf_response.content)} bytes')
        
        # Show first few lines of content
        content = pdf_response.text[:200]
        print(f'   Content preview: {content}...')
        print('   ✅ Text download successful!')
    else:
        print(f'   Error: {pdf_response.text}')
    
    print(f'\n=== Download Test Complete ===')
    
except Exception as e:
    print(f'Test error: {e}')
