import requests

# Test the new recent activities endpoint
try:
    response = requests.get('http://localhost:8002/api/invoices/recent-activities?limit=5')
    print(f'Recent activities status: {response.status_code}')
    if response.status_code == 200:
        data = response.json()
        activities = data.get('activities', [])
        print(f'Found {len(activities)} activities')
        for i, activity in enumerate(activities[:3]):
            description = activity.get('description', 'No description')
            timestamp = activity.get('timestamp', 'No timestamp')
            print(f'  {i+1}. {description} - {timestamp}')
    else:
        print(f'Error: {response.text}')
except Exception as e:
    print(f'Error testing endpoint: {e}')
