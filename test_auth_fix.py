import requests

# Test if the authentication endpoint is working now
try:
    print('=== Testing Authentication Fix ===\n')
    
    # Test the auth endpoint
    response = requests.get('http://localhost:8002/api/auth/me')
    print(f'Auth endpoint status: {response.status_code}')
    
    if response.status_code == 200:
        data = response.json()
        print(f'Auth response: {data}')
    elif response.status_code == 401:
        print('✅ Auth endpoint working (requires authentication - expected)')
    else:
        print(f'Error: {response.text}')
    
    # Test login endpoint
    print(f'\nTesting login endpoint...')
    login_data = {
        'username': 'test@example.com',
        'password': 'testpass123'
    }
    
    login_response = requests.post('http://localhost:8002/api/auth/login', data=login_data)
    print(f'Login status: {login_response.status_code}')
    
    if login_response.status_code == 200:
        login_data = login_response.json()
        print(f'Login successful: {login_data.get("access_token", "No token")[:20]}...')
    else:
        print(f'Login error: {login_response.text}')
    
    print(f'\n=== Auth Test Complete ===')
    
except Exception as e:
    print(f'Test error: {e}')
