import requests

# Test profile endpoint
try:
    print("🔍 Testing Profile Endpoint")
    print("=" * 40)
    
    # Login first
    login_data = {
        'username': 'dube-user',
        'password': 'dube123'
    }
    
    print("🔐 Logging in...")
    login_response = requests.post('http://localhost:8002/api/auth/login', data=login_data)
    
    if login_response.status_code == 200:
        token_data = login_response.json()
        token = token_data.get('access_token')
        print(f"✅ Login successful")
        print(f"Token: {token[:30]}...")
        
        # Test profile endpoint
        print("\n👤 Testing profile endpoint...")
        headers = {'Authorization': f'Bearer {token}'}
        profile_response = requests.get('http://localhost:8002/api/auth/me', headers=headers)
        
        print(f"Status Code: {profile_response.status_code}")
        print(f"Response: {profile_response.text}")
        
        if profile_response.status_code == 200:
            profile_data = profile_response.json()
            print(f"✅ Profile retrieved successfully")
            print(f"Username: {profile_data.get('username')}")
            print(f"Role: {profile_data.get('role')}")
            print(f"Portfolio Access: {profile_data.get('portfolio_access')}")
        else:
            print(f"❌ Profile retrieval failed")
            
    else:
        print(f"❌ Login failed: {login_response.status_code}")
        print(f"Error: {login_response.text}")
    
    print("\n" + "=" * 40)
    
except Exception as e:
    print(f"❌ Error: {str(e)}")
