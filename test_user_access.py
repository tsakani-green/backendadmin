import requests
import asyncio
import sys
import os
from motor.motor_asyncio import AsyncIOMotorClient

# Add the backend directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.config import settings

async def test_user_access():
    """Test user access control for different users"""
    
    # Connect to MongoDB
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client[settings.MONGO_DB_NAME or "esg_dashboard"]
    
    try:
        print("🔐 Testing User Access Control")
        print("=" * 50)
        
        # Test users
        test_users = [
            {
                "username": "admin",
                "password": "admin123",
                "expected_access": ["dube-trade-port", "bertha-house"],
                "role": "admin"
            },
            {
                "username": "dube-user",
                "password": "dube123",
                "expected_access": ["dube-trade-port"],
                "role": "client"
            },
            {
                "username": "bertha-user",
                "password": "bertha123",
                "expected_access": ["bertha-house"],
                "role": "client"
            }
        ]
        
        for test_user in test_users:
            print(f"\n👤 Testing {test_user['username']} ({test_user['role']}):")
            
            # Test login
            login_data = {
                'username': test_user['username'],
                'password': test_user['password']
            }
            
            login_response = requests.post('http://localhost:8002/api/auth/login', data=login_data)
            
            if login_response.status_code == 200:
                token_data = login_response.json()
                token = token_data.get('access_token')
                print(f"   ✅ Login successful")
                print(f"   ✅ Token received: {token[:20]}...")
                
                # Test user profile
                headers = {'Authorization': f'Bearer {token}'}
                profile_response = requests.get('http://localhost:8002/api/auth/me', headers=headers)
                
                if profile_response.status_code == 200:
                    profile_data = profile_response.json()
                    portfolio_access = profile_data.get('portfolio_access', [])
                    
                    print(f"   ✅ Profile retrieved")
                    print(f"   ✅ Full Name: {profile_data.get('full_name')}")
                    print(f"   ✅ Email: {profile_data.get('email')}")
                    print(f"   ✅ Role: {profile_data.get('role')}")
                    print(f"   ✅ Portfolio Access: {portfolio_access}")
                    
                    # Verify access matches expected
                    if set(portfolio_access) == set(test_user['expected_access']):
                        print(f"   ✅ Access control working correctly")
                    else:
                        print(f"   ❌ Access mismatch!")
                        print(f"      Expected: {test_user['expected_access']}")
                        print(f"      Actual: {portfolio_access}")
                    
                    # Test frontend portfolio filtering
                    print(f"   📱 Frontend Portfolio Display:")
                    all_portfolios = [
                        {'id': 'dube-trade-port', 'name': 'Dube Trade Port'},
                        {'id': 'bertha-house', 'name': 'Bertha House'}
                    ]
                    
                    if profile_data.get('role') == 'admin':
                        visible_portfolios = all_portfolios
                    else:
                        visible_portfolios = [p for p in all_portfolios 
                                            if p['id'] in portfolio_access]
                    
                    for portfolio in visible_portfolios:
                        print(f"      - {portfolio['name']} ({portfolio['id']})")
                        
                else:
                    print(f"   ❌ Profile retrieval failed: {profile_response.status_code}")
                    
            else:
                print(f"   ❌ Login failed: {login_response.status_code}")
                print(f"   Error: {login_response.text}")
        
        print(f"\n" + "=" * 50)
        print("🎯 Expected Behavior Summary:")
        print("🔑 Admin User:")
        print("   - Can see: Dube Trade Port + Bertha House")
        print("   - Access: All portfolios")
        print()
        print("🏢 Dube Trade Port User:")
        print("   - Can see: Dube Trade Port only")
        print("   - Access: dube-trade-port only")
        print()
        print("🏘️ Bertha House User:")
        print("   - Can see: Bertha House only") 
        print("   - Access: bertha-house only")
        print()
        print("✅ Each user only sees their assigned portfolio!")
        
    except Exception as e:
        print(f"❌ Error testing user access: {str(e)}")
        raise
    finally:
        client.close()

if __name__ == "__main__":
    print("🚀 Starting User Access Control Test...")
    asyncio.run(test_user_access())
    print("\n🎉 User Access Control Test Complete!")
