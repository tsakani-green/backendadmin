import asyncio
import aiohttp
import json

async def test_forgot_password_api():
    print("Testing forgot password API endpoint...")
    
    # Test data
    test_email = "admin@example.com"
    
    # API endpoint
    url = "http://localhost:8002/api/auth/forgot-password"
    
    async with aiohttp.ClientSession() as session:
        try:
            # Test the forgot password endpoint
            payload = {"email": test_email}
            
            async with session.post(url, json=payload) as response:
                print(f"Status Code: {response.status}")
                
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ API Response: {data}")
                    print("✅ Forgot password API endpoint working correctly!")
                else:
                    error_text = await response.text()
                    print(f"❌ API Error: {error_text}")
                    
        except aiohttp.ClientError as e:
            print(f"❌ Connection Error: {e}")
            print("Make sure the backend server is running on port 8002")

if __name__ == "__main__":
    asyncio.run(test_forgot_password_api())
