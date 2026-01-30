import requests

# Test signup endpoint
signup_data = {
    'username': 'testclient',
    'email': 'test@example.com',
    'password': 'password123',
    'full_name': 'Test Client',
    'company': 'Test Company'
}

response = requests.post(
    'http://localhost:8002/api/auth/signup',
    json=signup_data
)

print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")
print(f"Headers: {response.headers}")

if response.status_code == 200:
    data = response.json()
    print(f"\nSignup successful!")
    print(f"Access Token: {data.get('access_token')}")
    print(f"Role: {data.get('role')}")
    print(f"User ID: {data.get('user_id')}")
