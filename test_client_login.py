import requests

# Test client login with the newly created credentials
login_data = {
    'username': 'testclient',
    'password': 'password'
}

response = requests.post(
    'http://localhost:8002/api/auth/login',
    data=login_data,
    headers={'Content-Type': 'application/x-www-form-urlencoded'}
)

print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")
print(f"Headers: {response.headers}")

if response.status_code == 200:
    data = response.json()
    print(f"\nLogin successful!")
    print(f"Access Token: {data.get('access_token')}")
    print(f"Role: {data.get('role')}")
    print(f"User ID: {data.get('user_id')}")
else:
    print(f"Login failed with status: {response.status_code}")
