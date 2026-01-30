import requests

# Test login endpoint
login_data = {
    'username': 'admin',
    'password': 'admin'
}

response = requests.post(
    'http://localhost:8002/api/auth/login',
    data=login_data,
    headers={'Content-Type': 'application/x-www-form-urlencoded'}
)

print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")
print(f"Headers: {response.headers}")
