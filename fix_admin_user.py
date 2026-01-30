import asyncio
from app.core.database import get_db

async def fix_admin_user():
    db = await get_db()
    
    # Delete existing admin user
    await db.users.delete_one({"username": "admin"})
    print("Deleted existing admin user")
    
    # Create new admin user with a simple password hash
    # Using a known good hash for "admin"
    admin_user = {
        'username': 'admin',
        'email': 'admin@example.com',
        'full_name': 'Administrator',
        'hashed_password': '$2b$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', # password: "admin"
        'role': 'admin',
        'disabled': False,
        'created_at': '2025-01-01T00:00:00'
    }
    
    result = await db.users.insert_one(admin_user)
    print(f'Created new admin user with ID: {result.inserted_id}')
    print('Username: admin')
    print('Password: admin')

if __name__ == "__main__":
    asyncio.run(fix_admin_user())
