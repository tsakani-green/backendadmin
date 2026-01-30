import asyncio
from app.core.database import get_db
from app.api.auth import get_password_hash

async def check_users():
    db = await get_db()
    users = await db.users.find().to_list(length=10)
    print(f'Found {len(users)} users in database:')
    for user in users:
        print(f'  - Username: {user.get("username")}, Role: {user.get("role")}')
    
    if not users:
        print('No users found. Creating default admin user...')
        try:
            hashed_password = get_password_hash('admin123')
            admin_user = {
                'username': 'admin',
                'email': 'admin@example.com',
                'full_name': 'Administrator',
                'hashed_password': hashed_password,
                'role': 'admin',
                'disabled': False,
                'created_at': '2025-01-01T00:00:00'
            }
            result = await db.users.insert_one(admin_user)
            print(f'Created admin user with ID: {result.inserted_id}')
        except Exception as e:
            print(f'Error creating admin user: {e}')
            print('Creating admin user with plain password for testing...')
            admin_user = {
                'username': 'admin',
                'email': 'admin@example.com',
                'full_name': 'Administrator',
                'hashed_password': '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/RK.s5uO.G', # admin123
                'role': 'admin',
                'disabled': False,
                'created_at': '2025-01-01T00:00:00'
            }
            result = await db.users.insert_one(admin_user)
            print(f'Created admin user with ID: {result.inserted_id}')

if __name__ == "__main__":
    asyncio.run(check_users())
