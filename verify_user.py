import asyncio
from app.core.database import get_db

async def verify_user():
    db = await get_db()
    users = await db.users.find().to_list(length=10)
    print(f'Found {len(users)} users in database:')
    for user in users:
        print(f'  - Username: {user.get("username")}, Email: {user.get("email")}')
        print(f'    Hashed password: {user.get("hashed_password")}')
        print(f'    ID: {user.get("_id")}')
        print()

if __name__ == "__main__":
    asyncio.run(verify_user())
