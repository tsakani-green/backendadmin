import asyncio
import sys
import os
from motor.motor_asyncio import AsyncIOMotorClient
import hashlib

# Add the backend directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.config import settings

def simple_hash(password: str) -> str:
    """Simple password hashing for development"""
    return hashlib.sha256(password.encode()).hexdigest()

async def fix_admin_password():
    """Fix admin user password"""
    
    # Connect to MongoDB
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client[settings.MONGO_DB_NAME or "esg_dashboard"]
    
    try:
        print("🔧 Fixing admin user password...")
        
        # Update admin user password
        admin_password_hash = simple_hash("admin123")
        
        result = await db.users.update_one(
            {"username": "admin"},
            {"$set": {"hashed_password": admin_password_hash}}
        )
        
        if result.modified_count > 0:
            print("✅ Admin user password updated successfully")
        else:
            print("ℹ️ Admin user not found or password already correct")
        
        # Verify admin user
        admin_user = await db.users.find_one({"username": "admin"})
        if admin_user:
            print(f"\n👤 Admin User Details:")
            print(f"   Username: {admin_user.get('username')}")
            print(f"   Email: {admin_user.get('email')}")
            print(f"   Role: {admin_user.get('role')}")
            print(f"   Portfolio Access: {admin_user.get('portfolio_access', 'N/A')}")
            print(f"   Password Hash: {admin_user.get('hashed_password', 'N/A')[:20]}...")
        
        print(f"\n✅ Admin user password fix complete!")
        
    except Exception as e:
        print(f"❌ Error fixing admin password: {str(e)}")
        raise
    finally:
        client.close()

if __name__ == "__main__":
    print("🚀 Starting admin password fix...")
    asyncio.run(fix_admin_password())
    print("\n🎉 Admin password fix complete!")
