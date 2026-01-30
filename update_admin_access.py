import asyncio
import sys
import os
from motor.motor_asyncio import AsyncIOMotorClient

# Add the backend directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.config import settings

async def update_admin_access():
    """Update admin user portfolio access"""
    
    # Connect to MongoDB
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client[settings.MONGO_DB_NAME or "esg_dashboard"]
    
    try:
        print("🔧 Updating admin user portfolio access...")
        
        # Update admin user portfolio access
        result = await db.users.update_one(
            {"username": "admin"},
            {"$set": {"portfolio_access": ["dube-trade-port", "bertha-house"]}}
        )
        
        if result.modified_count > 0:
            print("✅ Admin user portfolio access updated successfully")
        else:
            print("ℹ️ Admin user not found or access already set")
        
        # Verify admin user
        admin_user = await db.users.find_one({"username": "admin"})
        if admin_user:
            print(f"\n👤 Admin User Details:")
            print(f"   Username: {admin_user.get('username')}")
            print(f"   Email: {admin_user.get('email')}")
            print(f"   Role: {admin_user.get('role')}")
            print(f"   Portfolio Access: {admin_user.get('portfolio_access')}")
        
        print(f"\n✅ Admin user access update complete!")
        
    except Exception as e:
        print(f"❌ Error updating admin access: {str(e)}")
        raise
    finally:
        client.close()

if __name__ == "__main__":
    print("🚀 Starting admin access update...")
    asyncio.run(update_admin_access())
    print("\n🎉 Admin access update complete!")
