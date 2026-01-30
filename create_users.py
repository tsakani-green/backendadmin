import asyncio
import sys
import os
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime
import hashlib

# Add the backend directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.config import settings

def simple_hash(password: str) -> str:
    """Simple password hashing for development"""
    return hashlib.sha256(password.encode()).hexdigest()

async def create_users():
    """Create users for Dube Trade Port and Bertha House"""
    
    # Connect to MongoDB
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client[settings.MONGO_DB_NAME or "esg_dashboard"]
    
    try:
        print("Creating users for Dube Trade Port and Bertha House...")
        
        # Create admin user first
        admin_user = {
            "username": "admin",
            "email": "admin@africaesg.ai",
            "full_name": "System Administrator",
            "hashed_password": simple_hash("admin123"),
            "role": "admin",
            "company": "AfricaESG.AI",
            "portfolio_access": ["dube-trade-port", "bertha-house"],  # Admin can access all
            "disabled": False,
            "created_at": datetime.utcnow()
        }
        
        # Check if admin exists
        existing_admin = await db.users.find_one({"username": "admin"})
        if not existing_admin:
            await db.users.insert_one(admin_user)
            print("✅ Admin user created successfully")
        else:
            print("ℹ️ Admin user already exists")
        
        # Create Dube Trade Port user
        dube_user = {
            "username": "dube-user",
            "email": "dube@dubetradeport.co.za",
            "full_name": "Dube Trade Port Manager",
            "hashed_password": simple_hash("dube123"),
            "role": "client",
            "company": "Dube Trade Port",
            "portfolio_access": ["dube-trade-port"],  # Only access Dube Trade Port
            "disabled": False,
            "created_at": datetime.utcnow()
        }
        
        # Check if dube user exists
        existing_dube = await db.users.find_one({"username": "dube-user"})
        if not existing_dube:
            await db.users.insert_one(dube_user)
            print("✅ Dube Trade Port user created successfully")
        else:
            print("ℹ️ Dube Trade Port user already exists")
        
        # Create Bertha House user
        bertha_user = {
            "username": "bertha-user",
            "email": "bertha@berthahouse.co.za",
            "full_name": "Bertha House Manager",
            "hashed_password": simple_hash("bertha123"),
            "role": "client",
            "company": "Bertha House",
            "portfolio_access": ["bertha-house"],  # Only access Bertha House
            "disabled": False,
            "created_at": datetime.utcnow()
        }
        
        # Check if bertha user exists
        existing_bertha = await db.users.find_one({"username": "bertha-user"})
        if not existing_bertha:
            await db.users.insert_one(bertha_user)
            print("✅ Bertha House user created successfully")
        else:
            print("ℹ️ Bertha House user already exists")
        
        print("\n📋 User Credentials:")
        print("=" * 50)
        print("🔑 Admin User:")
        print("   Username: admin")
        print("   Password: admin123")
        print("   Access: All portfolios")
        print("   Email: admin@africaesg.ai")
        print()
        print("🏢 Dube Trade Port User:")
        print("   Username: dube-user")
        print("   Password: dube123")
        print("   Access: Dube Trade Port only")
        print("   Email: dube@dubetradeport.co.za")
        print()
        print("🏘️ Bertha House User:")
        print("   Username: bertha-user")
        print("   Password: bertha123")
        print("   Access: Bertha House only")
        print("   Email: bertha@berthahouse.co.za")
        print("=" * 50)
        
        print("\n✅ User creation completed successfully!")
        
    except Exception as e:
        print(f"❌ Error creating users: {str(e)}")
        raise
    finally:
        client.close()

async def verify_users():
    """Verify users were created correctly"""
    
    # Connect to MongoDB
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client[settings.MONGO_DB_NAME or "esg_dashboard"]
    
    try:
        print("\n🔍 Verifying created users...")
        
        users = []
        async for user in db.users.find():
            user_dict = dict(user)
            user_dict['id'] = str(user['_id'])
            # Remove sensitive data for display
            user_dict.pop('hashed_password', None)
            users.append(user_dict)
        
        for user in users:
            print(f"\n👤 {user['full_name']}:")
            print(f"   Username: {user['username']}")
            print(f"   Email: {user['email']}")
            print(f"   Role: {user['role']}")
            print(f"   Company: {user.get('company', 'N/A')}")
            print(f"   Portfolio Access: {user.get('portfolio_access', 'N/A')}")
            print(f"   Disabled: {user['disabled']}")
            print(f"   Created: {user['created_at']}")
        
        print(f"\n✅ Total users found: {len(users)}")
        
    except Exception as e:
        print(f"❌ Error verifying users: {str(e)}")
        raise
    finally:
        client.close()

if __name__ == "__main__":
    print("🚀 Starting user creation process...")
    
    # Create users
    asyncio.run(create_users())
    
    # Verify users
    asyncio.run(verify_users())
    
    print("\n🎉 User management setup complete!")
