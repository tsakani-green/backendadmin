import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings

async def create_users_collection():
    # Connect to MongoDB
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    database = client.esg_dashboard
    
    try:
        # Create users collection (MongoDB creates it automatically when first document is inserted)
        # Let's create an index on username and email for faster queries
        await database.users.create_index("username", unique=True)
        await database.users.create_index("email", unique=True)
        
        print("✅ Users collection created with indexes")
        print("📍 Collection: esg_dashboard.users")
        print("🔑 Indexes created on: username, email")
        
        # Optionally create a default admin user
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        hashed_password = pwd_context.hash("admin123")
        admin_user = {
            "username": "admin",
            "email": "admin@esg.com",
            "full_name": "ESG Admin",
            "hashed_password": hashed_password,
            "role": "admin",
            "company": "ESG Dashboard",
            "disabled": False,
            "created_at": asyncio.get_event_loop().time()
        }
        
        try:
            await database.users.insert_one(admin_user)
            print("👤 Default admin user created:")
            print("   Username: admin")
            print("   Password: admin123")
            print("   Email: admin@esg.com")
        except Exception as e:
            if "duplicate key" in str(e):
                print("ℹ️ Admin user already exists")
            else:
                print(f"⚠️ Error creating admin user: {e}")
                
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    asyncio.run(create_users_collection())
