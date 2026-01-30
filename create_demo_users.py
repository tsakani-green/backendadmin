# Create demo users for testing

import asyncio
import hashlib
from motor.motor_asyncio import AsyncIOMotorClient

async def create_demo_users():
    # Connect to MongoDB
    client = AsyncIOMotorClient("mongodb://localhost:27017")
    db = client.esg_dashboard
    
    # Demo users with their passwords
    demo_users = [
        {
            "username": "admin",
            "email": "admin@africaesg.ai",
            "full_name": "System Administrator",
            "password": "admin123",
            "role": "admin",
            "company": "AfricaESG.AI",
            "portfolio_access": ["dube-trade-port", "bertha-house"],
            "status": "active"
        },
        {
            "username": "dube-user", 
            "email": "dube@dubetradeport.com",
            "full_name": "Dube Trade Port Manager",
            "password": "dube123",
            "role": "client",
            "company": "Dube Trade Port",
            "portfolio_access": ["dube-trade-port"],
            "status": "active"
        },
        {
            "username": "bertha-user",
            "email": "bertha@berthahouse.com", 
            "full_name": "Bertha House Manager",
            "password": "bertha123",
            "role": "client",
            "company": "Bertha House",
            "portfolio_access": ["bertha-house"],
            "status": "active"
        }
    ]
    
    for user_data in demo_users:
        # Check if user already exists
        existing_user = await db.users.find_one({
            "$or": [
                {"username": user_data["username"]},
                {"email": user_data["email"]}
            ]
        })
        
        if existing_user:
            print(f"User {user_data['username']} already exists, skipping...")
            continue
        
        # Hash password using same method as auth.py
        hashed_password = hashlib.sha256(user_data["password"].encode()).hexdigest()
        
        # Create user document
        user_doc = {
            "username": user_data["username"],
            "email": user_data["email"],
            "full_name": user_data["full_name"],
            "hashed_password": hashed_password,
            "role": user_data["role"],
            "company": user_data["company"],
            "portfolio_access": user_data["portfolio_access"],
            "disabled": False,
            "status": user_data["status"],
            "created_at": "2026-01-29T00:00:00Z"
        }
        
        # Insert user
        result = await db.users.insert_one(user_doc)
        print(f"Created user: {user_data['username']} (ID: {result.inserted_id})")
    
    print("\nDemo users created successfully!")
    print("You can now login with:")
    print("- Admin: username='admin', password='admin123'")
    print("- Dube User: username='dube-user', password='dube123'") 
    print("- Bertha User: username='bertha-user', password='bertha123'")
    
    client.close()

if __name__ == "__main__":
    asyncio.run(create_demo_users())
