#!/usr/bin/env python3
"""
MongoDB Migration Script
Migrates local MongoDB data to MongoDB Atlas
"""

import asyncio
import sys
from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure, OperationFailure

# Database configurations
LOCAL_MONGO_URL = "mongodb://localhost:27017/esg_dashboard"
ATLAS_MONGO_URL = "mongodb+srv://esgAdmin:Tsakani3408@africaesg-cluster.36oy0su.mongodb.net/esg_dashboard?retryWrites=true&w=majority"

class MongoMigrator:
    def __init__(self):
        self.local_client = None
        self.atlas_client = None
        self.local_db = None
        self.atlas_db = None

    async def connect_databases(self):
        """Connect to both local and Atlas databases"""
        try:
            print("🔗 Connecting to local MongoDB...")
            self.local_client = AsyncIOMotorClient(LOCAL_MONGO_URL)
            self.local_db = self.local_client.esg_dashboard
            await self.local_client.admin.command('ping')
            print("✅ Local MongoDB connected successfully")

            print("🔗 Connecting to MongoDB Atlas...")
            self.atlas_client = AsyncIOMotorClient(ATLAS_MONGO_URL)
            self.atlas_db = self.atlas_client.esg_dashboard
            await self.atlas_client.admin.command('ping')
            print("✅ MongoDB Atlas connected successfully")

        except ConnectionFailure as e:
            print(f"❌ Connection failed: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return False
        
        return True

    async def get_collection_names(self, db):
        """Get all collection names from database"""
        collections = await db.list_collection_names()
        return collections

    async def migrate_collection(self, collection_name):
        """Migrate a single collection from local to Atlas"""
        try:
            print(f"📦 Migrating collection: {collection_name}")
            
            # Get local collection
            local_collection = self.local_db[collection_name]
            
            # Get all documents from local collection
            documents = []
            async for doc in local_collection.find({}):
                # Convert ObjectId to string for JSON compatibility
                if '_id' in doc:
                    doc['_id'] = str(doc['_id'])
                documents.append(doc)
            
            if not documents:
                print(f"   📭 No documents found in {collection_name}")
                return 0

            # Get Atlas collection
            atlas_collection = self.atlas_db[collection_name]
            
            # Clear existing data in Atlas collection
            await atlas_collection.delete_many({})
            
            # Insert documents into Atlas
            if documents:
                result = await atlas_collection.insert_many(documents)
                count = len(result.inserted_ids)
                print(f"   ✅ Migrated {count} documents from {collection_name}")
                return count
            else:
                print(f"   📭 No documents to migrate in {collection_name}")
                return 0

        except OperationFailure as e:
            print(f"   ❌ Operation failed: {e}")
            return 0
        except Exception as e:
            print(f"   ❌ Error migrating {collection_name}: {e}")
            return 0

    async def verify_migration(self):
        """Verify migration by comparing document counts"""
        try:
            print("\n🔍 Verifying migration...")
            
            local_collections = await self.get_collection_names(self.local_db)
            atlas_collections = await self.get_collection_names(self.atlas_db)
            
            print(f"\n📊 Migration Summary:")
            print(f"Local collections: {len(local_collections)}")
            print(f"Atlas collections: {len(atlas_collections)}")
            
            for collection_name in local_collections:
                local_count = await self.local_db[collection_name].count_documents({})
                atlas_count = await self.atlas_db[collection_name].count_documents({})
                
                status = "✅" if local_count == atlas_count else "❌"
                print(f"   {status} {collection_name}: {local_count} → {atlas_count}")
            
            return True

        except Exception as e:
            print(f"❌ Verification failed: {e}")
            return False

    async def close_connections(self):
        """Close database connections"""
        if self.local_client:
            self.local_client.close()
        if self.atlas_client:
            self.atlas_client.close()

async def main():
    """Main migration function"""
    print("🚀 Starting MongoDB Migration to Atlas")
    print("=" * 50)
    
    migrator = MongoMigrator()
    
    try:
        # Connect to databases
        if not await migrator.connect_databases():
            print("❌ Failed to connect to databases. Exiting...")
            return
        
        # Get collection names
        collections = await migrator.get_collection_names(migrator.local_db)
        print(f"\n📋 Found {len(collections)} collections to migrate:")
        for collection in collections:
            print(f"   - {collection}")
        
        # Ask for confirmation
        print(f"\n⚠️  This will migrate all data to MongoDB Atlas")
        print(f"⚠️  Make sure you've updated the ATLAS_MONGO_URL in this script")
        confirm = input(f"\n❓ Do you want to continue? (y/N): ")
        
        if confirm.lower() != 'y':
            print("❌ Migration cancelled by user")
            return
        
        # Migrate collections
        print(f"\n🔄 Starting migration...")
        total_migrated = 0
        
        for collection_name in collections:
            count = await migrator.migrate_collection(collection_name)
            total_migrated += count
        
        print(f"\n🎉 Migration completed!")
        print(f"📊 Total documents migrated: {total_migrated}")
        
        # Verify migration
        await migrator.verify_migration()
        
        print(f"\n✅ Migration to MongoDB Atlas completed successfully!")
        print(f"🔗 Don't forget to update your .env file with the Atlas connection string!")
        
    except KeyboardInterrupt:
        print(f"\n❌ Migration cancelled by user")
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
    finally:
        await migrator.close_connections()

if __name__ == "__main__":
    # Check if ATLAS_MONGO_URL is updated
    if "YOUR_PASSWORD_HERE" in ATLAS_MONGO_URL:
        print("❌ Please update ATLAS_MONGO_URL in the script with your actual Atlas connection string")
        print("❌ Get your connection string from MongoDB Atlas dashboard")
        sys.exit(1)
    
    asyncio.run(main())
