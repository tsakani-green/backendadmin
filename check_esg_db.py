from pymongo import MongoClient
import os

# Check the esg_dashboard database
try:
    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017')
    client = MongoClient(mongo_uri)
    
    # Check esg_dashboard database
    db = client['esg_dashboard']
    collections = db.list_collection_names()
    print(f'Collections in esg_dashboard: {collections}')
    
    # Check each collection for documents
    for collection_name in collections:
        collection = db[collection_name]
        count = collection.count_documents({})
        print(f'  {collection_name}: {count} documents')
        
        if count > 0 and count < 5:  # Show sample if small number
            sample = collection.find_one()
            print(f'    Sample keys: {list(sample.keys())}')
            amount = sample.get('total_amount', 'N/A')
            print(f'    Sample total_amount: {amount}')
    
    client.close()
    
except Exception as e:
    print(f'Database error: {e}')
