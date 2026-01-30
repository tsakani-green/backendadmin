from pymongo import MongoClient
import os

# Check database connection and invoice data
try:
    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017')
    client = MongoClient(mongo_uri)
    db = client[os.getenv('MONGODB_DB', 'bertha_house')]
    collection = db[os.getenv('MONGODB_COLLECTION', 'invoices')]
    
    # Count documents
    total_docs = collection.count_documents({})
    print(f'Total invoice documents: {total_docs}')
    
    if total_docs > 0:
        # Get a sample document
        sample = collection.find_one()
        print(f'Sample document keys: {list(sample.keys())}')
        print(f'Sample total_amount: {sample.get("total_amount", "Not found")}')
        print(f'Sample created_at: {sample.get("created_at", "No date")}')
        
        # Get recent documents
        recent = list(collection.find().sort('created_at', -1).limit(3))
        print(f'Recent documents: {len(recent)}')
        for i, doc in enumerate(recent):
            amount = doc.get('total_amount', 0)
            date = doc.get('created_at', 'No date')
            print(f'  {i+1}. Amount: R{amount}, Date: {date}')
    else:
        print('No documents found in collection')
    
    client.close()
    
except Exception as e:
    print(f'Database error: {e}')
