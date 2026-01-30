import requests
from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

# Connect directly to MongoDB to check invoice fields
try:
    print('=== Checking MongoDB Invoice Fields ===')
    
    # Connect to MongoDB
    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017')
    client = MongoClient(mongo_uri)
    db = client[os.getenv('MONGODB_DB', 'bertha_house')]
    collection = db[os.getenv('MONGODB_COLLECTION', 'invoices')]
    
    # Get total count
    total_docs = collection.count_documents({})
    print(f'Total invoice documents: {total_docs}')
    
    if total_docs > 0:
        # Get a sample document to see the structure
        sample_doc = collection.find_one()
        print(f'\nSample document keys: {list(sample_doc.keys())}')
        
        # Look for water-related fields
        water_fields = []
        for key in sample_doc.keys():
            if 'water' in key.lower():
                water_fields.append(key)
        
        if water_fields:
            print(f'Water-related fields found: {water_fields}')
            for field in water_fields:
                print(f'  {field}: {sample_doc[field]}')
        else:
            print('No water-related fields found in sample document')
        
        # Check for utility-related fields that might contain water data
        utility_fields = []
        for key in sample_doc.keys():
            if any(term in key.lower() for term in ['utility', 'consumption', 'usage', 'meter']):
                utility_fields.append(key)
        
        if utility_fields:
            print(f'Utility-related fields: {utility_fields}')
            for field in utility_fields[:5]:  # Show first 5
                value = sample_doc[field]
                if isinstance(value, dict):
                    print(f'  {field}: {list(value.keys())}')
                else:
                    print(f'  {field}: {value}')
        
        # Check for any numeric fields that might be water consumption
        numeric_fields = []
        for key, value in sample_doc.items():
            if isinstance(value, (int, float)) and value > 0:
                numeric_fields.append((key, value))
        
        print(f'\nNumeric fields (potential water data):')
        for field, value in numeric_fields[:10]:
            print(f'  {field}: {value}')
        
        # Check a few more documents for water data
        print(f'\nChecking {min(5, total_docs)} documents for water data...')
        water_found = False
        for i, doc in enumerate(collection.find().limit(5)):
            doc_water_fields = [k for k in doc.keys() if 'water' in k.lower()]
            if doc_water_fields:
                print(f'  Document {i+1}: {doc_water_fields}')
                water_found = True
        
        if not water_found:
            print('  No water data found in any checked documents')
    
    client.close()
    
except Exception as e:
    print(f'Error checking MongoDB: {e}')
