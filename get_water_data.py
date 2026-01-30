import requests
from pymongo import MongoClient
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

try:
    print('=== Bertha House Water Data Analysis ===')
    
    # Connect to MongoDB
    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017')
    client = MongoClient(mongo_uri)
    db = client[os.getenv('MONGODB_DB', 'bertha_house')]
    collection = db[os.getenv('MONGODB_COLLECTION', 'invoices')]
    
    # Get all documents with water data
    water_docs = list(collection.find({'water_m3': {'$exists': True}}))
    print(f'Documents with water_m3 data: {len(water_docs)}')
    
    if water_docs:
        print('\nWater consumption data (m³):')
        total_water = 0
        water_values = []
        
        for i, doc in enumerate(water_docs):
            water_m3 = doc.get('water_m3', 0)
            invoice_date = doc.get('invoice_date', 'Unknown')
            vendor = doc.get('vendor_name', 'Unknown')
            invoice_num = doc.get('invoice_number', 'Unknown')
            
            water_values.append(water_m3)
            total_water += water_m3
            
            print(f'  {i+1}. {invoice_date} - {vendor} ({invoice_num}): {water_m3} m³')
        
        print(f'\nWater Statistics:')
        print(f'  Total water consumption: {total_water:.2f} m³')
        print(f'  Average per invoice: {total_water/len(water_docs):.2f} m³')
        print(f'  Min consumption: {min(water_values):.2f} m³')
        print(f'  Max consumption: {max(water_values):.2f} m³')
        
        # Calculate monthly estimates
        print(f'\nMonthly Estimates (based on available data):')
        avg_monthly = total_water / len(water_docs)
        print(f'  Average monthly water usage: {avg_monthly:.2f} m³')
        print(f'  Annual estimate: {avg_monthly * 12:.2f} m³')
        
        # Check for other water-related fields
        sample_doc = water_docs[0]
        other_water_fields = [k for k in sample_doc.keys() if 'water' in k.lower() and k != 'water_m3']
        if other_water_fields:
            print(f'\nOther water fields found: {other_water_fields}')
            for field in other_water_fields:
                print(f'  {field}: {sample_doc[field]}')
    
    # Check total documents vs water documents
    total_docs = collection.count_documents({})
    print(f'\nData Coverage:')
    print(f'  Total invoice documents: {total_docs}')
    print(f'  Documents with water data: {len(water_docs)}')
    print(f'  Coverage: {(len(water_docs)/total_docs)*100:.1f}%')
    
    client.close()
    
except Exception as e:
    print(f'Error: {e}')
