from pymongo import MongoClient
import os
from datetime import datetime

# Debug the energy insights data fetching
try:
    print('=== Debugging Energy Insights ===')
    
    # Connect to MongoDB
    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017')
    print(f'Mongo URI: {mongo_uri}')
    
    client = MongoClient(mongo_uri)
    db = client['esg_dashboard']
    collection = db['invoices']
    
    # Test database connection
    total_docs = collection.count_documents({})
    print(f'Total documents: {total_docs}')
    
    if total_docs > 0:
        # Get sample documents
        sample_docs = list(collection.find().limit(3))
        print(f'Sample documents: {len(sample_docs)}')
        
        for i, doc in enumerate(sample_docs):
            print(f'  Doc {i+1}:')
            print(f'    Created at: {doc.get("created_at", "Missing")}')
            print(f'    Total amount: {doc.get("total_amount", "Missing")}')
            print(f'    ESG score: {doc.get("esg_total_score", "Missing")}')
            print(f'    Keys: {list(doc.keys())[:5]}...')
    else:
        print('No documents found')
    
    # Test the data processing logic
    if total_docs > 0:
        invoices = list(collection.find().sort("created_at", -1).limit(100))
        print(f'Fetched {len(invoices)} invoices for processing')
        
        # Test the energy estimation logic
        historical_data = []
        for invoice in invoices[:3]:  # Just test first 3
            created_at = invoice.get('created_at', datetime.now())
            total_amount = invoice.get('total_amount', 0)
            esg_score = invoice.get('esg_total_score', 0)
            
            # Estimate energy from cost
            estimated_energy = total_amount * 2.5
            
            print(f'  Invoice: R{total_amount} -> {estimated_energy} kWh')
            
            historical_data.append({
                "date": created_at.isoformat(),
                "energy": estimated_energy,
                "month": created_at.strftime("%b"),
                "power_kw": estimated_energy / 720,
                "cost": total_amount,
                "esg_score": esg_score
            })
        
        print(f'Historical data created: {len(historical_data)} records')
    
    client.close()
    print('Database connection test completed successfully')
    
except Exception as e:
    print(f'Debug error: {e}')
    import traceback
    traceback.print_exc()
