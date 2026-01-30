from pymongo import MongoClient
import os

# Check the actual structure of invoice documents
try:
    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017')
    client = MongoClient(mongo_uri)
    db = client['esg_dashboard']
    collection = db['invoices']
    
    # Get all documents and analyze their structure
    invoices = list(collection.find())
    print(f'Total invoices: {len(invoices)}')
    
    # Collect all unique field names
    all_fields = set()
    amount_fields = []
    score_fields = []
    
    for invoice in invoices:
        for field in invoice.keys():
            all_fields.add(field)
            
            # Look for amount-related fields
            if any(keyword in field.lower() for keyword in ['amount', 'cost', 'price', 'total']):
                amount_fields.append((field, invoice.get(field)))
            
            # Look for score-related fields
            if any(keyword in field.lower() for keyword in ['score', 'esg', 'rating']):
                score_fields.append((field, invoice.get(field)))
    
    print(f'\nAll fields found: {sorted(all_fields)}')
    print(f'\nAmount-related fields: {amount_fields[:5]}')
    print(f'Score-related fields: {score_fields[:5]}')
    
    # Show sample documents with their actual data
    print(f'\nSample invoice data:')
    for i, invoice in enumerate(invoices[:3]):
        print(f'\nInvoice {i+1}:')
        for field in sorted(invoice.keys()):
            value = invoice[field]
            if isinstance(value, (int, float)) and value > 0:
                print(f'  {field}: {value}')
            elif isinstance(value, str) and len(value) < 50:
                print(f'  {field}: {value}')
    
    client.close()
    
except Exception as e:
    print(f'Error: {e}')
    import traceback
    traceback.print_exc()
