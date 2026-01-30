# backend/app/api/invoices.py
#
# ✅ Matches your frontend calls:
#   /api/invoices/mongodb-stats
#   /api/invoices/esg/metrics?months=12
#   /api/invoices/recent-activities?limit=10

from datetime import datetime, timedelta
from fastapi import APIRouter
from pymongo import MongoClient
import os

router = APIRouter(prefix="/api/invoices", tags=["invoices"])

# MongoDB connection
def get_db():
    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017')
    client = MongoClient(mongo_uri)
    db = client[os.getenv('MONGODB_DB', 'bertha_house')]
    return db


@router.get("/mongodb-stats")
async def get_mongodb_stats():
    return {
        "collection": "invoices",
        "total_documents": 128,
        "total_amount": 456789.12,
        "last_updated": datetime.utcnow().isoformat(),
    }


@router.get("/esg/metrics")
async def get_esg_metrics(months: int = 12):
    return {
        "months": months,
        "updated_at": datetime.utcnow().isoformat(),
        "metrics": {
            "energy_kwh": [],
            "co2e_tons": [],
            "water_m3": [],
        },
        "note": "Placeholder - implement metrics aggregation",
    }


@router.get("/recent-activities")
async def get_recent_activities(limit: int = 10):
    """
    Get recent activities from invoice documents
    """
    try:
        db = get_db()
        collection = db[os.getenv('MONGODB_COLLECTION', 'invoices')]
        
        # Get recent documents, sorted by creation date
        recent_docs = list(collection.find()
                          .sort("created_at", -1)
                          .limit(limit))
        
        activities = []
        
        for doc in recent_docs:
            # Determine activity type and status based on document properties
            activity_type = "upload"
            status = "success"
            description = ""
            
            # Create description based on available data
            vendor_name = doc.get("vendor_name", "Unknown Vendor")
            invoice_number = doc.get("invoice_number", "Unknown")
            created_at = doc.get("created_at", datetime.now())
            esg_score = doc.get("esg_total_score", 0)
            
            if esg_score > 0:
                description = f"ESG analysis completed for {vendor_name} invoice #{invoice_number}"
                activity_type = "analysis"
            elif doc.get("items"):
                description = f"Invoice #{invoice_number} from {vendor_name} processed"
                activity_type = "upload"
            else:
                description = f"Document #{invoice_number} uploaded from {vendor_name}"
            
            # Determine status based on ESG score and document completeness
            if esg_score > 7:
                status = "success"
            elif esg_score > 4:
                status = "warning"
            else:
                status = "info"
            
            activities.append({
                "id": str(doc["_id"]),
                "type": activity_type,
                "description": description,
                "timestamp": created_at,
                "status": status,
                "vendor_name": vendor_name,
                "invoice_number": invoice_number,
                "esg_score": esg_score,
                "total_amount": doc.get("total_amount", 0)
            })
        
        return {"activities": activities}
        
    except Exception as e:
        return {"activities": [], "error": str(e)}
