from fastapi import APIRouter, Depends, HTTPException
from pymongo import MongoClient
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any
from bson import ObjectId

router = APIRouter(prefix="/api/invoices", tags=["recent-activities"])

# MongoDB connection
def get_db():
    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017')
    client = MongoClient(mongo_uri)
    db = client[os.getenv('MONGODB_DB', 'bertha_house')]
    return db

@router.get("/recent-activities")
async def get_recent_activities(limit: int = 10, db=Depends(get_db)):
    """
    Get recent activities from invoice documents
    """
    try:
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
        raise HTTPException(status_code=500, detail=f"Error fetching recent activities: {str(e)}")

@router.get("/activity-summary")
async def get_activity_summary(db=Depends(get_db)):
    """
    Get summary of recent activities
    """
    try:
        collection = db[os.getenv('MONGODB_COLLECTION', 'invoices')]
        
        # Get counts for different activity types
        total_docs = collection.count_documents({})
        recent_24h = collection.count_documents({
            "created_at": {"$gte": datetime.now() - timedelta(hours=24)}
        })
        recent_week = collection.count_documents({
            "created_at": {"$gte": datetime.now() - timedelta(days=7)}
        })
        
        # Get ESG score distribution
        high_esg = collection.count_documents({"esg_total_score": {"$gte": 7}})
        medium_esg = collection.count_documents({"esg_total_score": {"$gte": 4, "$lt": 7}})
        low_esg = collection.count_documents({"esg_total_score": {"$lt": 4}})
        
        return {
            "summary": {
                "total_documents": total_docs,
                "last_24_hours": recent_24h,
                "last_week": recent_week,
                "esg_distribution": {
                    "high": high_esg,
                    "medium": medium_esg,
                    "low": low_esg
                }
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching activity summary: {str(e)}")
