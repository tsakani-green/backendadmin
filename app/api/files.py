from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import List, Dict, Any
import aiofiles
import os
import pandas as pd
from datetime import datetime, timedelta
from app.core.config import settings
from app.api.auth import get_current_user
from app.core.database import get_db
from bson import ObjectId
import json
import re
from dateutil import parser

router = APIRouter()

ALLOWED_EXTENSIONS = {'.csv', '.xlsx', '.xls', '.pdf', '.txt', '.json'}

def allowed_file(filename: str) -> bool:
    return any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS)

async def extract_invoice_data_from_file(file_path: str, content_type: str) -> List[Dict[str, Any]]:
    """Extract invoice data from uploaded file"""
    try:
        print(f"Extracting data from {file_path} with content type {content_type}")
        
        if file_path.endswith('.csv'):
            df = pd.read_csv(file_path)
            data = df.to_dict(orient='records')
            print(f"CSV extraction successful: {len(data)} records found")
            print(f"Sample record: {data[0] if data else 'No data'}")
            return data
        elif file_path.endswith(('.xlsx', '.xls')):
            df = pd.read_excel(file_path)
            data = df.to_dict(orient='records')
            print(f"Excel extraction successful: {len(data)} records found")
            return data
        elif file_path.endswith('.json'):
            async with aiofiles.open(file_path, 'r') as f:
                content = await f.read()
                json_data = json.loads(content)
                if isinstance(json_data, list):
                    data = json_data
                elif isinstance(json_data, dict) and 'data' in json_data:
                    data = json_data['data']
                else:
                    data = [json_data]
                print(f"JSON extraction successful: {len(data)} records found")
                return data
        elif file_path.endswith('.pdf'):
            # Basic PDF extraction (would need pdfplumber or similar in production)
            data = await extract_pdf_data(file_path)
            print(f"PDF extraction: {len(data)} records found")
            return data
        else:
            print(f"Unsupported file type: {file_path}")
            return []
    except Exception as e:
        print(f"Error extracting data from {file_path}: {str(e)}")
        import traceback
        traceback.print_exc()
        return []

async def extract_pdf_data(file_path: str) -> List[Dict[str, Any]]:
    """Extract data from PDF files (simplified implementation)"""
    # In production, use libraries like pdfplumber, PyPDF2, or OCR
    # For now, return mock data
    return [{
        "invoice_number": "PDF-INV-001",
        "vendor_name": "PDF Vendor",
        "invoice_date": datetime.now().strftime("%Y-%m-%d"),
        "total_amount": 1000.00,
        "description": "PDF extracted invoice"
    }]

def filter_last_12_months_data(data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter data to include only records from the last 12 months"""
    if not data:
        print("No data to filter")
        return []
    
    twelve_months_ago = datetime.now() - timedelta(days=365)
    print(f"Filtering data for dates after: {twelve_months_ago}")
    
    filtered_data = []
    
    for i, record in enumerate(data):
        print(f"Processing record {i+1}: {record}")
        invoice_date = None
        
        # Try to find date field (common names)
        date_fields = ['invoice_date', 'date', 'created_at', 'transaction_date', 'date_created', 'invoice_date']
        for field in date_fields:
            if field in record and record[field]:
                try:
                    invoice_date = parser.parse(str(record[field]))
                    print(f"Found date field '{field}': {invoice_date}")
                    break
                except Exception as e:
                    print(f"Failed to parse date from field '{field}': {record[field]} - {e}")
                    continue
        
        # If no date found, use current date
        if not invoice_date:
            invoice_date = datetime.now()
            print(f"No date found, using current date: {invoice_date}")
        
        # Check if within last 12 months
        if invoice_date >= twelve_months_ago:
            record['parsed_date'] = invoice_date
            filtered_data.append(record)
            print(f"Record {i+1} included (within 12 months)")
        else:
            print(f"Record {i+1} excluded (older than 12 months)")
    
    print(f"Filtered {len(data)} records to {len(filtered_data)} records within last 12 months")
    return filtered_data

def get_date_range(data: List[Dict[str, Any]]) -> Dict[str, str]:
    """Get the date range of the data"""
    if not data:
        return {}
    
    dates = [record.get('parsed_date', datetime.now()) for record in data]
    min_date = min(dates)
    max_date = max(dates)
    
    return {
        "start_date": min_date.strftime("%Y-%m-%d"),
        "end_date": max_date.strftime("%Y-%m-%d")
    }

async def store_invoice_records(invoice_data: List[Dict[str, Any]], user_id: str, db, file_id: str) -> int:
    """Store invoice records in esg_dashboard.invoices collection"""
    invoices_saved = 0
    
    for record in invoice_data:
        try:
            # Create invoice record with proper structure
            invoice_record = {
                "id": str(ObjectId()),
                "invoice_number": record.get('invoice_number', f"INV-{datetime.now().strftime('%Y%m%d%H%M%S')}-{invoices_saved + 1}"),
                "vendor_name": record.get('vendor_name', record.get('vendor', record.get('supplier', 'Unknown Vendor'))),
                "invoice_date": record.get('parsed_date', datetime.now()),
                "due_date": record.get('due_date', datetime.now() + timedelta(days=30)),
                "total_amount": float(record.get('total_amount', record.get('amount', record.get('total', 0)))),
                "currency": record.get('currency', 'USD'),
                "status": "processed",
                "file_path": None,  # Will be set if needed
                "user_id": user_id,
                "file_id": file_id,
                "items": extract_invoice_items(record),
                "esg_total_score": None,
                "esg_insights": None,
                "ai_recommendations": None,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "raw_data": record  # Store original data for reference
            }
            
            # Perform ESG analysis
            esg_analysis = perform_esg_analysis(invoice_record)
            invoice_record.update(esg_analysis)
            
            # Save to esg_dashboard.invoices collection
            await db.invoices.insert_one(invoice_record)
            invoices_saved += 1
            
        except Exception as e:
            print(f"Error storing invoice record: {str(e)}")
            continue
    
    return invoices_saved

def extract_invoice_items(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract invoice items from record"""
    items = []
    
    # Try to extract item information
    if 'items' in record and isinstance(record['items'], list):
        items = record['items']
    elif 'line_items' in record and isinstance(record['line_items'], list):
        items = record['line_items']
    else:
        # Create a single item from the record
        item = {
            "description": record.get('description', record.get('item_description', 'Unknown Item')),
            "quantity": float(record.get('quantity', 1)),
            "unit_price": float(record.get('unit_price', record.get('price', record.get('total_amount', 0)))),
            "total": float(record.get('total', record.get('total_amount', 0))),
            "esg_category": categorize_esg(record.get('description', '')),
            "esg_score": None
        }
        items = [item]
    
    return items

def categorize_esg(description: str) -> str:
    """Simple ESG categorization based on description"""
    desc_lower = description.lower()
    
    environmental_keywords = ['energy', 'recycling', 'waste', 'solar', 'green', 'environment', 'sustainability', 'renewable', 'carbon', 'eco']
    social_keywords = ['training', 'healthcare', 'education', 'community', 'welfare', 'social', 'employee', 'diversity', 'inclusion']
    governance_keywords = ['legal', 'compliance', 'audit', 'consulting', 'governance', 'regulatory', 'board', 'ethics']
    
    if any(keyword in desc_lower for keyword in environmental_keywords):
        return 'environmental'
    elif any(keyword in desc_lower for keyword in social_keywords):
        return 'social'
    elif any(keyword in desc_lower for keyword in governance_keywords):
        return 'governance'
    else:
        return 'environmental'  # Default category

def perform_esg_analysis(invoice_record: Dict[str, Any]) -> Dict[str, Any]:
    """Perform ESG analysis on invoice"""
    try:
        # Calculate ESG scores based on items and vendor
        items = invoice_record.get('items', [])
        vendor_name = invoice_record.get('vendor_name', '').lower()
        total_amount = invoice_record.get('total_amount', 0)
        
        # Initialize scores
        environmental_score = 5.0  # Base score
        social_score = 5.0
        governance_score = 5.0
        
        # Analyze items for ESG impact
        for item in items:
            category = item.get('esg_category', 'environmental')
            item_amount = item.get('total', 0)
            weight = item_amount / total_amount if total_amount > 0 else 0
            
            if category == 'environmental':
                environmental_score += weight * 2
            elif category == 'social':
                social_score += weight * 2
            elif category == 'governance':
                governance_score += weight * 2
        
        # Vendor-based scoring
        if any(keyword in vendor_name for keyword in ['green', 'eco', 'sustainable', 'renewable']):
            environmental_score += 1
        if any(keyword in vendor_name for keyword in ['fair trade', 'certified', 'organic']):
            social_score += 1
        
        # Cap scores at 10
        environmental_score = min(10, environmental_score)
        social_score = min(10, social_score)
        governance_score = min(10, governance_score)
        
        overall_score = (environmental_score + social_score + governance_score) / 3
        
        # Generate insights
        insights = []
        if environmental_score >= 7:
            insights.append("Strong environmental performance detected")
        if social_score >= 7:
            insights.append("Good social responsibility practices")
        if governance_score >= 7:
            insights.append("Solid governance compliance")
        
        # Generate recommendations
        recommendations = []
        if environmental_score < 6:
            recommendations.append("Consider more environmentally friendly suppliers")
        if social_score < 6:
            recommendations.append("Enhance social responsibility in procurement")
        if governance_score < 6:
            recommendations.append("Improve governance and compliance tracking")
        
        return {
            "esg_total_score": round(overall_score, 2),
            "esg_insights": {
                "environmental": round(environmental_score, 2),
                "social": round(social_score, 2),
                "governance": round(governance_score, 2),
                "insights": insights
            },
            "ai_recommendations": recommendations
        }
        
    except Exception as e:
        print(f"ESG analysis error: {str(e)}")
        return {
            "esg_total_score": 5.0,
            "esg_insights": {
                "environmental": 5.0,
                "social": 5.0,
                "governance": 5.0,
                "insights": ["Basic ESG analysis completed"]
            },
            "ai_recommendations": ["Consider enhancing ESG data quality"]
        }

@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    if current_user.role != "client":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only clients can upload files"
        )
    
    if not allowed_file(file.filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File type not allowed"
        )
    
    # Create upload directory if not exists
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    
    # Save file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{current_user.username}_{timestamp}_{file.filename}"
    file_path = os.path.join(settings.UPLOAD_DIR, filename)
    
    async with aiofiles.open(file_path, 'wb') as out_file:
        content = await file.read()
        await out_file.write(content)
    
    # Parse file based on type and extract invoice data
    file_info = {
        "user_id": ObjectId(current_user.id) if hasattr(current_user, 'id') else None,
        "username": current_user.username,
        "original_filename": file.filename,
        "stored_filename": filename,
        "file_path": file_path,
        "file_size": len(content),
        "content_type": file.content_type,
        "upload_date": datetime.utcnow(),
        "status": "processing",
        "processed_data": None,
        "invoice_data": None,
        "esg_analysis": None
    }
    
    # Save initial file info to database
    result = await db.files.insert_one(file_info)
    file_id = str(result.inserted_id)
    
    # Process file and extract invoice data
    try:
        extracted_data = await extract_invoice_data_from_file(file_path, file.content_type)
        
        # Filter for last 12 months and validate data
        filtered_data = filter_last_12_months_data(extracted_data)
        
        if filtered_data:
            file_info["processed_data"] = {
                "columns": list(filtered_data[0].keys()) if filtered_data else [],
                "row_count": len(filtered_data),
                "sample": filtered_data[:10],
                "total_records": len(filtered_data),
                "date_range": get_date_range(filtered_data)
            }
            file_info["invoice_data"] = filtered_data
            file_info["status"] = "processed"
            
            # Store individual invoice records in esg_dashboard.invoices
            invoices_saved = await store_invoice_records(filtered_data, current_user.id, db, file_id)
            file_info["invoices_saved"] = invoices_saved
            
        else:
            file_info["status"] = "no_data"
            file_info["message"] = "No invoice data found for the last 12 months"
            
    except Exception as e:
        file_info["status"] = "error"
        file_info["error"] = str(e)
    
    # Update file record
    await db.files.update_one(
        {"_id": result.inserted_id},
        {"$set": file_info}
    )
    
    return {
        "message": "File uploaded and processed successfully",
        "file_id": file_id,
        "filename": filename,
        "status": file_info["status"],
        "data_summary": file_info.get("processed_data"),
        "invoices_processed": len(file_info.get("invoice_data") or []),
        "invoices_saved": file_info.get("invoices_saved", 0)
    }

@router.get("/my-files")
async def get_my_files(
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    files = await db.files.find(
        {"user_id": ObjectId(current_user.id) if hasattr(current_user, 'id') else None}
    ).sort("upload_date", -1).to_list(100)
    
    for file in files:
        file["_id"] = str(file["_id"])
        if "user_id" in file:
            file["user_id"] = str(file["user_id"])
    
    return files

@router.get("/my-invoices")
async def get_my_invoices(
    current_user = Depends(get_current_user),
    db = Depends(get_db),
    limit: int = 50,
    offset: int = 0
):
    """Get invoices for the current user from the last 12 months"""
    twelve_months_ago = datetime.utcnow() - timedelta(days=365)
    
    cursor = db.invoices.find({
        "user_id": current_user.id,
        "created_at": {"$gte": twelve_months_ago}
    }).sort("created_at", -1).skip(offset).limit(limit)
    
    invoices = []
    async for document in cursor:
        document['_id'] = str(document['_id'])
        invoices.append(document)
    
    return {"invoices": invoices, "total": len(invoices)}

@router.get("/esg-summary/{user_id}")
async def get_esg_summary(user_id: str, db = Depends(get_db)):
    """Get ESG summary for user's invoices"""
    try:
        twelve_months_ago = datetime.utcnow() - timedelta(days=365)
        
        # Aggregate ESG scores
        pipeline = [
            {
                "$match": {
                    "user_id": user_id,
                    "created_at": {"$gte": twelve_months_ago},
                    "esg_total_score": {"$ne": None}
                }
            },
            {
                "$group": {
                    "_id": None,
                    "avg_esg_score": {"$avg": "$esg_total_score"},
                    "avg_environmental": {"$avg": "$esg_insights.environmental"},
                    "avg_social": {"$avg": "$esg_insights.social"},
                    "avg_governance": {"$avg": "$esg_insights.governance"},
                    "total_invoices": {"$sum": 1},
                    "total_amount": {"$sum": "$total_amount"}
                }
            }
        ]
        
        result = await db.invoices.aggregate(pipeline).to_list(length=1)
        
        if result:
            summary = result[0]
            return {
                "average_esg_score": round(summary["avg_esg_score"], 2),
                "average_environmental": round(summary["avg_environmental"], 2),
                "average_social": round(summary["avg_social"], 2),
                "average_governance": round(summary["avg_governance"], 2),
                "total_invoices": summary["total_invoices"],
                "total_amount": summary["total_amount"],
                "period": "12 months"
            }
        else:
            return {
                "average_esg_score": 0,
                "average_environmental": 0,
                "average_social": 0,
                "average_governance": 0,
                "total_invoices": 0,
                "total_amount": 0,
                "period": "12 months"
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get ESG summary: {str(e)}")

@router.post("/bulk-upload")
async def bulk_upload_files(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...),
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Handle bulk upload of multiple files"""
    if current_user.role != "client":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only clients can upload files"
        )
    
    total_files = len(files)
    successful_uploads = 0
    failed_uploads = 0
    total_invoices_saved = 0
    errors = []
    
    for file in files:
        try:
            if not allowed_file(file.filename):
                failed_uploads += 1
                errors.append(f"File {file.filename}: File type not allowed")
                continue
            
            # Process each file using the upload logic
            result = await upload_file(file, current_user, db)
            
            if result["status"] in ["processed", "completed"]:
                successful_uploads += 1
                total_invoices_saved += result.get("invoices_saved", 0)
            else:
                failed_uploads += 1
                errors.append(f"File {file.filename}: {result.get('error', 'Processing failed')}")
                
        except Exception as e:
            failed_uploads += 1
            errors.append(f"File {file.filename}: {str(e)}")
    
    return {
        "message": "Bulk upload completed",
        "total_files": total_files,
        "successful_uploads": successful_uploads,
        "failed_uploads": failed_uploads,
        "total_invoices_saved": total_invoices_saved,
        "errors": errors
    }
