from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
from enum import Enum

class InvoiceStatus(str, Enum):
    UPLOADED = "uploaded"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"

class ESGCategory(str, Enum):
    ENVIRONMENTAL = "environmental"
    SOCIAL = "social"
    GOVERNANCE = "governance"

class InvoiceItem(BaseModel):
    description: str
    quantity: float
    unit_price: float
    total: float
    esg_category: Optional[ESGCategory] = None
    esg_score: Optional[float] = None

class Invoice(BaseModel):
    id: Optional[str] = None
    invoice_number: str
    vendor_name: str
    invoice_date: datetime
    due_date: datetime
    total_amount: float
    currency: str = "USD"
    status: InvoiceStatus = InvoiceStatus.UPLOADED
    file_path: Optional[str] = None
    user_id: str
    items: List[InvoiceItem] = []
    esg_total_score: Optional[float] = None
    esg_insights: Optional[dict] = None
    ai_recommendations: Optional[List[str]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class InvoiceCreate(BaseModel):
    invoice_number: str
    vendor_name: str
    invoice_date: datetime
    due_date: datetime
    total_amount: float
    currency: str = "USD"

class InvoiceUpdate(BaseModel):
    status: Optional[InvoiceStatus] = None
    esg_total_score: Optional[float] = None
    esg_insights: Optional[dict] = None
    ai_recommendations: Optional[List[str]] = None

class ESGAnalysis(BaseModel):
    invoice_id: str
    environmental_score: float
    social_score: float
    governance_score: float
    overall_score: float
    insights: List[str]
    recommendations: List[str]
    analyzed_at: datetime

class BulkUploadResponse(BaseModel):
    total_files: int
    successful_uploads: int
    failed_uploads: int
    processed_invoices: List[str]
    errors: List[str]
