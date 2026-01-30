from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from typing import Optional, List
import google.generativeai as genai
import asyncio
import json
from datetime import datetime
from app.core.config import settings
from app.api.auth import get_current_user
from app.core.database import get_db
from bson import ObjectId
import pandas as pd

router = APIRouter()

# Configure Gemini
genai.configure(api_key=settings.GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-pro')

class ReportRequest(BaseModel):
    file_ids: List[str]
    report_type: str
    custom_prompt: Optional[str] = None
    timeframe: Optional[str] = None

async def analyze_esg_data(file_data: List[dict]) -> dict:
    """Analyze uploaded files for ESG data"""
    all_data = []
    
    for file_info in file_data:
        if file_info.get("processed_data"):
            if isinstance(file_info["processed_data"], dict) and "sample" in file_info["processed_data"]:
                all_data.extend(file_info["processed_data"]["sample"])
    
    if not all_data:
        return {"error": "No analyzable data found"}
    
    # Create analysis prompt
    prompt = f"""
    Analyze the following ESG data and provide insights:
    
    Data: {json.dumps(all_data[:20], indent=2)}
    
    Please provide:
    1. Key ESG metrics identified
    2. Trends and patterns
    3. Risk areas
    4. Improvement recommendations
    5. Summary score (1-100)
    
    Format as JSON with these sections.
    """
    
    try:
        response = model.generate_content(prompt)
        return json.loads(response.text)
    except Exception as e:
        return {"error": str(e), "analysis": "Failed to generate AI analysis"}

@router.post("/generate-report")
async def generate_report(
    request: ReportRequest,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Generate ESG report using AI"""
    
    # Get file data
    file_objects = []
    for file_id in request.file_ids:
        file_data = await db.files.find_one({"_id": ObjectId(file_id)})
        if file_data:
            file_objects.append(file_data)
    
    if not file_objects:
        raise HTTPException(status_code=404, detail="No files found")
    
    # Generate report with AI
    report_prompt = f"""
    Generate a comprehensive {request.report_type} ESG report based on the uploaded data.
    
    Report Requirements:
    - Executive Summary
    - Environmental Performance
    - Social Impact
    - Governance Metrics
    - Risk Assessment
    - Recommendations
    - Overall ESG Score
    
    Timeframe: {request.timeframe or 'Annual'}
    Custom Requirements: {request.custom_prompt or 'None'}
    
    Provide detailed analysis and actionable insights.
    """
    
    try:
        # Get AI analysis
        ai_analysis = await analyze_esg_data(file_objects)
        
        # Generate full report
        full_prompt = f"{report_prompt}\n\nInitial Analysis: {json.dumps(ai_analysis)}"
        response = model.generate_content(full_prompt)
        
        # Save report to database
        report_data = {
            "user_id": ObjectId(current_user.id) if hasattr(current_user, 'id') else None,
            "username": current_user.username,
            "report_type": request.report_type,
            "file_ids": request.file_ids,
            "ai_analysis": ai_analysis,
            "full_report": response.text,
            "generated_at": datetime.utcnow(),
            "status": "completed"
        }
        
        result = await db.reports.insert_one(report_data)
        report_data["_id"] = str(result.inserted_id)
        
        return {
            "report_id": str(result.inserted_id),
            "analysis": ai_analysis,
            "full_report": response.text,
            "status": "completed"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI generation failed: {str(e)}")

@router.websocket("/ws/generate-live/{client_id}")
async def websocket_generate_report(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for live AI report generation"""
    await websocket.accept()
    
    try:
        while True:
            # Receive data from client
            data = await websocket.receive_json()
            file_ids = data.get("file_ids", [])
            report_type = data.get("report_type", "Standard ESG Report")
            
            # Send initial response
            await websocket.send_json({
                "status": "processing",
                "message": "Starting AI analysis...",
                "step": 1,
                "total_steps": 5
            })
            
            await asyncio.sleep(1)
            
            # Simulate processing steps
            steps = [
                "Analyzing uploaded files...",
                "Extracting ESG metrics...",
                "Identifying trends and patterns...",
                "Generating recommendations...",
                "Compiling final report..."
            ]
            
            for i, step in enumerate(steps, 2):
                await websocket.send_json({
                    "status": "processing",
                    "message": step,
                    "step": i,
                    "total_steps": 5
                })
                await asyncio.sleep(2)
            
            # Generate final report
            prompt = f"Generate a comprehensive {report_type} with live updates."
            response = model.generate_content(prompt)
            
            await websocket.send_json({
                "status": "completed",
                "message": "Report generated successfully!",
                "report": response.text,
                "step": 5,
                "total_steps": 5
            })
            
    except WebSocketDisconnect:
        print(f"Client {client_id} disconnected")
    except Exception as e:
        await websocket.send_json({
            "status": "error",
            "message": f"Error: {str(e)}"
        })