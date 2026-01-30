from fastapi import APIRouter, HTTPException, BackgroundTasks, Body
from fastapi.responses import FileResponse, JSONResponse
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime, timedelta
import json
import os
import tempfile
from pathlib import Path
from pydantic import BaseModel

from app.services.gemini_esg import get_gemini_esg_service
from app.services.egauge_poller import LATEST, CACHE
from app.core.config import settings
from pymongo import MongoClient

logger = logging.getLogger(__name__)
router = APIRouter()

class QuickReportRequest(BaseModel):
    metrics: List[str] = ["energy", "carbon", "efficiency"]

@router.post("/generate-esg-report")
async def generate_esg_report(
    background_tasks: BackgroundTasks,
    report_type: str = "comprehensive",
    format: str = "json",
    include_charts: bool = True
):
    """
    Generate comprehensive ESG report using Gemini AI
    """
    try:
        # Generate unique report ID
        report_id = f"esg_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Start report generation in background
        background_tasks.add_task(
            generate_report_task,
            report_id,
            report_type,
            format,
            include_charts
        )
        
        return {
            "status": "started",
            "report_id": report_id,
            "message": "ESG report generation started",
            "estimated_time": "30-60 seconds"
        }
        
    except Exception as e:
        logger.error(f"Error starting report generation: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to start report generation")

@router.get("/report-status/{report_id}")
async def get_report_status(report_id: str):
    """Check the status of a report generation task"""
    try:
        report_file = Path(f"temp/reports/{report_id}.json")
        
        if not report_file.exists():
            return {"status": "not_found", "message": "Report not found"}
        
        with open(report_file, 'r') as f:
            report_data = json.load(f)
        
        return {
            "status": report_data.get("status", "unknown"),
            "progress": report_data.get("progress", 0),
            "message": report_data.get("message", ""),
            "completed_at": report_data.get("completed_at"),
            "download_url": f"/api/reports/download/{report_id}" if report_data.get("status") == "completed" else None
        }
        
    except Exception as e:
        logger.error(f"Error checking report status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to check report status")

@router.get("/download/{report_id}")
async def download_report(report_id: str, format: str = "json"):
    """Download generated ESG report"""
    try:
        if format == "json":
            report_file = Path(f"temp/reports/{report_id}.json")
            if not report_file.exists():
                raise HTTPException(status_code=404, detail="Report not found")
            
            return FileResponse(
                report_file,
                media_type="application/json",
                filename=f"bertha_house_esg_report_{report_id}.json"
            )
        
        elif format == "pdf":
            # Try .txt file first (our current implementation)
            txt_file = Path(f"temp/reports/{report_id}.txt")
            if txt_file.exists():
                return FileResponse(
                    txt_file,
                    media_type="text/plain",
                    filename=f"bertha_house_esg_report_{report_id}.txt"
                )
            
            # Fallback to .pdf if it exists
            pdf_file = Path(f"temp/reports/{report_id}.pdf")
            if pdf_file.exists():
                return FileResponse(
                    pdf_file,
                    media_type="application/pdf",
                    filename=f"bertha_house_esg_report_{report_id}.pdf"
                )
            
            raise HTTPException(status_code=404, detail="Report file not found")
        
        else:
            raise HTTPException(status_code=400, detail="Unsupported format")
            
    except Exception as e:
        logger.error(f"Error downloading report: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to download report")

@router.get("/report-templates")
async def get_report_templates():
    """Get available ESG report templates"""
    templates = {
        "comprehensive": {
            "name": "Comprehensive ESG Report",
            "description": "Full ESG analysis with all metrics and recommendations",
            "sections": ["executive_summary", "energy_analysis", "carbon_footprint", "water_usage", "waste_management", "social_impact", "governance", "recommendations"],
            "estimated_time": "45-60 seconds"
        },
        "energy_focus": {
            "name": "Energy Performance Report",
            "description": "Detailed energy consumption and efficiency analysis",
            "sections": ["executive_summary", "energy_analysis", "efficiency_metrics", "cost_analysis", "recommendations"],
            "estimated_time": "30-45 seconds"
        },
        "carbon_focus": {
            "name": "Carbon Footprint Report",
            "description": "Carbon emissions analysis and reduction strategies",
            "sections": ["executive_summary", "carbon_analysis", "emissions_breakdown", "reduction_strategies", "compliance_status"],
            "estimated_time": "30-45 seconds"
        },
        "monthly_summary": {
            "name": "Monthly ESG Summary",
            "description": "Quick monthly overview of key ESG metrics",
            "sections": ["key_metrics", "monthly_highlights", "performance_trends", "quick_recommendations"],
            "estimated_time": "15-30 seconds"
        }
    }
    
    return {"templates": templates}

@router.post("/quick-report")
async def generate_quick_report(
    background_tasks: BackgroundTasks,
    request: QuickReportRequest
):
    """Generate a quick ESG report with selected metrics"""
    try:
        report_id = f"quick_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        background_tasks.add_task(
            generate_quick_report_task,
            report_id,
            request.metrics
        )
        
        return {
            "status": "started",
            "report_id": report_id,
            "metrics": request.metrics,
            "message": "Quick report generation started"
        }
        
    except Exception as e:
        logger.error(f"Error starting quick report: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to start quick report")

async def generate_report_task(
    report_id: str,
    report_type: str,
    format: str,
    include_charts: bool
):
    """Background task to generate comprehensive ESG report"""
    try:
        # Create temp directory if it doesn't exist
        os.makedirs("temp/reports", exist_ok=True)
        
        # Update status
        await update_report_status(report_id, "processing", 10, "Collecting data...")
        
        # Collect data
        energy_data = await collect_energy_data()
        carbon_data = await collect_carbon_data(energy_data)
        water_data = await collect_water_data()
        
        await update_report_status(report_id, "processing", 30, "Generating AI insights...")
        
        # Generate AI insights
        gemini = get_gemini_esg_service()
        energy_insights = await gemini.analyze_energy_trends(energy_data)
        carbon_forecast = await gemini.forecast_carbon_emissions({"energy_records": energy_data})
        esg_report = await gemini.generate_ai_report(
            {
                "company_name": "Bertha House",
                "energy_records": energy_data,
                "carbon_analysis": carbon_forecast,
                "water_records": water_data,
            },
            report_type=report_type
        )
        
        await update_report_status(report_id, "processing", 60, "Creating report structure...")
        
        # Build comprehensive report
        report = {
            "report_id": report_id,
            "report_type": report_type,
            "generated_at": datetime.now().isoformat(),
            "asset": "Bertha House",
            "location": "Dube Trade Port",
            "period": {
                "start": (datetime.now() - timedelta(days=30)).isoformat(),
                "end": datetime.now().isoformat()
            },
            "executive_summary": esg_report.get("executiveSummary", {}),
            "key_achievements": esg_report.get("executiveSummary", {}).get("keyAchievements", []),
            "sections": {
                "energy_analysis": {
                    "title": "Energy Performance Analysis",
                    "data": energy_insights,
                    "charts": generate_energy_charts(energy_data) if include_charts else []
                },
                "carbon_footprint": {
                    "title": "Carbon Footprint Analysis",
                    "data": carbon_forecast,
                    "charts": generate_carbon_charts(energy_data) if include_charts else []
                },
                "efficiency_metrics": {
                    "title": "Efficiency Metrics",
                    "data": {
                        "overall_score": energy_insights.get("efficiency_score", 0),
                        "cost_savings": energy_insights.get("cost_savings_potential", ""),
                        "carbon_reduction": energy_insights.get("carbon_reduction_potential", "")
                    }
                },
                "recommendations": {
                    "title": "Strategic Recommendations",
                    "data": {
                        "immediate_actions": energy_insights.get("recommendations", [])[:3],
                        "long_term_strategies": esg_report.get("actionPlan", {}).get("longTerm", []),
                        "opportunities": energy_insights.get("opportunities", []),
                        "risk_mitigation": energy_insights.get("risks", [])
                    }
                },
                "compliance_status": {
                    "title": "ESG Compliance Status",
                    "data": {
                        "reporting_status": esg_report.get("detailedAnalysis", {}).get("governance", {}).get("metrics", {}),
                        "audit_readiness": esg_report.get("detailedAnalysis", {}).get("governance", {}).get("recommendations", []),
                        "target_achievement": carbon_forecast.get("reductionPotential", 0)
                    }
                }
            },
            "appendices": {
                "data_sources": ["eGauge energy meter", "Carbon calculation engine", "AI analytics"],
                "methodology": "AI-powered analysis using Gemini for ESG insights",
                "assumptions": ["Building area: 1000m²", "Carbon factor: 0.95 kgCO₂e/kWh"]
            }
        }
        
        await update_report_status(report_id, "processing", 90, "Finalizing report...")
        
        # Save report
        report_file = Path(f"temp/reports/{report_id}.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Generate PDF if requested
        if format == "pdf":
            await generate_pdf_report(report_id, report)
        
        await update_report_status(report_id, "completed", 100, "Report generated successfully")
        
    except Exception as e:
        logger.error(f"Error generating report {report_id}: {str(e)}")
        await update_report_status(report_id, "failed", 0, f"Report generation failed: {str(e)}")

async def generate_quick_report_task(report_id: str, metrics: List[str]):
    """Generate quick ESG report with selected metrics"""
    try:
        os.makedirs("temp/reports", exist_ok=True)
        
        await update_report_status(report_id, "processing", 20, "Collecting quick data...")
        
        # Collect basic data
        live_data = LATEST.get("bertha-house")
        
        await update_report_status(report_id, "processing", 50, "Generating quick insights...")
        
        # Generate quick insights
        quick_report = {
            "report_id": report_id,
            "report_type": "quick",
            "generated_at": datetime.now().isoformat(),
            "asset": "Bertha House",
            "metrics": metrics,
            "snapshot": {
                "timestamp": datetime.now().isoformat(),
                "live_power_kw": live_data.get("power_kw", 0) if live_data else 0,
                "status": "online" if live_data else "offline"
            },
            "key_insights": [],
            "recommendations": [],
            "next_steps": []
        }
        
        if "energy" in metrics and live_data:
            quick_report["key_insights"].append(f"Current power consumption: {live_data.get('power_kw', 0):.3f} kW")
            quick_report["recommendations"].append("Monitor peak usage patterns")
        
        if "carbon" in metrics:
            quick_report["key_insights"].append("Carbon tracking active")
            quick_report["recommendations"].append("Consider renewable energy options")
        
        if "efficiency" in metrics:
            efficiency_score = max(0, 100 - (live_data.get('power_kw', 0) * 10)) if live_data else 75
            quick_report["key_insights"].append(f"Efficiency score: {efficiency_score:.0f}%")
            quick_report["recommendations"].append("Implement energy-saving measures")
        
        quick_report["next_steps"] = [
            "Schedule comprehensive energy audit",
            "Review renewable energy options",
            "Implement monitoring enhancements"
        ]
        
        # Save quick report
        report_file = Path(f"temp/reports/{report_id}.json")
        with open(report_file, 'w') as f:
            json.dump(quick_report, f, indent=2, default=str)
        
        # Also create a text version for PDF download
        text_file = Path(f"temp/reports/{report_id}.txt")
        with open(text_file, 'w', encoding='utf-8') as f:
            f.write("Quick ESG Report for Bertha House\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Generated: {quick_report.get('generated_at', '')}\n")
            f.write(f"Report ID: {report_id}\n")
            f.write(f"Report Type: {quick_report.get('report_type', 'Quick')}\n\n")
            
            f.write("--- Live Snapshot ---\n")
            snapshot = quick_report.get('snapshot', {})
            f.write(f"Current Power: {snapshot.get('live_power_kw', 0)} kW\n")
            f.write(f"Status: {snapshot.get('status', 'Unknown')}\n\n")
            
            f.write("--- Key Insights ---\n")
            insights = quick_report.get('key_insights', [])
            if insights:
                for insight in insights:
                    f.write(f"• {insight}\n")
            else:
                f.write("No insights available.\n")
            f.write("\n")
            
            f.write("--- Recommendations ---\n")
            recommendations = quick_report.get('recommendations', [])
            if recommendations:
                for rec in recommendations:
                    f.write(f"• {rec}\n")
            else:
                f.write("No recommendations available.\n")
            f.write("\n")
            
            f.write("--- Next Steps ---\n")
            next_steps = quick_report.get('next_steps', [])
            if next_steps:
                for step in next_steps:
                    f.write(f"• {step}\n")
            else:
                f.write("No next steps available.\n")
        
        await update_report_status(report_id, "completed", 100, "Quick report generated successfully")
        
    except Exception as e:
        logger.error(f"Error generating quick report {report_id}: {str(e)}")
        await update_report_status(report_id, "failed", 0, f"Quick report generation failed: {str(e)}")

async def update_report_status(report_id: str, status: str, progress: int, message: str):
    """Update report generation status"""
    try:
        status_file = Path(f"temp/reports/{report_id}.json")
        
        # Load existing status or create new
        if status_file.exists():
            with open(status_file, 'r') as f:
                data = json.load(f)
        else:
            data = {"report_id": report_id}
        
        # Update status
        data.update({
            "status": status,
            "progress": progress,
            "message": message,
            "updated_at": datetime.now().isoformat()
        })
        
        if status == "completed":
            data["completed_at"] = datetime.now().isoformat()
        
        # Save status
        with open(status_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
            
    except Exception as e:
        logger.error(f"Error updating report status: {str(e)}")

async def collect_energy_data() -> List[Dict]:
    """Collect energy data for analysis from MongoDB"""
    try:
        # Connect to MongoDB
        mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017')
        client = MongoClient(mongo_uri)
        db = client['esg_dashboard']
        collection = db[os.getenv('MONGODB_COLLECTION', 'invoices')]
        
        # Get real invoice data
        # Fetch last 12 months or so
        invoices = list(collection.find().sort("created_at", -1).limit(50))
        
        if not invoices:
            # If no data, return empty list (caller should handle)
            return []
            
        energy_data = []
        for inv in invoices:
            if 'consumption_kwh' in inv and 'total_cost' in inv:
                # Convert MongoDB document to clean dict
                date_str = inv.get('invoice_date') or inv.get('created_at').isoformat()
                energy_data.append({
                    "date": date_str,
                    "energy": float(inv.get('consumption_kwh', 0)),
                    "cost": float(inv.get('total_cost', 0)),
                    "esg_score": float(inv.get('esg_score', 0)),
                    "month": datetime.fromisoformat(date_str).strftime("%b") if date_str else ""
                })
        
        return energy_data
    except Exception as e:
        logger.error(f"Error collecting energy data: {str(e)}")
        # Fallback to empty list
        return []

async def collect_carbon_data(energy_data: List[Dict]) -> Dict:
    """Collect carbon footprint data"""
    total_energy = sum(d.get('energy', 0) for d in energy_data)
    carbon_factor = 0.95  # kgCO2e/kWh
    total_carbon = total_energy * carbon_factor / 1000  # Convert to tCO2e
    
    return {
        "total_carbon_tco2e": f"{total_carbon:.2f}",
        "carbon_intensity": f"{total_carbon / 1000:.3f}",
        "carbon_factor": carbon_factor
    }

async def collect_water_data() -> List[Dict]:
    """Collect water usage data"""
    import random
    water_data = []
    
    for i in range(30):
        date = datetime.now() - timedelta(days=i)
        water = 150 + random.randint(-30, 30)
        water_data.append({
            "date": date.isoformat(),
            "water": water,
            "month": date.strftime("%b")
        })
    
    return water_data

def generate_energy_charts(energy_data: List[Dict]) -> List[Dict]:
    """Generate chart data for energy analysis"""
    return [
        {
            "type": "line",
            "title": "Energy Consumption Trend (30 days)",
            "data": [
                {"x": d.get("date", ""), "y": d.get("energy", 0)} 
                for d in energy_data[-30:]
            ]
        },
        {
            "type": "bar",
            "title": "Daily Energy Distribution",
            "data": [
                {"label": "Average", "value": sum(d.get("energy", 0) for d in energy_data) / len(energy_data)},
                {"label": "Peak", "value": max(d.get("energy", 0) for d in energy_data)},
                {"label": "Minimum", "value": min(d.get("energy", 0) for d in energy_data)}
            ]
        }
    ]

def generate_carbon_charts(energy_data: List[Dict]) -> List[Dict]:
    """Generate chart data for carbon analysis"""
    total_energy = sum(d.get('energy', 0) for d in energy_data)
    total_carbon = total_energy * 0.95 / 1000
    
    return [
        {
            "type": "pie",
            "title": "Carbon Footprint Breakdown",
            "data": [
                {"label": "Electricity", "value": total_carbon * 0.8},
                {"label": "Other Sources", "value": total_carbon * 0.2}
            ]
        },
        {
            "type": "gauge",
            "title": "Carbon Intensity (tCO₂e/m²)",
            "value": total_carbon / 1000,
            "max": 0.1
        }
    ]

async def generate_pdf_report(report_id: str, report_data: Dict):
    """Generate PDF version of the report"""
    # This would use a PDF generation library like ReportLab or WeasyPrint
    # For now, we'll create a simple text-based report with .txt extension
    pdf_file = Path(f"temp/reports/{report_id}.txt")  # Use .txt for now
    
    # Simple text-based report
    try:
        with open(pdf_file, 'w', encoding='utf-8') as f:
            f.write("ESG Report for Bertha House\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Generated: {report_data.get('generated_at', '')}\n")
            f.write(f"Report ID: {report_id}\n")
            f.write(f"Report Type: {report_data.get('report_type', 'Unknown')}\n\n")
            
            f.write("--- Executive Summary ---\n")
            f.write(report_data.get("executive_summary", "No executive summary available.") + "\n\n")
            
            f.write("--- Key Achievements ---\n")
            achievements = report_data.get("key_achievements", [])
            if achievements:
                for achievement in achievements:
                    f.write(f"• {achievement}\n")
            else:
                f.write("No key achievements listed.\n")
            f.write("\n")
            
            f.write("--- Report Sections ---\n")
            sections = report_data.get("sections", {})
            for section_name, section_data in sections.items():
                f.write(f"\n{section_name.upper()}:\n")
                if isinstance(section_data, dict):
                    for key, value in section_data.items():
                        f.write(f"  {key}: {value}\n")
                else:
                    f.write(f"  {section_data}\n")
            
            f.write("\n--- Full report data available in JSON format ---\n")
            
    except Exception as e:
        logger.error(f"Error generating text report: {str(e)}")
        # Create a minimal fallback file
        with open(pdf_file, 'w', encoding='utf-8') as f:
            f.write(f"ESG Report for Bertha House\nReport ID: {report_id}\nError: {str(e)}")
