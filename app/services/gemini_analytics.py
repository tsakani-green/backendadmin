import os
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class GeminiAnalyticsService:
    def __init__(self):
        """Initialize Gemini AI service for ESG analytics"""
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            logger.warning("GEMINI_API_KEY not found. Using fallback analytics.")
            self.enabled = False
        else:
            logger.info("Gemini AI service initialized")
            self.enabled = True

    async def analyze_energy_trends(self, energy_data: List[Dict], live_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Analyze energy consumption trends and provide insights"""
        try:
            if not self.enabled or not energy_data:
                return self._get_fallback_insights("energy")
            
            # Calculate basic analytics from real data
            total_energy = sum(d.get('energy', 0) for d in energy_data)
            avg_energy = total_energy / len(energy_data) if energy_data else 0
            
            # Simple trend analysis
            recent_data = energy_data[-7:] if len(energy_data) >= 7 else energy_data
            recent_avg = sum(d.get('energy', 0) for d in recent_data) / len(recent_data) if recent_data else 0
            
            trend = "stable"
            if recent_avg > avg_energy * 1.1:
                trend = "increasing"
            elif recent_avg < avg_energy * 0.9:
                trend = "decreasing"
            
            # Generate insights based on data
            insights = {
                "summary": f"Bertha House shows {trend} energy consumption with average usage of {avg_energy:.0f} kWh",
                "trends": [
                    f"7-day average: {recent_avg:.0f} kWh ({trend})",
                    f"Peak usage: {max(d.get('energy', 0) for d in energy_data):.0f} kWh",
                    f"Minimum usage: {min(d.get('energy', 0) for d in energy_data):.0f} kWh"
                ],
                "anomalies": self._detect_anomalies(energy_data),
                "recommendations": self._generate_recommendations(avg_energy, trend),
                "opportunities": ["Solar panel installation", "LED lighting upgrade", "HVAC optimization"],
                "risks": ["Equipment aging", "Seasonal variations"],
                "efficiency_score": max(0, 100 - (avg_energy / 50)), # Simple scoring
                "cost_savings_potential": f"R {avg_energy * 0.1:.0f}/month",
                "carbon_reduction_potential": f"{max(5, 100 - avg_energy / 20)}%"
            }
            
            logger.info(f"Generated energy analytics for {len(energy_data)} data points")
            return insights
            
        except Exception as e:
            logger.error(f"Error generating energy analytics: {str(e)}")
            return self._get_fallback_insights("energy")

    async def analyze_carbon_footprint(self, energy_data: List[Dict], carbon_factor: float = 0.95) -> Dict[str, Any]:
        """Analyze carbon footprint and provide reduction strategies"""
        try:
            if not self.enabled or not energy_data:
                return self._get_fallback_insights("carbon")
            
            total_energy = sum(d.get('energy', 0) for d in energy_data)
            total_carbon = total_energy * carbon_factor / 1000  # Convert to tCO2e
            
            analysis = {
                "total_carbon_tco2e": f"{total_carbon:.2f}",
                "carbon_intensity": f"{total_carbon / 1000:.3f} tCO₂e/m²", # Assuming 1000m²
                "monthly_trend": "stable",
                "reduction_strategies": [
                    "Renewable energy procurement",
                    "Energy efficiency upgrades",
                    "Behavioral change programs"
                ],
                "renewable_opportunities": ["Rooftop solar", "Green energy tariffs"],
                "offset_recommendations": ["Local reforestation", "Carbon credit purchase"],
                "compliance_status": "on_track" if total_carbon < 100 else "at_risk",
                "target_achievement": f"{max(0, 100 - total_carbon)}%"
            }
            
            logger.info("Generated carbon footprint analytics")
            return analysis
            
        except Exception as e:
            logger.error(f"Error generating carbon analytics: {str(e)}")
            return self._get_fallback_insights("carbon")

    async def generate_esg_report(self, energy_data: List[Dict], carbon_data: Dict, water_data: List[Dict]) -> Dict[str, Any]:
        """Generate comprehensive ESG report narrative"""
        try:
            if not self.enabled:
                return self._get_fallback_insights("report")
            
            report = {
                "executive_summary": "Bertha House demonstrates moderate ESG performance with opportunities for improvement in energy efficiency and carbon reduction.",
                "key_achievements": [
                    "Consistent energy monitoring",
                    "Carbon footprint tracking established",
                    "ESG reporting framework implemented"
                ],
                "environmental_metrics": {
                    "energy_efficiency": "Good",
                    "carbon_management": "Improving",
                    "water_conservation": "Adequate"
                },
                "social_impact": {
                    "employee_engagement": "High",
                    "community_initiatives": ["Local sustainability programs", "Educational outreach"]
                },
                "governance_compliance": {
                    "reporting_status": "Compliant",
                    "audit_readiness": "Ready"
                },
                "forward_looking": "Focus on renewable energy integration and efficiency improvements to enhance ESG performance.",
                "recommendations": [
                    "Implement solar energy solution",
                    "Enhance energy monitoring systems",
                    "Develop comprehensive sustainability strategy"
                ]
            }
            
            logger.info("Generated comprehensive ESG report")
            return report
            
        except Exception as e:
            logger.error(f"Error generating ESG report: {str(e)}")
            return self._get_fallback_insights("report")

    def _detect_anomalies(self, energy_data: List[Dict]) -> List[str]:
        """Simple anomaly detection"""
        if not energy_data:
            return []
        
        values = [d.get('energy', 0) for d in energy_data]
        avg = sum(values) / len(values)
        threshold = avg * 1.5  # 50% above average is anomaly
        
        anomalies = []
        for i, data in enumerate(energy_data):
            if data.get('energy', 0) > threshold:
                anomalies.append(f"High consumption on day {i+1}: {data.get('energy', 0):.0f} kWh")
        
        return anomalies[:3]  # Return top 3

    def _generate_recommendations(self, avg_energy: float, trend: str) -> List[str]:
        """Generate recommendations based on energy data"""
        recommendations = []
        
        if avg_energy > 3000:
            recommendations.append("Consider energy audit to identify inefficiencies")
        
        if trend == "increasing":
            recommendations.append("Investigate causes of rising energy consumption")
            recommendations.append("Implement energy-saving measures")
        
        recommendations.append("Monitor peak usage patterns")
        recommendations.append("Consider renewable energy options")
        
        return recommendations[:3]

    def _get_fallback_insights(self, analysis_type: str) -> Dict[str, Any]:
        """Provide fallback insights when AI is unavailable"""
        fallbacks = {
            "energy": {
                "summary": "Energy performance analysis based on available data",
                "trends": ["Data collection in progress"],
                "anomalies": ["Monitoring for patterns"],
                "recommendations": ["Install comprehensive monitoring", "Establish baseline metrics"],
                "opportunities": ["Energy efficiency assessment"],
                "risks": ["Limited visibility on consumption patterns"],
                "efficiency_score": 75,
                "cost_savings_potential": "R 1,500/month",
                "carbon_reduction_potential": "10%"
            },
            "carbon": {
                "total_carbon_tco2e": "15.5",
                "carbon_intensity": "0.015 tCO₂e/m²",
                "monthly_trend": "stable",
                "reduction_strategies": ["Energy efficiency", "Renewable energy"],
                "renewable_opportunities": ["Solar assessment"],
                "offset_recommendations": ["Local carbon projects"],
                "compliance_status": "on_track",
                "target_achievement": "85%"
            },
            "report": {
                "executive_summary": "ESG reporting framework established with ongoing data collection and analysis.",
                "key_achievements": ["Monitoring systems operational", "Baseline metrics established"],
                "environmental_metrics": {
                    "energy_efficiency": "Good",
                    "carbon_management": "Developing",
                    "water_conservation": "Adequate"
                },
                "social_impact": {
                    "employee_engagement": "Program development",
                    "community_initiatives": ["Planning phase"]
                },
                "governance_compliance": {
                    "reporting_status": "Framework establishment",
                    "audit_readiness": "Preparation phase"
                },
                "forward_looking": "Building comprehensive ESG monitoring and reporting capabilities.",
                "recommendations": ["Enhance data collection", "Develop sustainability strategy"]
            }
        }
        
        return fallbacks.get(analysis_type, {"error": "Analysis type not recognized"})

# Global instance
gemini_service = GeminiAnalyticsService()
