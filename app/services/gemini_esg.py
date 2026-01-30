# Gemini AI Service for ESG Analysis
import google.generativeai as genai
import os
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class GeminiESGService:
    def __init__(self):
        """Initialize Gemini AI for ESG analysis"""
        # Get API key from environment
        api_key = os.getenv("GEMINI_API_KEY", "YOUR_GEMINI_API_KEY_HERE")
        
        if api_key == "YOUR_GEMINI_API_KEY_HERE":
            logger.warning("Gemini API key not configured. Using mock responses.")
            self.mock_mode = True
        else:
            try:
                genai.configure(api_key=api_key)
                model_name = os.getenv("GEMINI_MODEL_ESG", "gemini-1.5-flash")
                self.model = genai.GenerativeModel(model_name)
                self.model_name = model_name
                self.mock_mode = False
                logger.info(f"Gemini AI initialized with model: {model_name}")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini: {str(e)}")
                self.mock_mode = True
    
    async def predict_esg_scores(self, client_data: Dict) -> Dict:
        """Predict ESG scores using Gemini AI"""
        if self.mock_mode:
            return self._mock_esg_prediction()
        
        try:
            prompt = f"""
            As an ESG expert, analyze this company data and predict ESG scores:
            
            Company Data:
            {json.dumps(client_data, indent=2)}
            
            Provide your response as a JSON object with the following structure:
            1. currentScore: Overall ESG score (0-100)
            2. pillarScores: Object with environmental, social, governance scores
            3. predictedScores: List of 6 months predictions with confidence
            4. trend: "improving", "stable", or "declining"
            5. confidence: Confidence score (0-1)
            6. keyDrivers: List of key drivers
            7. riskFactors: List of risk factors
            """
            
            response = self.model.generate_content(prompt)
            return self._parse_gemini_response(response)
            
        except Exception as e:
            logger.error(f"Gemini ESG prediction error: {str(e)}")
            return self._mock_esg_prediction()
    
    async def assess_esg_risks(self, portfolio_data: Dict) -> Dict:
        """Assess ESG risks using Gemini AI"""
        if self.mock_mode:
            return self._mock_risk_assessment()
        
        try:
            prompt = f"""
            As an ESG risk analyst, assess risks for this portfolio:
            
            Portfolio Data:
            {json.dumps(portfolio_data, indent=2)}
            
            Provide your response as a JSON object with:
            1. overallRiskScore: Overall risk score (0-100)
            2. riskCategories: Object with environmental, social, governance risk scores and levels
            3. topRisks: List of top 3 risks with type, probability, impact, and mitigation
            4. recommendations: List of mitigation strategies
            5. riskLevel: "low", "medium", or "high"
            """
            
            response = self.model.generate_content(prompt)
            return self._parse_gemini_response(response)
            
        except Exception as e:
            logger.error(f"Gemini risk assessment error: {str(e)}")
            return self._mock_risk_assessment()
    
    async def forecast_carbon_emissions(self, historical_data: Dict) -> Dict:
        """Forecast carbon emissions using Gemini AI"""
        if self.mock_mode:
            return self._mock_carbon_forecast()
        
        try:
            prompt = f"""
            As a carbon emissions expert, forecast emissions based on historical data:
            
            Historical Data:
            {json.dumps(historical_data, indent=2)}
            
            Provide your response as a JSON object with:
            1. currentEmissions: Current emissions baseline
            2. forecastData: List of 6 months predictions with confidence
            3. reductionPotential: Percentage reduction potential
            4. keyDrivers: List of key drivers affecting emissions
            5. optimizationOpportunities: List of optimization opportunities
            """
            
            response = self.model.generate_content(prompt)
            return self._parse_gemini_response(response)
            
        except Exception as e:
            logger.error(f"Gemini carbon forecast error: {str(e)}")
            return self._mock_carbon_forecast()

    async def analyze_energy_trends(self, energy_data: List[Dict], live_data: Optional[Dict] = None) -> Dict:
        """Analyze energy trends — delegate to GeminiAnalyticsService when available, otherwise use a local fallback."""
        try:
            # Prefer the analytics implementation if present
            try:
                from app.services.gemini_analytics import GeminiAnalyticsService
                analytics = GeminiAnalyticsService()
                return await analytics.analyze_energy_trends(energy_data, live_data)
            except Exception:
                # Fallback to a compact local analysis if analytics service isn't available
                total = sum(d.get('energy', 0) for d in energy_data) if energy_data else 0
                avg = total / len(energy_data) if energy_data else 0
                recent = energy_data[-7:] if len(energy_data) >= 7 else energy_data
                recent_avg = sum(d.get('energy', 0) for d in recent) / len(recent) if recent else 0
                trend = 'stable'
                if recent_avg > avg * 1.1:
                    trend = 'increasing'
                elif recent_avg < avg * 0.9:
                    trend = 'decreasing'

                return {
                    'summary': f'Energy consumption appears {trend} (avg {avg:.0f} kWh).',
                    'trends': [f'7-day avg: {recent_avg:.0f} kWh', f'overall avg: {avg:.0f} kWh'],
                    'anomalies': [],
                    'recommendations': ['Investigate peak usage', 'Consider efficiency measures'],
                    'efficiency_score': max(0, 100 - (avg / 50)),
                    'cost_savings_potential': f'R {avg * 0.1:.0f}/month',
                    'carbon_reduction_potential': f'{max(5, 100 - avg / 20)}%'
                }
        except Exception as e:
            logger.exception('analyze_energy_trends failed')
            return {'error': 'energy trend analysis failed', 'details': str(e)}

    async def generate_recommendations(self, company_profile: Dict) -> Dict:
        """Generate sustainability recommendations using Gemini AI"""
        if self.mock_mode:
            return self._mock_recommendations()
        
        try:
            prompt = f"""
            As a sustainability consultant, generate recommendations for this company:
            
            Company Profile:
            {json.dumps(company_profile, indent=2)}
            
            Provide your response as a JSON object with:
            1. recommendations: List of 9 recommendations (3 high, 3 medium, 3 low priority)
            2. totalPotentialSavings: Total annual savings
            3. implementationRoadmap: List of phases with duration and items
            4. esgImpact: Overall ESG impact score
            """
            
            response = self.model.generate_content(prompt)
            return self._parse_gemini_response(response)
            
        except Exception as e:
            logger.error(f"Gemini recommendations error: {str(e)}")
            return self._mock_recommendations()
    
    async def analyze_document(self, file_content: str, filename: str) -> Dict:
        """Analyze ESG document using Gemini AI"""
        if self.mock_mode:
            return self._mock_document_analysis()
        
        try:
            prompt = f"""
            As an ESG document analyst, analyze this document:
            
            Filename: {filename}
            Content: {file_content[:10000]}  # First 10K chars
            
            Provide your response as a JSON object with:
            1. summary: Brief summary
            2. esgMetrics: Object with environmental, social, governance scores
            3. keyInsights: List of key insights
            4. complianceStatus: Object with overall status, gaps, recommendations
            5. extractedData: Object with emissions, energy, water data
            """
            
            response = self.model.generate_content(prompt)
            return self._parse_gemini_response(response)
            
        except Exception as e:
            logger.error(f"Gemini document analysis error: {str(e)}")
            return self._mock_document_analysis()
    
    async def generate_ai_report(self, company_data: Dict, report_type: str = "comprehensive") -> Dict:
        """Generate comprehensive AI ESG report using Gemini"""
        if self.mock_mode:
            return self._mock_ai_report()
        
        try:
            prompt = f"""
            As an ESG reporting expert, generate a {report_type} report:
            
            Company Data:
            {json.dumps(company_data, indent=2)}
            
            Provide your response as a JSON object with:
            1. executiveSummary: Object with overallESGScore, trend, achievements, improvementAreas
            2. detailedAnalysis: Object with environmental, social, governance analysis
            3. predictions: Object with next quarter/year scores, confidence, keyDrivers
            4. actionPlan: Object with immediate, shortTerm, longTerm actions
            5. reportId: Unique report ID
            6. generatedAt: Timestamp
            """
            
            response = self.model.generate_content(prompt)
            return self._parse_gemini_response(response)
            
        except Exception as e:
            logger.error(f"Gemini report generation error: {str(e)}")
            return self._mock_ai_report()
    
    async def chat(self, prompt: str) -> Dict:
        """General chat with Gemini AI for ESG questions"""
        if self.mock_mode:
            return self._mock_chat_response(prompt)
        
        try:
            response = self.model.generate_content(prompt)
            return {
                "answer": response.text,
                "model": self.model_name,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Gemini chat error: {str(e)}")
            return self._mock_chat_response(prompt)
    
    def _parse_gemini_response(self, response) -> Dict:
        """Parse Gemini response to ensure JSON format"""
        try:
            # Extract text from response
            response_text = response.text
            
            # Try to extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                # Clean up any common formatting issues
                json_str = json_str.replace('\n', ' ').replace('\r', '')
                return json.loads(json_str)
            else:
                # If no JSON found, wrap in structured response
                return {
                    "analysis": response_text,
                    "model": self.model_name,
                    "timestamp": datetime.now().isoformat()
                }
        except json.JSONDecodeError as e:
            logger.warning(f"Could not parse Gemini response as JSON: {str(e)}")
            return {
                "analysis": response.text if hasattr(response, 'text') else str(response),
                "model": self.model_name,
                "timestamp": datetime.now().isoformat(),
                "note": "Response not in JSON format"
            }
        except Exception as e:
            logger.error(f"Error parsing Gemini response: {str(e)}")
            return {
                "error": "Failed to parse response",
                "raw_response": str(response.text) if hasattr(response, 'text') else str(response),
                "model": self.model_name
            }
    
    # Enhanced mock responses
    def _mock_esg_prediction(self) -> Dict:
        return {
            "currentScore": 78,
            "pillarScores": {
                "environmental": 82,
                "social": 76,
                "governance": 74
            },
            "predictedScores": [
                {"month": "Jan", "score": 78.5, "confidence": 0.92},
                {"month": "Feb", "score": 79.2, "confidence": 0.89},
                {"month": "Mar", "score": 80.1, "confidence": 0.86},
                {"month": "Apr", "score": 80.8, "confidence": 0.83},
                {"month": "May", "score": 81.5, "confidence": 0.80},
                {"month": "Jun", "score": 82.3, "confidence": 0.77}
            ],
            "trend": "improving",
            "confidence": 0.85,
            "keyDrivers": [
                "Energy efficiency improvements (15% reduction in consumption)",
                "Renewable energy adoption (35% renewable mix)",
                "Waste reduction initiatives (40% recycling rate)"
            ],
            "riskFactors": [
                {"factor": "Regulatory changes", "impact": "medium", "probability": 0.35},
                {"factor": "Supply chain emissions", "impact": "high", "probability": 0.45},
                {"factor": "Climate impact", "impact": "medium", "probability": 0.30}
            ],
            "model": "gemini-pro-mock"
        }
    
    def _mock_risk_assessment(self) -> Dict:
        return {
            "overallRiskScore": 42.5,
            "riskCategories": {
                "environmental": {"score": 35, "level": "low", "trend": "improving"},
                "social": {"score": 48, "level": "medium", "trend": "stable"},
                "governance": {"score": 44, "level": "medium", "trend": "improving"}
            },
            "topRisks": [
                {
                    "type": "Regulatory Compliance",
                    "probability": 0.35,
                    "impact": "high",
                    "mitigation": "Enhanced monitoring and reporting systems",
                    "timeline": "3-6 months"
                },
                {
                    "type": "Climate Risk",
                    "probability": 0.45,
                    "impact": "medium",
                    "mitigation": "Climate adaptation strategies and carbon offset programs",
                    "timeline": "6-12 months"
                },
                {
                    "type": "Supply Chain ESG",
                    "probability": 0.25,
                    "impact": "medium",
                    "mitigation": "Supplier engagement programs and ESG requirements",
                    "timeline": "12-18 months"
                }
            ],
            "recommendations": [
                "Implement enhanced compliance monitoring system",
                "Develop comprehensive climate adaptation plan",
                "Strengthen supplier ESG requirements and audits",
                "Establish regular ESG risk assessment cycles"
            ],
            "riskLevel": "medium",
            "model": "gemini-pro-mock"
        }
    
    def _mock_carbon_forecast(self) -> Dict:
        return {
            "currentEmissions": 1250.5,
            "units": "metric tons CO2e",
            "forecastData": [
                {"month": "Jan", "predicted": 1280.2, "confidence": 0.90, "trend": "up"},
                {"month": "Feb", "predicted": 1265.8, "confidence": 0.88, "trend": "down"},
                {"month": "Mar", "predicted": 1245.3, "confidence": 0.86, "trend": "down"},
                {"month": "Apr", "predicted": 1230.7, "confidence": 0.84, "trend": "down"},
                {"month": "May", "predicted": 1218.9, "confidence": 0.82, "trend": "down"},
                {"month": "Jun", "predicted": 1205.4, "confidence": 0.80, "trend": "down"}
            ],
            "reductionPotential": 18.5,
            "keyDrivers": [
                "Energy consumption trends (seasonal variations)",
                "Production volume changes",
                "Renewable energy integration progress",
                "Operational efficiency improvements"
            ],
            "optimizationOpportunities": [
                {"opportunity": "Solar panel installation", "savings": 120, "roi": 3.2},
                {"opportunity": "Energy efficiency upgrades", "savings": 85, "roi": 2.8},
                {"opportunity": "Process optimization", "savings": 65, "roi": 4.1},
                {"opportunity": "Transportation electrification", "savings": 45, "roi": 5.5}
            ],
            "model": "gemini-pro-mock"
        }
    
    def _mock_recommendations(self) -> Dict:
        return {
            "recommendations": [
                {
                    "category": "Energy",
                    "priority": "high",
                    "title": "Install Solar Panels",
                    "description": "Install rooftop solar panels to reduce grid dependency and lower emissions",
                    "estimatedSavings": "$45,000/year",
                    "implementationTime": "3-6 months",
                    "esgImpact": {"environmental": 8, "social": 3, "governance": 2},
                    "roi": 185,
                    "carbonReduction": 120
                },
                {
                    "category": "Emissions",
                    "priority": "high",
                    "title": "Implement Carbon Tracking System",
                    "description": "Real-time carbon emissions monitoring and reporting system",
                    "estimatedSavings": "$28,000/year",
                    "implementationTime": "6-12 months",
                    "esgImpact": {"environmental": 6, "social": 2, "governance": 5},
                    "roi": 156,
                    "carbonReduction": 85
                },
                {
                    "category": "Water",
                    "priority": "medium",
                    "title": "Water Recycling System",
                    "description": "Install water recycling and conservation system",
                    "estimatedSavings": "$15,000/year",
                    "implementationTime": "9-15 months",
                    "esgImpact": {"environmental": 5, "social": 4, "governance": 1},
                    "roi": 134,
                    "carbonReduction": 30
                }
            ],
            "totalPotentialSavings": "$88,000/year",
            "totalCarbonReduction": 235,
            "implementationRoadmap": [
                {"phase": "Quick Wins", "duration": "0-3 months", "items": 3, "priority": "high"},
                {"phase": "Strategic Projects", "duration": "3-12 months", "items": 4, "priority": "medium"},
                {"phase": "Long-term Vision", "duration": "12-24 months", "items": 3, "priority": "low"}
            ],
            "esgImpact": {"environmental": 7.5, "social": 4.2, "governance": 3.8},
            "model": "gemini-pro-mock"
        }
    
    def _mock_document_analysis(self) -> Dict:
        return {
            "summary": "ESG sustainability report analyzed successfully. Strong performance in environmental initiatives with room for improvement in social metrics.",
            "esgMetrics": {
                "environmental": {"score": 76, "mentions": 15, "sentiment": "positive", "trend": "improving"},
                "social": {"score": 82, "mentions": 12, "sentiment": "positive", "trend": "stable"},
                "governance": {"score": 79, "mentions": 18, "sentiment": "neutral", "trend": "improving"}
            },
            "keyInsights": [
                "Strong commitment to renewable energy initiatives (40% renewable mix)",
                "Comprehensive sustainability reporting framework aligned with GRI standards",
                "Room for improvement in social impact measurement and diversity metrics",
                "Good governance practices with transparent reporting and board oversight",
                "Significant progress in waste reduction and circular economy initiatives"
            ],
            "complianceStatus": {
                "overall": "compliant",
                "frameworks": ["GRI", "SASB", "TCFD"],
                "gaps": [
                    "Enhanced disclosure required for Scope 3 emissions",
                    "Third-party verification needed for environmental claims",
                    "More detailed diversity and inclusion metrics required"
                ],
                "recommendations": [
                    "Add more detailed ESG metrics and KPIs in next report",
                    "Enhance climate risk disclosure and scenario analysis",
                    "Include supplier ESG performance data"
                ]
            },
            "extractedData": {
                "emissions": {"scope1": 450, "scope2": 320, "scope3": 180, "units": "metric tons CO2e"},
                "energy": {"renewable": 65, "total": 100, "units": "MWh", "renewablePercentage": 65},
                "water": {"consumption": 5500, "recycled": 1200, "units": "cubic meters", "recyclingRate": 22},
                "waste": {"total": 120, "recycled": 85, "units": "tons", "recyclingRate": 71}
            },
            "model": "gemini-pro-mock"
        }
    
    def _mock_ai_report(self) -> Dict:
        current_time = datetime.now()
        return {
            "reportId": f"GEMINI-REPORT-{current_time.strftime('%Y%m%d-%H%M%S')}",
            "generatedAt": current_time.isoformat(),
            "executiveSummary": {
                "overallESGScore": 79,
                "trend": "improving",
                "keyAchievements": [
                    "22% reduction in carbon emissions year-over-year",
                    "35% increase in renewable energy usage",
                    "Enhanced governance framework with independent board oversight",
                    "40% waste diversion rate achieved"
                ],
                "areasForImprovement": [
                    "Supply chain transparency and ESG requirements",
                    "Social impact measurement and reporting",
                    "Climate risk assessment and adaptation planning",
                    "Diversity and inclusion metrics"
                ],
                "timePeriod": f"Q1 {current_time.year}",
                "comparisonPeriod": f"Q1 {current_time.year - 1}"
            },
            "detailedAnalysis": {
                "environmental": {
                    "score": 76,
                    "strengths": [
                        "Energy efficiency initiatives showing 15% reduction",
                        "Strong renewable energy adoption strategy",
                        "Effective waste management and recycling programs"
                    ],
                    "weaknesses": [
                        "Water management needs improvement",
                        "Scope 3 emissions reporting incomplete",
                        "Limited biodiversity initiatives"
                    ],
                    "recommendations": [
                        "Implement water recycling systems",
                        "Enhance waste sorting and circular economy initiatives",
                        "Develop biodiversity action plan"
                    ],
                    "metrics": {
                        "carbonIntensity": 45.2,
                        "energyEfficiency": 0.85,
                        "waterUsage": 5500,
                        "wasteRecycling": 71
                    }
                },
                "social": {
                    "score": 82,
                    "strengths": [
                        "Excellent employee safety record",
                        "Strong community engagement programs",
                        "Comprehensive employee wellness initiatives"
                    ],
                    "weaknesses": [
                        "Limited diversity metrics and targets",
                        "Supply chain labor practices need monitoring",
                        "Social impact measurement could be more comprehensive"
                    ],
                    "recommendations": [
                        "Enhance diversity programs with measurable targets",
                        "Improve labor monitoring in supply chain",
                        "Develop comprehensive social impact measurement framework"
                    ],
                    "metrics": {
                        "employeeSatisfaction": 88,
                        "safetyIncidents": 2,
                        "communityInvestment": 150000,
                        "trainingHours": 40
                    }
                },
                "governance": {
                    "score": 79,
                    "strengths": [
                        "Strong board oversight and independence",
                        "Comprehensive ethics policies and training",
                        "Transparent financial reporting"
                    ],
                    "weaknesses": [
                        "Stakeholder communication could be enhanced",
                        "ESG risk integration needs improvement",
                        "Executive compensation ESG linkage weak"
                    ],
                    "recommendations": [
                        "Enhance stakeholder communication channels",
                        "Improve ESG risk integration in decision-making",
                        "Strengthen executive compensation ESG linkage"
                    ],
                    "metrics": {
                        "boardDiversity": 35,
                        "esgTraining": 95,
                        "whistleblowerCases": 0,
                        "policyCompliance": 98
                    }
                }
            },
            "predictions": {
                "nextQuarterScore": 81,
                "nextYearScore": 85,
                "confidence": 0.87,
                "keyDrivers": [
                    "Continued energy efficiency improvements",
                    "Renewable energy expansion projects",
                    "Enhanced ESG data collection and reporting",
                    "Supply chain ESG integration"
                ],
                "risks": [
                    {"risk": "Regulatory changes", "impact": "medium", "probability": 0.35},
                    {"risk": "Climate events", "impact": "high", "probability": 0.25},
                    {"risk": "Market volatility", "impact": "medium", "probability": 0.40}
                ]
            },
            "actionPlan": {
                "immediate": [
                    "Conduct comprehensive energy audit",
                    "Review and update compliance requirements",
                    "Enhance ESG data collection systems",
                    "Launch stakeholder engagement initiative"
                ],
                "shortTerm": [
                    "Implement solar panel project phase 1",
                    "Develop comprehensive reporting framework",
                    "Launch supply chain ESG assessment",
                    "Establish ESG training program"
                ],
                "longTerm": [
                    "Achieve carbon neutrality target",
                    "Develop 5-year sustainability strategy",
                    "Implement circular economy initiatives",
                    "Establish industry leadership in ESG"
                ]
            },
            "model": "gemini-pro-mock",
            "version": "2.0"
        }
    
    def _mock_chat_response(self, prompt: str) -> Dict:
        """Generate mock chat response based on prompt"""
        prompt_lower = prompt.lower()
        
        if 'report' in prompt_lower:
            response_text = "I can help you generate comprehensive ESG reports. Based on your organization's data, I recommend starting with a sustainability performance report that includes environmental impact analysis, social responsibility metrics, and governance compliance assessment. Would you like me to begin the report generation process?"
        elif 'recommend' in prompt_lower or 'improve' in prompt_lower:
            response_text = "Based on ESG best practices and your current performance, I recommend: 1) Implementing energy efficiency measures (estimated savings: $45K/year), 2) Enhancing diversity and inclusion programs, 3) Strengthening supply chain ESG requirements, 4) Improving climate risk assessment. Which area would you like to explore in detail?"
        elif 'score' in prompt_lower or 'rating' in prompt_lower:
            response_text = "Your current ESG score is estimated at 7.8/10. Breakdown: Environmental: 8.2/10 (strong renewable energy performance), Social: 7.9/10 (good employee engagement), Governance: 7.3/10 (transparent reporting). Overall trend: Improving (+0.5 points this quarter)."
        elif 'carbon' in prompt_lower or 'emission' in prompt_lower:
            response_text = "Current carbon emissions: 1,250 metric tons CO2e. Reduction potential: 18.5%. Key opportunities: Solar installation (120t reduction), energy efficiency (85t), process optimization (65t). Estimated annual savings: $88,000."
        elif 'invoice' in prompt_lower or 'purchase' in prompt_lower:
            response_text = "I can analyze your invoices for ESG impact. For effective analysis, ensure invoices include: 1) Supplier ESG ratings, 2) Product/service carbon footprint data, 3) Sustainability certifications, 4) Environmental impact metrics. Upload your invoices and I'll categorize them by ESG impact."
        else:
            response_text = f"As your ESG AI assistant, I can help with: sustainability reporting, ESG scoring, carbon footprint analysis, risk assessment, recommendations, and document analysis. Regarding '{prompt[:50]}...', I suggest focusing on data-driven ESG initiatives aligned with industry best practices and regulatory requirements."
        
        return {
            "answer": response_text,
            "model": "gemini-pro-mock",
            "timestamp": datetime.now().isoformat(),
            "confidence": 0.85
        }
    
    def refresh_service(self):
        """Force refresh the service with current environment variables"""
        try:
            api_key = os.getenv("GEMINI_API_KEY", "YOUR_GEMINI_API_KEY_HERE")
            
            if api_key == "YOUR_GEMINI_API_KEY_HERE":
                self.mock_mode = True
                logger.warning("Gemini API key not configured. Staying in mock mode.")
            else:
                genai.configure(api_key=api_key)
                model_name = os.getenv("GEMINI_MODEL_ESG", "gemini-1.5-flash")
                self.model = genai.GenerativeModel(model_name)
                self.model_name = model_name
                self.mock_mode = False
                logger.info(f"Gemini service refreshed with model: {model_name}")
        except Exception as e:
            logger.error(f"Failed to refresh Gemini service: {str(e)}")
            self.mock_mode = True

# Global Gemini service instance
gemini_esg_service = GeminiESGService()

def get_gemini_esg_service():
    """Get the global Gemini ESG service instance"""
    return gemini_esg_service