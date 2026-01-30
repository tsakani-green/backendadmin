# backend/app/services/sunsynk_service.py

import httpx
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from ..core.config import settings

logger = logging.getLogger(__name__)

class SunsynkService:
    """Service for interacting with Sunsynk API to get energy data"""
    
    def __init__(self):
        self.api_url = settings.SUNSYNK_API_URL
        self.api_key = settings.SUNSYNK_API_KEY
        self.api_secret = settings.SUNSYNK_API_SECRET
        self.access_token = None
        self.token_expires_at = None
        
    async def get_access_token(self) -> str:
        """Get or refresh access token for Sunsynk API"""
        # Check if current token is still valid
        if self.access_token and self.token_expires_at and datetime.now() < self.token_expires_at:
            return self.access_token
            
        try:
            async with httpx.AsyncClient(verify=False) as client:  # Disable SSL verification
                # Try different authentication methods and endpoints
                auth_methods = [
                    # Method 1: Form data with key/secret
                    {
                        "url": f"{self.api_url}/oauth/token",
                        "data": {
                            "key": self.api_key,
                            "secret": self.api_secret
                        },
                        "headers": {"Content-Type": "application/x-www-form-urlencoded"}
                    },
                    # Method 2: JSON body
                    {
                        "url": f"{self.api_url}/oauth/token",
                        "json": {
                            "key": self.api_key,
                            "secret": self.api_secret
                        },
                        "headers": {"Content-Type": "application/json"}
                    },
                    # Method 3: Different endpoint - /api/v1/auth
                    {
                        "url": f"{self.api_url}/api/v1/auth",
                        "json": {
                            "api_key": self.api_key,
                            "api_secret": self.api_secret
                        },
                        "headers": {"Content-Type": "application/json"}
                    },
                    # Method 4: Direct token endpoint
                    {
                        "url": f"{self.api_url}/api/v1/token",
                        "json": {
                            "key": self.api_key,
                            "secret": self.api_secret
                        },
                        "headers": {"Content-Type": "application/json"}
                    },
                    # Method 5: Basic auth to /api/v1/devices
                    {
                        "url": f"{self.api_url}/api/v1/devices",
                        "headers": {
                            "X-API-Key": self.api_key,
                            "X-API-Secret": self.api_secret
                        }
                    }
                ]
                
                for i, method in enumerate(auth_methods):
                    try:
                        print(f"Trying auth method {i+1}: {method['url']}")
                        
                        if "data" in method:
                            response = await client.post(method["url"], data=method["data"], headers=method["headers"])
                        elif "json" in method:
                            response = await client.post(method["url"], json=method["json"], headers=method["headers"])
                        else:
                            response = await client.get(method["url"], headers=method["headers"])
                        
                        print(f"Response status: {response.status_code}")
                        print(f"Response text: {response.text[:200]}...")
                        
                        if response.status_code == 200:
                            token_data = response.json()
                            # Try different token field names
                            token = token_data.get("access_token") or token_data.get("token") or token_data.get("data", {}).get("token")
                            
                            if token:
                                self.access_token = token
                                # Set token to expire in 1 hour (3600 seconds)
                                self.token_expires_at = datetime.now() + timedelta(seconds=3600)
                                logger.info(f"Successfully obtained Sunsynk API access token using method {i+1}")
                                return self.access_token
                            else:
                                logger.warning(f"Auth method {i+1} succeeded but no token found in response")
                        else:
                            logger.warning(f"Auth method {i+1} failed: {response.status_code} - {response.text}")
                    except Exception as e:
                        logger.warning(f"Auth method {i+1} exception: {str(e)}")
                
                logger.error("All authentication methods failed")
                return None
                        
        except Exception as e:
            logger.error(f"Error getting Sunsynk access token: {str(e)}")
            return None
    
    async def get_device_list(self) -> List[Dict[str, Any]]:
        """Get list of devices from Sunsynk API"""
        token = await self.get_access_token()
        if not token:
            return []
            
        try:
            async with httpx.AsyncClient(verify=False) as client:  # Disable SSL verification
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                }
                
                response = await client.get(
                    f"{self.api_url}/api/v1/devices",
                    headers=headers
                )
                
                if response.status_code == 200:
                    devices = response.json()
                    logger.info(f"Successfully retrieved {len(devices)} devices from Sunsynk API")
                    return devices
                else:
                    logger.error(f"Failed to get devices: {response.status_code} - {response.text}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting device list: {str(e)}")
            return []
    
    async def get_device_realtime_data(self, device_sn: str) -> Dict[str, Any]:
        """Get real-time data for a specific device"""
        token = await self.get_access_token()
        if not token:
            return {}
            
        try:
            async with httpx.AsyncClient(verify=False) as client:  # Disable SSL verification
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                }
                
                response = await client.get(
                    f"{self.api_url}/api/v1/devices/{device_sn}/realtime",
                    headers=headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"Successfully retrieved real-time data for device {device_sn}")
                    return data
                else:
                    logger.error(f"Failed to get real-time data: {response.status_code} - {response.text}")
                    return {}
                    
        except Exception as e:
            logger.error(f"Error getting real-time data: {str(e)}")
            return {}
    
    async def get_device_power_data(self, device_sn: str, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Get historical power data for a specific device"""
        token = await self.get_access_token()
        if not token:
            return []
            
        try:
            async with httpx.AsyncClient(verify=False) as client:  # Disable SSL verification
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                }
                
                params = {
                    "startTime": start_time.isoformat(),
                    "endTime": end_time.isoformat(),
                    "interval": "5m"  # 5-minute intervals
                }
                
                response = await client.get(
                    f"{self.api_url}/api/v1/devices/{device_sn}/power",
                    headers=headers,
                    params=params
                )
                
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"Successfully retrieved power data for device {device_sn}")
                    return data
                else:
                    logger.error(f"Failed to get power data: {response.status_code} - {response.text}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting power data: {str(e)}")
            return []
    
    async def get_bertha_house_data(self) -> Dict[str, Any]:
        """Get comprehensive energy data for Bertha House"""
        try:
            # For now, return mock data since the actual API endpoints are not accessible
            # This allows the frontend to work while we investigate the correct API structure
            logger.info("Returning mock Sunsynk data for Bertha House")
            
            mock_data = {
                "device_info": {
                    "name": "Bertha House Inverter",
                    "sn": "SN123456789",
                    "model": "Sunsynk 8kW Hybrid",
                    "status": "online"
                },
                "realtime": {
                    "power": 3500,  # Current power in watts
                    "voltage": 230,
                    "current": 15.2,
                    "frequency": 50.0
                },
                "power_data": [],  # Would contain historical data
                "timestamp": datetime.now().isoformat(),
                "current_power_kw": 3.5,  # Convert W to kW
                "total_energy_kwh": 2456.8,  # Mock total energy
                "daily_energy_kwh": 28.4  # Mock daily energy
            }
            
            return mock_data
            
        except Exception as e:
            logger.error(f"Error getting Bertha House data: {str(e)}")
            return {}
    
    def _extract_current_power(self, realtime_data: Dict[str, Any]) -> float:
        """Extract current power in kW from real-time data"""
        try:
            # Look for power-related fields in the data
            # The exact field names may vary based on Sunsynk API response
            power_fields = ["power", "activePower", "totalPower", "currentPower"]
            
            for field in power_fields:
                if field in realtime_data:
                    power_watts = realtime_data[field]
                    return float(power_watts) / 1000  # Convert W to kW
            
            return 0.0
            
        except Exception as e:
            logger.error(f"Error extracting current power: {str(e)}")
            return 0.0
    
    def _calculate_total_energy(self, power_data: List[Dict[str, Any]]) -> float:
        """Calculate total energy in kWh from power data"""
        try:
            if not power_data:
                return 0.0
            
            total_energy_wh = 0.0
            
            for data_point in power_data:
                # Get power value in watts
                power_w = self._extract_power_from_data_point(data_point)
                
                # Each data point represents 5 minutes (300 seconds)
                # Energy (Wh) = Power (W) × Time (h)
                energy_wh = power_w * (5 / 60)  # 5 minutes = 5/60 hours
                total_energy_wh += energy_wh
            
            return total_energy_wh / 1000  # Convert Wh to kWh
            
        except Exception as e:
            logger.error(f"Error calculating total energy: {str(e)}")
            return 0.0
    
    def _calculate_daily_energy(self, power_data: List[Dict[str, Any]]) -> float:
        """Calculate today's energy in kWh from power data"""
        try:
            if not power_data:
                return 0.0
            
            today = datetime.now().date()
            daily_energy_wh = 0.0
            
            for data_point in power_data:
                # Check if data point is from today
                timestamp_str = data_point.get("timestamp", data_point.get("time"))
                if timestamp_str:
                    timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                    if timestamp.date() == today:
                        power_w = self._extract_power_from_data_point(data_point)
                        energy_wh = power_w * (5 / 60)  # 5 minutes = 5/60 hours
                        daily_energy_wh += energy_wh
            
            return daily_energy_wh / 1000  # Convert Wh to kWh
            
        except Exception as e:
            logger.error(f"Error calculating daily energy: {str(e)}")
            return 0.0
    
    def _extract_power_from_data_point(self, data_point: Dict[str, Any]) -> float:
        """Extract power in watts from a single data point"""
        power_fields = ["power", "activePower", "totalPower", "value"]
        
        for field in power_fields:
            if field in data_point:
                return float(data_point[field])
        
        return 0.0

# Global instance
sunsynk_service = SunsynkService()
