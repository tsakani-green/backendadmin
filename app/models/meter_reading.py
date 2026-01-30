# app/models/meter_reading.py
from sqlalchemy import Column, Integer, Float, DateTime, String
from app.core.database import Base
from datetime import datetime

class MeterReading(Base):
    __tablename__ = "meter_readings"

    id = Column(Integer, primary_key=True, index=True)
    project_name = Column(String, index=True)      # "Bertha House"
    meter_name = Column(String, index=True)        # "Local Mains"
    ts_utc = Column(DateTime, index=True, default=datetime.utcnow)

    power_kw = Column(Float, nullable=False)
    energy_kwh_delta = Column(Float, nullable=True)
    cost_zar_delta = Column(Float, nullable=True)
