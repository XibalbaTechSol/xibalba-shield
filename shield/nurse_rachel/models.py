"""Clinical schemas and action models for Nurse Rachel."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class TriageUrgency(str, Enum):
    ROUTINE = "routine"
    URGENT = "urgent"
    IMMEDIATE_EMERGENCY = "immediate_emergency"


class ADLCategory(str, Enum):
    BATHING = "bathing"
    DRESSING = "dressing"
    GROOMING = "grooming"
    TOILETING = "toileting"
    TRANSFERRING = "transferring"
    EATING = "eating"
    MOBILITY = "mobility"
    MEDICATION_PROMPT = "medication_prompt"


class AssistanceLevel(str, Enum):
    INDEPENDENT = "independent"
    STANDBY_PROMPT = "standby_prompt"
    PARTIAL_PHYSICAL = "partial_physical"
    FULL_ASSISTANCE = "full_assistance"


class LogVitalsAction(BaseModel):
    """Log physiological vitals within standard clinical measurement bounds."""

    patient_token: str = Field(..., description="De-identified patient token")
    systolic_bp: Optional[int] = Field(None, ge=40, le=260, description="Systolic BP (mmHg)")
    diastolic_bp: Optional[int] = Field(None, ge=20, le=160, description="Diastolic BP (mmHg)")
    heart_rate_bpm: Optional[int] = Field(None, ge=30, le=240, description="Heart rate (BPM)")
    blood_glucose_mg_dl: Optional[int] = Field(None, ge=20, le=600, description="Blood glucose (mg/dL)")
    oxygen_saturation_pct: Optional[int] = Field(None, ge=50, le=100, description="SpO2 percentage")
    temperature_fahrenheit: Optional[float] = Field(None, ge=90.0, le=108.0, description="Body temp (F)")
    recorded_at: str = Field(..., description="ISO 8601 timestamp")

    @field_validator("diastolic_bp")
    @classmethod
    def validate_pulse_pressure(cls, v: Optional[int], info) -> Optional[int]:
        if v is not None and "systolic_bp" in info.data and info.data["systolic_bp"] is not None:
            if v >= info.data["systolic_bp"]:
                raise ValueError("Diastolic blood pressure must be lower than systolic blood pressure")
        return v


class RecordADLAction(BaseModel):
    """Record personal care activities of daily living (ADL) observations."""

    patient_token: str = Field(..., description="De-identified patient token")
    category: ADLCategory
    assistance_level: AssistanceLevel
    duration_minutes: int = Field(..., ge=1, le=480, description="Duration of personal care support")
    notes: str = Field(..., max_length=1000, description="Objective caregiver notes")
    observed_at: str = Field(..., description="ISO 8601 timestamp")


class QueryCarePlanAction(BaseModel):
    """Query authorized care plan and authorized hours under Medicaid LTC."""

    patient_token: str
    include_medication_list: bool = True
    include_authorized_hours: bool = True


class DispatchRNEscalationAction(BaseModel):
    """Escalate clinical findings to the supervising registered nurse."""

    patient_token: str
    urgency: TriageUrgency
    clinical_summary: str = Field(..., min_length=10, max_length=2000)
    vitals_snapshot: Optional[dict] = None
    suggested_nurse_followup: str = Field(..., max_length=500)
