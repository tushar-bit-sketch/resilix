"""
RESILIX Pydantic Schemas
Consistent request/response contracts with strict input validation.
"""
from typing import Any, Optional
from pydantic import BaseModel, Field, validator


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=6, max_length=128)


class UserOut(BaseModel):
    id: int
    username: str
    full_name: str
    role: str
    last_login_at: Optional[str] = None


class LoginResponse(BaseModel):
    user: UserOut
    csrf_token: str
    session_expires_at: str
    access_token: str


class EquipmentCreate(BaseModel):
    device_id: str = Field(..., min_length=3, max_length=32, regex=r"^[A-Z0-9_-]+$")
    name: str = Field(..., min_length=3, max_length=100)
    device_type: str = Field(..., regex=r"^(water_pump|motor|fan|compressor|sensor_rig)$")
    location: str = Field(..., min_length=2, max_length=120)
    description: str = Field(default="", max_length=500)
    is_simulated: bool = True
    is_enabled: bool = True
    has_current_sensor: bool = True
    temp_normal_min: float = Field(default=35.0, ge=-10.0, le=100.0)
    temp_normal_max: float = Field(default=50.0, ge=0.0, le=120.0)
    temp_warning_threshold: float = Field(default=58.0, ge=10.0, le=125.0)
    temp_critical_threshold: float = Field(default=68.0, ge=15.0, le=130.0)
    vib_normal_min: float = Field(default=1.0, ge=0.0, le=20.0)
    vib_normal_max: float = Field(default=3.0, ge=0.1, le=25.0)
    vib_warning_threshold: float = Field(default=4.5, ge=0.5, le=40.0)
    vib_critical_threshold: float = Field(default=7.0, ge=1.0, le=50.0)
    current_normal_min: float = Field(default=3.5, ge=0.0, le=50.0)
    current_normal_max: float = Field(default=6.5, ge=0.1, le=60.0)
    current_warning_threshold: float = Field(default=8.5, ge=0.5, le=80.0)
    current_critical_threshold: float = Field(default=11.0, ge=1.0, le=100.0)
    persistence_window_count: int = Field(default=2, ge=1, le=15)

    @validator("temp_normal_max")
    def check_temp_normal(cls, v: float, values: dict[str, Any]) -> float:
        if "temp_normal_min" in values and v <= values["temp_normal_min"]:
            raise ValueError("temp_normal_max must be greater than temp_normal_min")
        return v

    @validator("temp_warning_threshold")
    def check_temp_warn(cls, v: float, values: dict[str, Any]) -> float:
        if "temp_normal_max" in values and v <= values["temp_normal_max"]:
            raise ValueError("temp_warning_threshold must exceed temp_normal_max")
        return v

    @validator("temp_critical_threshold")
    def check_temp_crit(cls, v: float, values: dict[str, Any]) -> float:
        if "temp_warning_threshold" in values and v <= values["temp_warning_threshold"]:
            raise ValueError("temp_critical_threshold must exceed temp_warning_threshold")
        return v

    @validator("vib_normal_max")
    def check_vib_normal(cls, v: float, values: dict[str, Any]) -> float:
        if "vib_normal_min" in values and v <= values["vib_normal_min"]:
            raise ValueError("vib_normal_max must be greater than vib_normal_min")
        return v

    @validator("vib_warning_threshold")
    def check_vib_warn(cls, v: float, values: dict[str, Any]) -> float:
        if "vib_normal_max" in values and v <= values["vib_normal_max"]:
            raise ValueError("vib_warning_threshold must exceed vib_normal_max")
        return v

    @validator("vib_critical_threshold")
    def check_vib_crit(cls, v: float, values: dict[str, Any]) -> float:
        if "vib_warning_threshold" in values and v <= values["vib_warning_threshold"]:
            raise ValueError("vib_critical_threshold must exceed vib_warning_threshold")
        return v


class EquipmentUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=100)
    location: Optional[str] = Field(None, min_length=2, max_length=120)
    description: Optional[str] = Field(None, max_length=500)
    is_enabled: Optional[bool] = None
    has_current_sensor: Optional[bool] = None
    temp_warning_threshold: Optional[float] = Field(None, ge=10.0, le=125.0)
    temp_critical_threshold: Optional[float] = Field(None, ge=15.0, le=130.0)
    vib_warning_threshold: Optional[float] = Field(None, ge=0.5, le=40.0)
    vib_critical_threshold: Optional[float] = Field(None, ge=1.0, le=50.0)
    current_warning_threshold: Optional[float] = Field(None, ge=0.5, le=80.0)
    current_critical_threshold: Optional[float] = Field(None, ge=1.0, le=100.0)
    persistence_window_count: Optional[int] = Field(None, ge=1, le=15)


class MaintenanceNoteCreate(BaseModel):
    note_type: str = Field(default="INSPECTION", regex=r"^(INSPECTION|CALIBRATION|REPAIR|OBSERVATION)$")
    content: str = Field(..., min_length=5, max_length=1000)


class TelemetryIngestRequest(BaseModel):
    device_id: str = Field(..., min_length=3, max_length=32)
    timestamp: str
    sequence_number: int = Field(..., ge=1)
    temperature: Optional[float] = None
    vibration: Optional[float] = None
    current_amps: Optional[float] = None
    simulation_mode: str = Field(default="SIMULATED")
    scenario_name: str = Field(default="manual_ingest")
    is_synthetic_anomaly: bool = False
    integrity_signature: Optional[str] = None


class SimulatorControlRequest(BaseModel):
    speed_multiplier: Optional[float] = Field(default=1.0, ge=0.25, le=10.0)
    device_id: Optional[str] = None


class ScenarioTriggerRequest(BaseModel):
    scenario_code: str = Field(
        ...,
        regex=r"^(A_NORMAL|B_ELEVATED_VIBRATION|C_RISING_TEMPERATURE|D_MISSING_SENSOR|E_STALE_SENSOR|F_IMPLAUSIBLE_READING|G_INCONSISTENT_READING|H_NETWORK_OUTAGE|I_NETWORK_RECOVERY|J_SENSOR_RECOVERY)$",
    )
    device_id: str = Field(default="PUMP-01", min_length=3, max_length=32)
    steps: int = Field(default=4, ge=1, le=20)


class AlertAcknowledgeRequest(BaseModel):
    note: Optional[str] = Field(default="Acknowledged by operator for inspection.", max_length=500)


class AlertResolveRequest(BaseModel):
    resolution_note: str = Field(..., min_length=5, max_length=1000)
    is_false_alert: Optional[bool] = False


class SyncConnectivityRequest(BaseModel):
    online: bool
    simulate_transient_failure: bool = False


class SettingsUpdateRequest(BaseModel):
    app_name: Optional[str] = Field(None, min_length=2, max_length=64)
    stale_data_timeout_seconds: Optional[int] = Field(None, ge=5, le=3600)
    default_persistence_window: Optional[int] = Field(None, ge=1, le=15)
    simulator_interval_seconds: Optional[float] = Field(None, ge=0.5, le=60.0)
    max_simulator_speed: Optional[float] = Field(None, ge=1.0, le=10.0)
    event_retention_limit: Optional[int] = Field(None, ge=100, le=50000)
    sync_max_retries: Optional[int] = Field(None, ge=1, le=20)
    sync_backoff_base_seconds: Optional[float] = Field(None, ge=0.5, le=60.0)
    dashboard_refresh_seconds: Optional[int] = Field(None, ge=2, le=120)
    baseline_window_size: Optional[int] = Field(None, ge=5, le=200)
    baseline_min_samples: Optional[int] = Field(None, ge=3, le=50)
    device_thresholds: Optional[dict[str, dict[str, Any]]] = None

    @validator("baseline_min_samples")
    def validate_min_samples(cls, v: Optional[int], values: dict[str, Any]) -> Optional[int]:
        if v is not None and values.get("baseline_window_size") is not None:
            if v > values["baseline_window_size"]:
                raise ValueError("baseline_min_samples cannot exceed baseline_window_size")
        return v
