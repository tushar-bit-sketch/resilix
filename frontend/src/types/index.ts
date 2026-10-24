/**
 * RESILIX TypeScript Domain & API Contracts
 * Seva First Innovation Challenge 2026 | Surakshit Bharat — Security & Resilience
 */

export type UserRole = 'admin' | 'operator';

export interface User {
  id: number;
  username: string;
  full_name: string;
  role: UserRole;
  last_login_at?: string | null;
}

export interface LoginResponse {
  user: User;
  csrf_token: string;
  session_expires_at: string;
  access_token: string;
}

export type OperationalStatus = 'HEALTHY' | 'WARNING' | 'CRITICAL' | 'OFFLINE' | 'DISABLED';
export type SensorHealthStatus = 'OK' | 'MISSING_SENSOR' | 'STALE_DATA' | 'IMPLAUSIBLE_READING' | 'INCONSISTENT_SIGNAL' | 'RECOVERED';
export type SeverityLevel = 'INFO' | 'WARNING' | 'CRITICAL';
export type AlertLifecycleState = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED';
export type ValidationState = 'ACCEPTED' | 'SUSPECT' | 'REJECTED';
export type SyncState = 'PENDING' | 'SYNCING' | 'SYNCED' | 'FAILED';

export interface Equipment {
  device_id: string;
  name: string;
  device_type: 'water_pump' | 'motor' | 'fan' | 'compressor' | 'sensor_rig';
  location: string;
  description: string;
  is_simulated: boolean;
  is_enabled: boolean;
  operational_status: OperationalStatus;
  sensor_health_status: SensorHealthStatus;
  has_current_sensor: boolean;
  temp_normal_min: number;
  temp_normal_max: number;
  temp_warning_threshold: number;
  temp_critical_threshold: number;
  vib_normal_min: number;
  vib_normal_max: number;
  vib_warning_threshold: number;
  vib_critical_threshold: number;
  current_normal_min: number;
  current_normal_max: number;
  current_warning_threshold: number;
  current_critical_threshold: number;
  persistence_window_count: number;
  last_sequence_number: number;
  last_telemetry_at?: string | null;
  latest_temperature?: number | null;
  latest_vibration?: number | null;
  latest_current?: number | null;
  most_recent_alert?: {
    alert_id: string;
    severity: SeverityLevel;
    title: string;
    lifecycle_state: AlertLifecycleState;
    last_seen_at: string;
  } | null;
}

export interface SensorReading {
  id: number;
  device_id: string;
  sequence_number: number;
  timestamp: string;
  received_at?: string;
  temperature: number | null;
  vibration: number | null;
  current_amps: number | null;
  validation_state?: ValidationState;
  validation_flags?: string[];
  simulation_mode?: string;
  scenario_name?: string;
  is_synthetic_anomaly?: boolean;
}

export interface AlertItem {
  alert_id: string;
  event_id: string;
  device_id: string;
  severity: SeverityLevel;
  alert_type: string;
  metric: string;
  title: string;
  description: string;
  explanation: string;
  recommended_action: string;
  rule_id: string;
  observed_value: number | null;
  threshold_value: number | null;
  lifecycle_state: AlertLifecycleState;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  acknowledged_by?: string | null;
  acknowledged_at?: string | null;
  resolved_by?: string | null;
  resolved_at?: string | null;
  resolution_note?: string | null;
  is_false_alert?: boolean;
}

export interface EventRecord {
  event_id: string;
  sequence_index: number;
  device_id: string | null;
  metric: string;
  event_category: string;
  event_type: string;
  severity: SeverityLevel;
  timestamp: string;
  observed_value: number | null;
  baseline_value?: number | null;
  threshold_value: number | null;
  deviation_score?: number | null;
  persistence_count?: number;
  rule_id: string;
  summary: string;
  explanation: string;
  recommended_action: string;
  event_source?: string;
  acknowledged: boolean;
  acknowledged_by?: string | null;
  acknowledged_at?: string | null;
  sync_state?: SyncState;
  event_hash?: string;
  previous_hash?: string;
  chain_index?: number;
  idempotency_key?: string;
  ack_id?: string | null;
}

export interface ScenarioDefinition {
  code: string;
  name: string;
  expected_behavior: string;
  proves: string;
  does_not_prove: string;
}

export interface SimulatorStatus {
  running: boolean;
  paused: boolean;
  speed_multiplier: number;
  active_scenario: string;
  active_scenario_info: ScenarioDefinition;
  target_device_id?: string | null;
  step_counter: number;
  last_tick_at?: string | null;
  available_scenarios: ScenarioDefinition[];
  truthfulness_notice: string;
}

export interface DashboardSummary {
  overall_health: OperationalStatus;
  total_equipment: number;
  healthy_equipment_count: number;
  warning_equipment_count: number;
  critical_equipment_count: number;
  disabled_equipment_count: number;
  active_alerts_count: number;
  sensor_health_issues_count: number;
  pending_sync_events_count: number;
  last_successful_sync_at?: string | null;
  sync_online: boolean;
  alert_severity_distribution: Record<SeverityLevel, number>;
  equipment_health_distribution: Record<string, number>;
  equipment_overview: Equipment[];
  simulator: SimulatorStatus;
  dashboard_refresh_seconds: number;
  timestamp: string;
}
