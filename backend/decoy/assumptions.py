"""Every number that could not be sourced lives here, with a rationale. Provenance: SYNTHETIC.

The UI shows these under Compliance -> Assumptions; experiment E8 varies them by +-20%.
"""

ASSUMPTIONS = {
    "persons_per_household": {"value": 4.5, "why": "Urban India household size (Census order of magnitude)"},
    "water_lpcd": {"value": 135, "why": "CPHEEO urban supply norm used as demand basis (litres per capita per day)"},
    "hospital_litres_per_bed_day": {"value": 450, "why": "Typical tertiary-hospital design demand"},
    "hospital_min_pressure_m": {"value": 15.0, "why": "Head needed at the hospital connection for rooftop tanks / floors"},
    "zone_min_pressure_m": {"value": 10.0, "why": "Minimum residual head at consumer connection"},
    "required_pressure_m": {"value": 15.0, "why": "PDD full-service pressure"},
    "generator_autonomy_h": {"value": 8.0, "why": "Hospital backup diesel generator fuel autonomy"},
    "w_hospital_hour": {"value": 2500.0, "why": "One hospital-hour without water/power counted as 2500 household-hours (critical-service weight)"},
    "inr_per_household_hour": {"value": 70.0, "why": "Rough rupee value of one household losing water and power for an hour (value of lost service, order of magnitude)"},
    "w_mwh": {"value": 700.0, "why": "1 MWh unserved ~ 700 households for an hour at ~1.4 kWh/h"},
    "repair_h": {"plc": 8.0, "rtu": 6.0, "valve": 6.0, "breaker": 3.0, "breaker_lockout": 14.0, "bms": 4.0,
                 "why": "Time to restore a hijacked controller: forensic validation + re-flash + crew dispatch before it may return to service"},
    "ps2_local_duty": {"value": 0.5, "why": "PS2 level logic depends on SCADA radio telemetry; if SCADA link is cut the PLC runs a fixed 50% duty schedule"},
    "isolate_all_duty": {"value": 0.5, "why": "If every SCADA link is cut, PLCs revert to a fixed 50% duty pump schedule (demand-following logic and tank telemetry are lost)"},
    "p_patched_it": {"value": 0.35, "why": "Probability an inventory-listed IT device is actually already patched"},
    "p_patched_ot": {"value": 0.10, "why": "OT patching is rare (Dragos: most OT bugs wait for maintenance windows)"},
    "p_default_creds_iot": {"value": 0.45, "why": "CERT-In 20-city study: weak/unauthorised access is the most prevalent finding"},
    "p_unauth_remote": {"value": 0.50, "why": "CERT-In 2.3: Western India top weakness = remote connections allowed to unauthorised computers"},
    "mfa_factor": {"value": 0.12, "why": "Residual success probability of VPN credential abuse once MFA is enforced"},
    "fix_cost": {"virtual_patch": 1.0, "close_link": 1.5, "mfa_vendor": 2.0, "rotate_creds": 1.0, "firmware_patch": 6.0,
                 "monitoring": 3.0, "manual_fallback": 4.0, "why": "Relative effort units (CPG 2.0 style cost/ease), 1 = an hour of an engineer"},
    "lambda_downtime": {"value": 1.0, "why": "Exchange rate between effort units and household-hours of outage in the planner"},
}


def A(key, sub="value"):
    v = ASSUMPTIONS[key]
    return v[sub]
