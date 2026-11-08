package integrity.pack

# Nurse Rachel Wisconsin Medicaid Personal Care Services Policy Pack (v1.0.0)
# Enforces statutory compliance across EVV, RN supervision, hospitalization holds,
# Prior Authorization (PA/RF) weekly unit caps, CMS-485 Plan of Care, Scope of Practice,
# and HIPAA BAA endpoint verification.

default decision := {
    "decision": "permit",
    "reason_code": "NR_COMPLIANT_PERMIT",
}

# 1. HIPAA § 164.502(e) & § 164.312(b): Non-BAA Endpoint Transmission Block
deny_reasons["NR_HIPAA_NON_BAA_ENDPOINT"] if {
    input.target_endpoint
    not input.baa_verified_endpoint
}

# 2. Scope-of-Practice Boundary (Wis. Stat. § 441.06): Prohibit Autonomous Prescribing / Diagnosis
unauthorized_keywords := {
    "prescribe",
    "prescription",
    "rx",
    "diagnose",
    "diagnosis",
    "titrate",
    "dosage adjustment",
    "stop taking medication",
}

deny_reasons["NR_CONTAIN_UNAUTHORIZED_MEDICAL_PRACTICE"] if {
    some kw in unauthorized_keywords
    contains(lower(input.serialized_args), kw)
}

# 3. 21st Century Cures Act § 12006(a): EVV 6 Statutory Elements & 250m Geofence
deny_reasons["NR_CURES_EVV_MISSING_STATUTORY_FIELDS"] if {
    input.event_class == "clinical.evv"
    not input.evv_six_elements_complete
}

deny_reasons["NR_CURES_EVV_GEOFENCE_BREACH"] if {
    input.event_class == "clinical.evv"
    input.gps_distance_meters > 250
    not input.cms_manual_edit_reason_code
}

# 4. Wis. Admin. Code § DHS 105.17(2)(b): 60-Day RN Supervisory Visit Clock
deny_reasons["NR_WI_DHS_105_17_SUPERVISORY_OVERDUE"] if {
    input.event_class == "clinical.claim"
    input.days_since_last_rn_supervisory_visit > 60
}

# 5. Wis. Admin. Code § DHS 107.112(4): Inpatient Hospitalization Billing Hold
deny_reasons["NR_WI_DHS_107_112_HOSPITAL_HOLD"] if {
    input.event_class == "clinical.claim"
    input.member_inpatient_admitted == true
}

# 6. Wis. Admin. Code § DHS 107.112(1)-(3): Prior Authorization (PA/RF) Weekly Unit Cap
deny_reasons["NR_WI_DHS_107_112_PA_UNIT_CAP_EXCEEDED"] if {
    input.event_class == "clinical.claim"
    input.weekly_units_requested + input.weekly_units_used > input.weekly_units_authorized
    not input.rn_override_cosigned
}

# 7. 42 CFR § 440.70 / ACA § 6407: Signed CMS-485 & Face-to-Face Encounter
deny_reasons["NR_ACA_6407_UNSIGNED_POC_OR_F2F"] if {
    input.event_class == "clinical.claim"
    not input.cms_485_physician_signed
}

deny_reasons["NR_ACA_6407_UNSIGNED_POC_OR_F2F"] if {
    input.event_class == "clinical.claim"
    not input.face_to_face_within_window
}

# Precedence resolution: DENY overrides PERMIT
decision := {
    "decision": "deny",
    "reason_code": code,
} if {
    count(deny_reasons) > 0
    codes := sort([c | some c in deny_reasons])
    code := codes[0]
}
