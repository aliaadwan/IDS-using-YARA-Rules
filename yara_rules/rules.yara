rule Detect_Custom_Synthetic_Malware {
    meta:
        description = "Matches a synthetic indicator included in test samples for validation of the IDS pipeline"
        author = "Students"
        severity = "High"
        date = "2025-11-26"

    strings:
         $marker = "SECRET_MALWARE_PROJECT_123_ATTACK" nocase ascii wide

    condition:
        $marker
}
rule Detect_Synthetic_HTTP_Test_Signature {
    meta:
        description = "Detects a synthetic HTTP-based test signature used to validate artifact extraction and YARA scanning"
        author = "Students"
        severity = "Medium"
        date = "2025-12-25"

    strings:
        $marker = "YARA_RULE_MATCH_0000" nocase ascii wide

    condition:
        $marker
}
