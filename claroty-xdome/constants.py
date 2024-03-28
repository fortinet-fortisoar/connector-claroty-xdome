"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""
device_fields_to_check = ["device_type", "mac_oui_list", "model", "software_or_firmware_version", "purdue_level",
                          "known_vulnerabilities", "risk_score"]
device_format_dict = {"purdue_level": {"Level 1": 1, "Level 2": 2, "Level 3": 3, "Level 4": 4, "Level 5": 5}}

alert_fields_to_check = ["id", "category"]
ot_events_fields_to_check = ["event_id", "event_type", "dest_asset_id", "source_asset_id"]

vulnerability_fields_to_check = ["id", "name", "vulnerability_type", "cve_ids"]