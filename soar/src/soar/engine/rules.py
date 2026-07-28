PLAYBOOK: dict[str, str] = {
    "SSH_BRUTEFORCE_001": "block_ip",
    "SMB_EXFIL_001": "block_ip",
    "MALICIOUS_FILE_EXEC_001": "notify",
    "WEB_BRUTEFORCE_001": "block_ip",
    "SMB_MALICIOUS_FILE_001": "block_ip",
    "KERBEROASTING_001": "block_ip",
    "ASREP_ROASTING_001": "block_ip",
}

RULE_TO_SCENARIO: dict[str, str] = {
    "SSH_BRUTEFORCE_001": "S1",
    "SMB_EXFIL_001": "S2",
    "MALICIOUS_FILE_EXEC_001": "S3",
    "WEB_BRUTEFORCE_001": "S4",
    "SMB_MALICIOUS_FILE_001": "S5",
    "KERBEROASTING_001": "S6",
    "ASREP_ROASTING_001": "S6",
}

SCENARIOS_EXPECTING_IP: set[str] = {"S1", "S2", "S4", "S5", "S6"}

WHITELIST: list[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]
