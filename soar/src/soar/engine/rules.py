PLAYBOOK: dict[str, str] = {
    "SSH_BRUTEFORCE_001": "block_ip",
    "SMB_EXFIL_001": "block_ip",
    "MALICIOUS_FILE_EXEC_001": "notify",
}

RULE_TO_SCENARIO: dict[str, str] = {
    "SSH_BRUTEFORCE_001": "S1",
    "SMB_EXFIL_001": "S2",
    "MALICIOUS_FILE_EXEC_001": "S3",
}

SCENARIOS_EXPECTING_IP: set[str] = {"S1", "S2"}

WHITELIST: list[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]
