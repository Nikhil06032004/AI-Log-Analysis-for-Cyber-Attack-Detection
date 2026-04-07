"""
log_normalizer.py — Convert Windows Event Logs and Network Flow data
into text strings that UpgradedAMIDES can parse.

Functions:
    normalize_windows_event(event: dict) -> str
    normalize_network_flow(flow: dict) -> str
    normalize_syslog(line: str) -> str
"""

# ── Windows Event ID label map ────────────────────────────────────────────────

WINDOWS_EVENT_LABELS = {
    # Authentication
    4624: "successful_logon",
    4625: "failed_logon",
    4627: "group_membership_logon",
    4634: "logoff",
    4647: "user_initiated_logoff",
    4648: "logon_explicit_credentials",
    4740: "user_account_locked",
    4768: "kerberos_ticket_requested",
    4771: "kerberos_preauth_failed",
    4776: "ntlm_auth_attempted",
    # Privilege / escalation
    4672: "special_privileges_assigned",
    4673: "privileged_service_called",
    4674: "privileged_object_operation",
    # Process
    4688: "process_created",
    4689: "process_exited",
    # Scheduled tasks / persistence
    4698: "scheduled_task_created",
    4699: "scheduled_task_deleted",
    4700: "scheduled_task_enabled",
    4702: "scheduled_task_updated",
    # Account management
    4720: "user_account_created",
    4722: "user_account_enabled",
    4724: "password_reset_attempt",
    4728: "added_to_global_group",
    4732: "added_to_local_group",
    4756: "added_to_universal_group",
    # Object / file access
    4656: "object_handle_requested",
    4660: "object_deleted",
    4663: "object_access_attempt",
    4657: "registry_value_modified",
    # Services
    4697: "service_installed",
    7034: "service_crashed",
    7045: "new_service_installed",
    # Network share
    5140: "network_share_accessed",
    5145: "network_share_object_checked",
    # Windows Filtering Platform — network connections
    5156: "network_connection_allowed",
    5157: "network_connection_blocked",
    5158: "network_bind_allowed",
    5159: "network_bind_blocked",
    # Firewall rule changes
    4946: "firewall_rule_added",
    4947: "firewall_rule_modified",
    4948: "firewall_rule_deleted",
    5447: "wfp_filter_changed",
    # Log tampering (LOG_EVASION)
    1102: "audit_log_cleared",
    4719: "system_audit_policy_changed",
}

# Fields to extract from UserData / EventData dicts
_USERDATA_KEYS = [
    # Auth / account
    "TargetUserName", "SubjectUserName", "IpAddress", "IpPort",
    "LogonType", "ProcessName", "NewProcessName", "CommandLine",
    "ServiceName", "TaskName", "ObjectName", "FailureReason",
    "PrivilegeList", "ShareName", "ParentProcessName",
    # Network / WFP (EventID 5156 / 5157)
    "Application", "Direction", "SourceAddress", "SourcePort",
    "DestAddress", "DestPort", "Protocol", "FilterRTID",
    "LayerName", "RemoteUserID", "State", "Action", "ProcessID",
]

# Placeholder values that carry no information
_EMPTY_VALUES = {"-", "%%1832", "%%1833", "%%1834", "%%2313",
                 "%%2304", "%%2305", "N/A", "n/a", "null", "NULL", ""}

# ── Network protocol / port maps ──────────────────────────────────────────────

_PROTO_NUM_MAP = {
    "1": "icmp", "6": "tcp", "17": "udp",
    1: "icmp", 6: "tcp", 17: "udp",
}

_PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain_u", 80: "http", 110: "pop_3", 111: "sunrpc",
    119: "nntp", 143: "imap4", 443: "http_443", 445: "netbios_ssn",
    514: "shell", 587: "smtp", 993: "imap4", 995: "pop_3",
    1433: "sql_net", 3306: "sql_net", 3389: "X11",
    8080: "http", 8443: "http_443",
}

# NSL-KDD column order (41 columns, no label)
_NSLKDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

_NSLKDD_DEFAULTS = {
    "duration": 0, "protocol_type": "tcp", "service": "other",
    "flag": "SF", "src_bytes": 0, "dst_bytes": 0, "land": 0,
    "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0,
    "logged_in": 0, "num_compromised": 0, "root_shell": 0,
    "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
    "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
    "is_host_login": 0, "is_guest_login": 0, "count": 1, "srv_count": 1,
    "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
    "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
    "srv_diff_host_rate": 0.0, "dst_host_count": 1, "dst_host_srv_count": 1,
    "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
    "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
    "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
    "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
}


# ── Public API ────────────────────────────────────────────────────────────────

def normalize_windows_event(event: dict) -> str:
    """
    Convert a Windows Event Log entry (dict) into a syslog-style string
    that UpgradedAMIDES can parse and classify.

    Expected fields (all optional):
        EventID       — integer event code
        Source        — provider name (e.g. "Microsoft-Windows-Security-Auditing")
        Computer      — hostname
        TimeCreated   — ISO timestamp string
        Level         — "Information" | "Warning" | "Error" | "Critical"
        Message       — human-readable event message
        Keywords      — "Audit Success" | "Audit Failure" | ...
        UserData      — dict of event-specific fields (IpAddress, TargetUserName, etc.)
        EventData     — alias for UserData (some parsers use this key)

    Returns:
        A single-line syslog-style string, e.g.:
        "Security[4625]: warning failed_logon An account failed to log on.
         TargetUserName=administrator IpAddress=192.168.1.100 LogonType=3 host=PC01"
    """
    event_id  = int(event.get("EventID", 0))
    source    = event.get("Source", "Windows") or "Windows"
    computer  = event.get("Computer", "") or ""
    level     = (event.get("Level", "Information") or "Information").lower()
    message   = (event.get("Message", "") or "").replace("\n", " ").replace("\r", "").strip()
    keywords  = (event.get("Keywords", "") or "").lower()
    timestamp = (event.get("TimeCreated", "") or "")[:19]

    # EventData is an alias for UserData used by some Windows log parsers
    user_data = event.get("UserData") or event.get("EventData") or {}

    label = WINDOWS_EVENT_LABELS.get(event_id, f"event_{event_id}")

    # Decode WFP protocol numbers → name (EventID 5156/5157 Protocol field)
    proto_raw = str(user_data.get("Protocol", "")).strip()
    if proto_raw.isdigit():
        user_data = dict(user_data)   # don't mutate original
        user_data["Protocol"] = {"1": "icmp", "6": "tcp", "17": "udp"}.get(proto_raw, f"proto{proto_raw}")

    # Decode WFP direction codes
    direction_raw = str(user_data.get("Direction", "")).strip()
    if "%%14592" in direction_raw:
        user_data["Direction"] = "Inbound"
    elif "%%14593" in direction_raw:
        user_data["Direction"] = "Outbound"

    # Collect meaningful key=value pairs from UserData
    kv_parts = []
    for key in _USERDATA_KEYS:
        val = str(user_data.get(key, "")).strip()
        if val and val not in _EMPTY_VALUES:
            kv_parts.append(f"{key}={val}")

    # Build the normalized line — model input
    parts = [f"{source}[{event_id}:{label}]", level]
    if timestamp:
        parts.append(f"time={timestamp}")
    if "failure" in keywords or "fail" in keywords:
        parts.append("AUDIT_FAILURE")
    elif "success" in keywords:
        parts.append("AUDIT_SUCCESS")
    if message:
        parts.append(message[:300])
    parts.extend(kv_parts)
    if computer:
        parts.append(f"host={computer}")

    return " ".join(parts)


def normalize_network_flow(flow: dict) -> str:
    """
    Convert a network flow dict into a string UpgradedAMIDES can parse.

    If the dict already contains enough NSL-KDD column names (>=4 of the
    41 standard columns), it is serialised as a 41-column CSV row so the
    model's numerical NSL-KDD feature extractor fires properly.

    Otherwise the function produces a human-readable syslog-style line
    that activates the model's text-based feature extractors.

    Accepted input field names (flexible):
        src_ip / source_ip
        dst_ip / dest_ip / destination_ip
        src_port / sport
        dst_port / dport
        protocol / proto / protocol_type
        src_bytes / bytes_sent / bytes_out
        dst_bytes / bytes_received / bytes_in
        duration / dur
        flags / tcp_flags / flag
        service
        logged_in / authenticated
        — plus any NSL-KDD column name passed through directly
    """
    # Check for native NSL-KDD input
    nslkdd_overlap = sum(1 for col in _NSLKDD_COLUMNS if col in flow)
    if nslkdd_overlap >= 4:
        return _build_nslkdd_csv(flow)

    # Normalise field names
    proto_raw = (flow.get("protocol") or flow.get("proto")
                 or flow.get("protocol_type") or "tcp")
    proto     = _PROTO_NUM_MAP.get(proto_raw, str(proto_raw).lower())

    src_bytes = int(flow.get("src_bytes") or flow.get("bytes_sent")
                    or flow.get("bytes_out") or 0)
    dst_bytes = int(flow.get("dst_bytes") or flow.get("bytes_received")
                    or flow.get("bytes_in") or 0)
    duration  = float(flow.get("duration") or flow.get("dur") or 0)
    src_port  = int(flow.get("src_port") or flow.get("sport") or 0)
    dst_port  = int(flow.get("dst_port") or flow.get("dport") or 0)
    src_ip    = flow.get("src_ip") or flow.get("source_ip") or ""
    dst_ip    = (flow.get("dst_ip") or flow.get("dest_ip")
                 or flow.get("destination_ip") or "")
    flags     = str(flow.get("flags") or flow.get("tcp_flags")
                    or flow.get("flag") or "SF").upper()
    service   = flow.get("service") or _infer_service(dst_port, proto)
    logged_in = int(flow.get("logged_in") or flow.get("authenticated") or 0)

    # Build syslog-style representation
    parts = [f"NETWORK_FLOW proto={proto}"]
    if src_ip:
        parts.append(f"src={src_ip}:{src_port}")
    if dst_ip:
        parts.append(f"dst={dst_ip}:{dst_port}")
    parts.append(f"service={service}")
    parts.append(f"flags={flags}")
    parts.append(f"bytes_sent={src_bytes}")
    parts.append(f"bytes_recv={dst_bytes}")
    parts.append(f"duration={duration:.3f}s")
    if logged_in:
        parts.append("logged_in=1")

    # Passthrough NSL-KDD-style numeric hints if present
    for k in ("num_failed_logins", "count", "srv_count", "serror_rate",
              "rerror_rate", "num_compromised", "root_shell", "su_attempted",
              "num_shells", "num_file_creations"):
        if k in flow:
            parts.append(f"{k}={flow[k]}")

    return " ".join(parts)


def normalize_syslog(line: str) -> str:
    """
    Normalise a raw syslog line (collapse whitespace, strip control chars).

    No semantic transformation is applied — the model's syslog feature
    extractor handles the rest.
    """
    # Strip ANSI escape codes if present
    import re
    line = re.sub(r'\x1b\[[0-9;]*m', '', line)
    return " ".join(line.split())


# ── Internal helpers ──────────────────────────────────────────────────────────

def _infer_service(dst_port: int, proto: str) -> str:
    """Map a destination port to the closest NSL-KDD service name."""
    return _PORT_SERVICE_MAP.get(int(dst_port), "other")


def _build_nslkdd_csv(flow: dict) -> str:
    """
    Serialise a dict with NSL-KDD field names into a 41-column CSV string
    (no label column) compatible with UpgradedAMIDES.parse().
    """
    merged = {**_NSLKDD_DEFAULTS, **flow}
    return ",".join(
        str(merged.get(col, _NSLKDD_DEFAULTS.get(col, 0)))
        for col in _NSLKDD_COLUMNS
    )
