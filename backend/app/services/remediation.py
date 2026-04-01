"""
remediation.py — RemediationEngine for automated threat response.

Actions:
  BLOCK_IP        — iptables DROP on Linux; netsh log-only on Windows
  ALERT_ADMIN     — email alert via smtplib (requires SMTP env vars)
  LOG_AND_MONITOR — append structured entry to logs/threats.log

Configuration via environment variables:
  ADMIN_EMAIL   — recipient address for ALERT_ADMIN
  SMTP_HOST     — SMTP server hostname (default: localhost)
  SMTP_PORT     — SMTP server port    (default: 25)
  SMTP_USER     — SMTP login user     (optional)
  SMTP_PASS     — SMTP login password (optional)

Usage:
    from app.services.remediation import RemediationEngine
    engine = RemediationEngine()
    engine.execute(['BLOCK_IP', 'ALERT_ADMIN', 'LOG_AND_MONITOR'], log_line, threat_info)
"""

import os
import re
import logging
import platform
import smtplib
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

logger = logging.getLogger(__name__)

# threats.log is written two levels above this file: project_root/logs/threats.log
_LOG_DIR = Path(__file__).resolve().parent.parent.parent.parent / 'logs'
THREAT_LOG_PATH = _LOG_DIR / 'threats.log'

# IPs in these ranges are typically internal — skip external-IP-only blocking
_PRIVATE_PREFIXES = ('10.', '192.168.', '172.16.', '172.17.', '172.18.',
                     '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                     '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                     '172.29.', '172.30.', '172.31.', '127.', '0.0.0.0')


class RemediationEngine:
    """
    Execute remediation actions in response to detected threats.

    Each action method is independent — a failure in one does not
    prevent the others from running.
    """

    def __init__(
        self,
        admin_email: str = "",
        smtp_host:   str = "",
        smtp_port:   int = 0,
        smtp_user:   str = "",
        smtp_pass:   str = "",
    ):
        # Prefer constructor args; fall back to environment variables
        self.admin_email = admin_email or os.getenv('ADMIN_EMAIL', '')
        self.smtp_host   = smtp_host   or os.getenv('SMTP_HOST', 'localhost')
        self.smtp_port   = smtp_port   or int(os.getenv('SMTP_PORT', '25'))
        self.smtp_user   = smtp_user   or os.getenv('SMTP_USER', '')
        self.smtp_pass   = smtp_pass   or os.getenv('SMTP_PASS', '')
        self.is_windows  = platform.system() == 'Windows'

    # ── Public API ────────────────────────────────────────────────────────────

    def execute(self, actions: list, log_line: str, threat_info: dict):
        """
        Execute a list of remediation action names.

        Args:
            actions:     List of action strings, e.g. ['BLOCK_IP', 'ALERT_ADMIN']
            log_line:    The raw log line that triggered the threat
            threat_info: Dict returned by UpgradedAMIDES.predict()
        """
        for action in actions:
            try:
                if action == 'BLOCK_IP':
                    self._block_ip(log_line, threat_info)
                elif action == 'ALERT_ADMIN':
                    self._alert_admin(log_line, threat_info)
                elif action == 'LOG_AND_MONITOR':
                    self._log_and_monitor(log_line, threat_info)
                else:
                    logger.warning("[Remediation] Unknown action: %s", action)
            except Exception as exc:
                # Each action is isolated — log error and continue
                logger.error("[Remediation] Action %s failed: %s", action, exc)

    # ── Action implementations ────────────────────────────────────────────────

    def _block_ip(self, log_line: str, threat_info: dict):
        """
        Block the source IP extracted from the log line.

        Linux  : adds an iptables INPUT DROP rule (requires root).
        Windows: logs the intended block (netsh rules require elevation;
                 the entry is recorded in threats.log for manual action).
        """
        ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', log_line)
        if not ips:
            logger.debug("[BLOCK_IP] No IP addresses found in log line.")
            return

        # Prefer external (non-private) IPs; fall back to all found IPs
        external = [ip for ip in ips if not ip.startswith(_PRIVATE_PREFIXES)]
        targets  = external if external else ips

        for ip in targets[:3]:  # cap at 3 IPs per event to avoid runaway rules
            if self.is_windows:
                msg = f"[BLOCK_IP] Windows: manual firewall rule needed for {ip}"
                logger.info(msg)
                # Record the intended block so operators can act on it
                self._log_and_monitor(
                    log_line,
                    {**threat_info, 'note': f'BLOCK_IP logged (Windows): {ip}'},
                )
            else:
                cmd = f"iptables -I INPUT -s {ip} -j DROP"
                rc = os.system(cmd)
                if rc == 0:
                    logger.info("[BLOCK_IP] Blocked %s via iptables.", ip)
                else:
                    logger.warning(
                        "[BLOCK_IP] iptables returned %d for %s "
                        "(may require root privileges).", rc, ip
                    )

    def _alert_admin(self, log_line: str, threat_info: dict):
        """
        Send an email alert to the configured admin address.

        Requires ADMIN_EMAIL env var.  Silently skips if not set.
        """
        if not self.admin_email:
            logger.debug(
                "[ALERT_ADMIN] ADMIN_EMAIL not configured — skipping email alert."
            )
            return

        threat_type = threat_info.get('threat_type', 'UNKNOWN')
        severity    = threat_info.get('severity', '').upper()
        confidence  = threat_info.get('confidence', 0) * 100
        actions     = ', '.join(threat_info.get('remediation_actions', []))
        signals     = threat_info.get('top_signals') or []
        signal_text = '\n'.join(f"  {k}: {v}" for k, v in signals)

        subject = f"[THREAT ALERT] {threat_type} — {severity} | AI Log Analysis"
        body = (
            f"Threat Detection Alert\n"
            f"{'=' * 50}\n"
            f"Timestamp   : {datetime.now().isoformat()}\n"
            f"Threat Type : {threat_type}\n"
            f"Severity    : {severity}\n"
            f"Confidence  : {confidence:.1f}%\n"
            f"Actions     : {actions}\n"
            f"\nLog Line:\n  {log_line}\n"
            f"\nTop Signals:\n{signal_text}\n"
        )

        try:
            msg = EmailMessage()
            msg['From']    = self.smtp_user or 'siem@localhost'
            msg['To']      = self.admin_email
            msg['Subject'] = subject
            msg.set_content(body)

            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=5) as server:
                if self.smtp_user and self.smtp_pass:
                    server.login(self.smtp_user, self.smtp_pass)
                server.send_message(msg)

            logger.info("[ALERT_ADMIN] Alert sent to %s", self.admin_email)

        except Exception as exc:
            logger.warning("[ALERT_ADMIN] Email failed: %s", exc)

    def _log_and_monitor(self, log_line: str, threat_info: dict):
        """
        Append a structured threat entry to logs/threats.log.

        Format (pipe-delimited):
          ISO-timestamp | THREAT_TYPE | SEVERITY | conf=XX.X% | log_line
        """
        THREAT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

        threat_type = threat_info.get('threat_type', 'UNKNOWN')
        severity    = threat_info.get('severity', '').upper()
        confidence  = threat_info.get('confidence', 0) * 100
        # Truncate long log lines to keep the file manageable
        short_line  = log_line[:300].replace('\n', ' ').replace('\r', '')

        entry = (
            f"{datetime.now().isoformat()} | "
            f"{threat_type:<15} | "
            f"{severity:<8} | "
            f"conf={confidence:5.1f}% | "
            f"{short_line}\n"
        )

        try:
            with open(THREAT_LOG_PATH, 'a', encoding='utf-8') as fh:
                fh.write(entry)
            logger.debug("[LOG_AND_MONITOR] Written to %s", THREAT_LOG_PATH)
        except Exception as exc:
            logger.error("[LOG_AND_MONITOR] Write failed: %s", exc)
