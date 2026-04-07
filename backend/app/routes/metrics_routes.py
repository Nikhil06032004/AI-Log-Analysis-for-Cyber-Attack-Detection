"""
metrics_routes.py — Real-time system resource metrics via psutil.

Endpoints:
  GET /api/metrics/live   — CPU, RAM, disk, network stats (call every 2–3 s)
  GET /api/metrics/disks  — all mounted disk partitions
"""

import time
import logging
import platform
from datetime import datetime, timezone

import psutil
from fastapi import APIRouter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/metrics", tags=["System Metrics"])

# ── Baseline for network delta (bytes per second) ────────────────────────────
_prev_net: dict = {}
_prev_ts: float = 0.0


def _net_delta() -> dict:
    """Return current network bytes/packets per second since last call."""
    global _prev_net, _prev_ts
    now   = time.monotonic()
    counters = psutil.net_io_counters(pernic=False)
    curr  = {
        "bytes_sent":   counters.bytes_sent,
        "bytes_recv":   counters.bytes_recv,
        "packets_sent": counters.packets_sent,
        "packets_recv": counters.packets_recv,
    }

    if _prev_ts and (now - _prev_ts) > 0:
        dt = now - _prev_ts
        result = {
            "bytes_sent_per_s":   round((curr["bytes_sent"]   - _prev_net.get("bytes_sent",   curr["bytes_sent"]))   / dt),
            "bytes_recv_per_s":   round((curr["bytes_recv"]   - _prev_net.get("bytes_recv",   curr["bytes_recv"]))   / dt),
            "packets_sent_per_s": round((curr["packets_sent"] - _prev_net.get("packets_sent", curr["packets_sent"])) / dt),
            "packets_recv_per_s": round((curr["packets_recv"] - _prev_net.get("packets_recv", curr["packets_recv"])) / dt),
            "bytes_sent_total":   curr["bytes_sent"],
            "bytes_recv_total":   curr["bytes_recv"],
        }
    else:
        result = {
            "bytes_sent_per_s": 0, "bytes_recv_per_s": 0,
            "packets_sent_per_s": 0, "packets_recv_per_s": 0,
            "bytes_sent_total": curr["bytes_sent"],
            "bytes_recv_total": curr["bytes_recv"],
        }

    _prev_net = curr
    _prev_ts  = now
    return result


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/live")
def get_live_metrics():
    """
    Returns a single snapshot of all key system resource metrics.
    Designed to be polled every 2–3 seconds from the frontend.
    """
    # CPU — interval=None uses non-blocking last reading (fast)
    cpu_percent   = psutil.cpu_percent(interval=None)
    cpu_per_core  = psutil.cpu_percent(interval=None, percpu=True)
    cpu_freq      = psutil.cpu_freq()
    cpu_count_log = psutil.cpu_count(logical=True)
    cpu_count_phy = psutil.cpu_count(logical=False)
    cpu_times     = psutil.cpu_times_percent(interval=None)

    # RAM
    vm = psutil.virtual_memory()
    sw = psutil.swap_memory()

    # Disk (root partition)
    disk_root = psutil.disk_usage("/")
    disk_io   = psutil.disk_io_counters()

    # All mounted partitions (summary)
    partitions = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            partitions.append({
                "device":      part.device,
                "mountpoint":  part.mountpoint,
                "fstype":      part.fstype,
                "total_gb":    round(usage.total / 1e9, 2),
                "used_gb":     round(usage.used  / 1e9, 2),
                "free_gb":     round(usage.free  / 1e9, 2),
                "percent":     usage.percent,
            })
        except PermissionError:
            pass

    # Network
    net = _net_delta()

    # Processes (top 8 by CPU)
    procs = []
    try:
        for p in sorted(
            psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]),
            key=lambda x: x.info.get("cpu_percent") or 0,
            reverse=True,
        )[:8]:
            procs.append({
                "pid":    p.info["pid"],
                "name":   p.info["name"],
                "cpu":    round(p.info.get("cpu_percent") or 0, 1),
                "mem":    round(p.info.get("memory_percent") or 0, 1),
                "status": p.info.get("status", ""),
            })
    except Exception:
        pass

    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "platform":  platform.system(),
        "hostname":  platform.node(),

        "cpu": {
            "percent":          round(cpu_percent, 1),
            "per_core":         [round(c, 1) for c in cpu_per_core],
            "count_logical":    cpu_count_log,
            "count_physical":   cpu_count_phy,
            "freq_mhz_current": round(cpu_freq.current, 0) if cpu_freq else None,
            "freq_mhz_max":     round(cpu_freq.max,     0) if cpu_freq else None,
            "user_pct":         round(cpu_times.user,   1),
            "system_pct":       round(cpu_times.system, 1),
            "idle_pct":         round(cpu_times.idle,   1),
        },

        "ram": {
            "total_gb":    round(vm.total    / 1e9, 2),
            "used_gb":     round(vm.used     / 1e9, 2),
            "available_gb":round(vm.available/ 1e9, 2),
            "percent":     vm.percent,
            "cached_gb":   round(getattr(vm, "cached", 0) / 1e9, 2),
            "swap_total_gb": round(sw.total  / 1e9, 2),
            "swap_used_gb":  round(sw.used   / 1e9, 2),
            "swap_percent":  sw.percent,
        },

        "disk": {
            "root_total_gb": round(disk_root.total / 1e9, 2),
            "root_used_gb":  round(disk_root.used  / 1e9, 2),
            "root_free_gb":  round(disk_root.free  / 1e9, 2),
            "root_percent":  disk_root.percent,
            "read_mb_total": round(disk_io.read_bytes  / 1e6, 1) if disk_io else 0,
            "write_mb_total":round(disk_io.write_bytes / 1e6, 1) if disk_io else 0,
            "partitions":    partitions,
        },

        "network": net,

        "top_processes": procs,
    }
