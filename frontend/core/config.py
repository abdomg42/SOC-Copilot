from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class AppConfig:
    api_base_url: str
    request_timeout_s: int
    default_alert_window_h: int
    max_table_rows: int


def load_config() -> AppConfig:
    base_url = os.getenv("SOC_API_BASE_URL", "http://localhost:8000").rstrip("/")
    timeout_s = int(os.getenv("SOC_API_TIMEOUT", "45"))
    default_hours = int(os.getenv("SOC_DEFAULT_HOURS", "24"))
    max_rows = int(os.getenv("SOC_MAX_TABLE_ROWS", "1500"))
    return AppConfig(
        api_base_url=base_url,
        request_timeout_s=timeout_s,
        default_alert_window_h=default_hours,
        max_table_rows=max_rows,
    )
