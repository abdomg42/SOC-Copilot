from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests


class APIError(RuntimeError):
    """Raised when the backend API is unreachable or returns an error."""


class SOCAPIClient:
    def __init__(self, base_url: str, timeout_s: int = 45) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.session = requests.Session()

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=payload,
                timeout=self.timeout_s,
            )
        except requests.RequestException as exc:
            raise APIError(f"Request failed for {url}: {exc}") from exc

        try:
            data = response.json()
            if not isinstance(data, dict):
                data = {"data": data}
        except ValueError:
            data = {"detail": response.text}

        if not response.ok:
            detail = data.get("detail", f"HTTP {response.status_code}")
            raise APIError(f"API error on {path}: {detail}")

        return data

    def health(self) -> Dict[str, Any]:
        return self._request("GET", "/health")

    def analyze_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", "/analyze", payload=alert_payload)

    def chat(self, question: str, history: List[Dict[str, str]]) -> Dict[str, Any]:
        payload = {"question": question, "history": history}
        return self._request("POST", "/chat", payload=payload)

    def get_alerts(self, hours: int = 24, severity: str = "Toutes") -> Dict[str, Any]:
        params = {"hours": hours, "severity": severity}
        return self._request("GET", "/alerts", params=params)
