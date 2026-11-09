"""API client communicating with the FastAPI backend for the Streamlit dashboard."""

from typing import Any, Dict, List, Optional

import httpx


class ScannerAPIClient:
    """Client for FastAPI backend endpoints."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url.rstrip("/")
        self.api_v1 = f"{self.base_url}/api/v1"

    def check_health(self) -> Dict[str, Any]:
        """Check backend health status."""
        try:
            with httpx.Client(timeout=3.0) as client:
                res = client.get(f"{self.base_url}/health")
                if res.status_code == 200:
                    return res.json()
        except Exception as e:
            return {"status": "unreachable", "error": str(e)}
        return {"status": "unreachable"}

    def list_scans(self, skip: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch list of scans from backend."""
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(f"{self.api_v1}/scans?skip={skip}&limit={limit}")
                if res.status_code == 200:
                    return res.json().get("items", [])
        except Exception:
            pass
        return []

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve scan details by ID."""
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(f"{self.api_v1}/scans/{scan_id}")
                if res.status_code == 200:
                    return res.json()
        except Exception:
            pass
        return None

    def create_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger a new scan execution."""
        with httpx.Client(timeout=60.0) as client:
            res = client.post(f"{self.api_v1}/scans", json=payload)
            if res.status_code == 200:
                return res.json()
            return {"error": res.json().get("detail", res.text)}

    def list_all_findings(
        self,
        skip: int = 0,
        limit: int = 100,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        retest_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch all findings across scans with optional filters."""
        params: Dict[str, Any] = {"skip": skip, "limit": limit}
        if category:
            params["category"] = category
        if severity:
            params["severity"] = severity
        if retest_status:
            params["retest_status"] = retest_status

        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(f"{self.api_v1}/findings", params=params)
                if res.status_code == 200:
                    return res.json()
        except Exception:
            pass
        return []

    def get_findings(
        self,
        scan_id: str,
        category: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch findings for a scan with optional filters."""
        params = {}
        if category:
            params["category"] = category
        if severity:
            params["severity"] = severity

        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(f"{self.api_v1}/scans/{scan_id}/findings", params=params)
                if res.status_code == 200:
                    return res.json()
        except Exception:
            pass
        return []

    def retest_finding(self, finding_id: str) -> Dict[str, Any]:
        """Trigger retest for a specific finding."""
        try:
            with httpx.Client(timeout=15.0) as client:
                res = client.post(f"{self.api_v1}/findings/{finding_id}/retest")
                if res.status_code == 200:
                    return res.json()
                return {"error": res.text}
        except Exception as e:
            return {"error": str(e)}

    def get_report(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Fetch full JSON report."""
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(f"{self.api_v1}/scans/{scan_id}/report")
                if res.status_code == 200:
                    return res.json()
        except Exception:
            pass
        return None

    def get_csv_export(self, scan_id: str) -> Optional[str]:
        """Fetch CSV export string."""
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(f"{self.api_v1}/scans/{scan_id}/export.csv")
                if res.status_code == 200:
                    return res.text
        except Exception:
            pass
        return None

    def get_demo_config(self) -> Dict[str, Any]:
        """Fetch Demo RAG configuration status."""
        try:
            with httpx.Client(timeout=3.0) as client:
                res = client.get(f"{self.api_v1}/demo-rag/config")
                if res.status_code == 200:
                    return res.json()
        except Exception:
            pass
        return {"vulnerable_mode": True, "guardrails_active": False}

    def update_demo_config(self, vulnerable_mode: bool) -> Dict[str, Any]:
        """Update Demo RAG security posture."""
        try:
            with httpx.Client(timeout=3.0) as client:
                res = client.post(
                    f"{self.api_v1}/demo-rag/config",
                    json={"vulnerable_mode": vulnerable_mode},
                )
                if res.status_code == 200:
                    return res.json()
        except Exception as e:
            return {"error": str(e)}
        return {}

    def query_demo_rag(self, query: str, vulnerable_mode: Optional[bool] = None) -> Dict[str, Any]:
        """Query Demo RAG target."""
        payload: Dict[str, Any] = {"query": query}
        if vulnerable_mode is not None:
            payload["vulnerable_mode"] = vulnerable_mode

        try:
            with httpx.Client(timeout=10.0) as client:
                res = client.post(f"{self.api_v1}/demo-rag/query", json=payload)
                if res.status_code == 200:
                    return res.json()
                return {"error": res.text}
        except Exception as e:
            return {"error": str(e)}

    def detect_text(self, text: str, context: Optional[str] = None) -> Dict[str, Any]:
        """Send ad-hoc detection request."""
        payload = {"text": text}
        if context:
            payload["context"] = context

        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.post(f"{self.api_v1}/detect", json=payload)
                if res.status_code == 200:
                    return res.json()
        except Exception as e:
            return {"error": str(e)}
        return {}

    # -------------------------------------------------------------------------
    # PROJECTS & ONBOARDING CLIENT METHODS
    # -------------------------------------------------------------------------
    def get_onboarding_status(self) -> Dict[str, Any]:
        """Fetch onboarding completion status for user."""
        try:
            with httpx.Client(timeout=4.0) as client:
                res = client.get(f"{self.api_v1}/onboarding/status")
                if res.status_code == 200:
                    return res.json()
        except Exception:
            pass
        return {"is_completed": False, "selected_demo": False, "has_projects": False}

    def complete_onboarding(self, selected_demo: bool = False, project_id: Optional[str] = None) -> Dict[str, Any]:
        """Mark onboarding as complete for user."""
        payload = {"selected_demo": selected_demo, "project_id": project_id}
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.post(f"{self.api_v1}/onboarding/complete", json=payload)
                if res.status_code == 200:
                    return res.json()
        except Exception as e:
            return {"error": str(e)}
        return {"is_completed": True}

    def reset_onboarding(self) -> Dict[str, Any]:
        """Reset onboarding state."""
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.post(f"{self.api_v1}/onboarding/reset")
                if res.status_code == 200:
                    return res.json()
        except Exception as e:
            return {"error": str(e)}
        return {"is_completed": False}

    def list_projects(self, skip: int = 0, limit: int = 50, include_archived: bool = False) -> List[Dict[str, Any]]:
        """List projects for user."""
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(f"{self.api_v1}/projects?skip={skip}&limit={limit}&include_archived={include_archived}")
                if res.status_code == 200:
                    return res.json().get("items", [])
        except Exception:
            pass
        return []

    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve project details by ID."""
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(f"{self.api_v1}/projects/{project_id}")
                if res.status_code == 200:
                    return res.json()
        except Exception:
            pass
        return None

    def create_project(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create new project."""
        try:
            with httpx.Client(timeout=10.0) as client:
                res = client.post(f"{self.api_v1}/projects", json=payload)
                if res.status_code == 200:
                    return res.json()
                return {"error": res.json().get("detail", res.text)}
        except Exception as e:
            return {"error": str(e)}

    def update_project(self, project_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing project."""
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.patch(f"{self.api_v1}/projects/{project_id}", json=payload)
                if res.status_code == 200:
                    return res.json()
                return {"error": res.json().get("detail", res.text)}
        except Exception as e:
            return {"error": str(e)}

    def delete_project(self, project_id: str) -> Dict[str, Any]:
        """Delete project."""
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.delete(f"{self.api_v1}/projects/{project_id}")
                if res.status_code == 200:
                    return res.json()
                return {"error": res.text}
        except Exception as e:
            return {"error": str(e)}

    def verify_project_connection(
        self,
        project_id: str,
        override_req: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Trigger diagnostic connection verification."""
        try:
            with httpx.Client(timeout=15.0) as client:
                res = client.post(
                    f"{self.api_v1}/projects/{project_id}/verify-connection",
                    json=override_req or {},
                )
                if res.status_code == 200:
                    return res.json()
                return {"error": res.json().get("detail", res.text), "is_connected": False, "status": "ERROR"}
        except Exception as e:
            return {"error": str(e), "is_connected": False, "status": "ERROR"}

    def get_project_preferences(self, project_id: str) -> Dict[str, Any]:
        """Get project security preferences."""
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(f"{self.api_v1}/projects/{project_id}/preferences")
                if res.status_code == 200:
                    return res.json()
        except Exception:
            pass
        return {}

    def update_project_preferences(self, project_id: str, preferences: Dict[str, Any]) -> Dict[str, Any]:
        """Update project security preferences."""
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.patch(f"{self.api_v1}/projects/{project_id}/preferences", json=preferences)
                if res.status_code == 200:
                    return res.json()
                return {"error": res.text}
        except Exception as e:
            return {"error": str(e)}

