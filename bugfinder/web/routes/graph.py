from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from bugfinder.web.auth import get_current_user

router = APIRouter()

SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#6b7280",
}


@router.get("/graph")
async def full_graph(user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        scans = await repo.list_scans()
        return _build_graph(repo, scans)


@router.get("/graph/scan/{scan_id}")
async def scan_graph(scan_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        scan = await repo.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return _build_graph(repo, [scan])


@router.get("/graph/project/{project_id}")
async def project_graph(project_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        scans = await repo.list_scans(project_id=project_id)
        if not scans:
            raise HTTPException(status_code=404, detail="No scans found for this project")
        return _build_graph(repo, scans)


def _build_graph(repo: Any, scans: list[Any]) -> dict:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()

    for scan in scans:
        scan_id = f"scan_{scan.id}"
        if scan_id not in seen_nodes:
            seen_nodes.add(scan_id)
            status = _get_status(scan)
            nodes.append({
                "id": scan_id,
                "label": scan.target[:30],
                "group": "scan",
                "title": f"<b>{scan.target}</b><br>Status: {status}<br>Profile: {scan.profile}",
                "shape": "box",
                "color": "#059669",
                "font": {"color": "#f3f4f6", "size": 12},
                "size": 30,
                "metadata": {
                    "type": "scan",
                    "id": scan.id,
                    "target": scan.target,
                    "status": status,
                    "profile": scan.profile,
                },
            })

        findings = getattr(scan, "findings", [])
        for f in findings:
            f_id = f"finding_{f.id}"
            if f_id not in seen_nodes:
                seen_nodes.add(f_id)
                sev = _get_severity(f)
                color = SEVERITY_COLORS.get(sev, "#6b7280")
                nodes.append({
                    "id": f_id,
                    "label": f.title[:25],
                    "group": "finding",
                    "title": (
                        f"<b>{f.title}</b><br>"
                        f"Severity: <span style='color:{color}'>{sev.upper()}</span><br>"
                        f"Confidence: {_get_confidence(f)}<br>"
                        f"Category: {f.category or 'N/A'}<br>"
                        f"CWE: {f.cwe_id or 'N/A'}"
                    ),
                    "shape": "dot",
                    "color": color,
                    "font": {"color": "#f3f4f6", "size": 10},
                    "size": _severity_size(sev),
                    "metadata": {
                        "type": "finding",
                        "id": f.id,
                        "title": f.title,
                        "severity": sev,
                        "scan_id": scan.id,
                    },
                })
            edges.append({
                "from": scan_id,
                "to": f_id,
                "label": "finding",
                "color": {"color": "#4b5563", "opacity": 0.6},
                "font": {"size": 8, "color": "#6b7280"},
            })

            asset_id = getattr(f, "asset_id", None)
            if asset_id and f"asset_{asset_id}" not in seen_nodes:
                pass

        assets = getattr(scan, "assets", [])
        for asset in assets:
            a_id = f"asset_{asset.id}"
            if a_id not in seen_nodes:
                seen_nodes.add(a_id)
                nodes.append({
                    "id": a_id,
                    "label": asset.name[:25],
                    "group": "asset",
                    "title": f"<b>{asset.name}</b><br>Type: {asset.asset_type}",
                    "shape": "hexagon",
                    "color": "#6366f1",
                    "font": {"color": "#f3f4f6", "size": 11},
                    "size": 20,
                    "metadata": {
                        "type": "asset",
                        "id": asset.id,
                        "name": asset.name,
                        "asset_type": asset.asset_type,
                    },
                })
            edges.append({
                "from": scan_id,
                "to": a_id,
                "label": "asset",
                "color": {"color": "#4b5563", "opacity": 0.6},
                "font": {"size": 8, "color": "#6b7280"},
            })

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "scans": len(scans),
            "findings": sum(1 for n in nodes if n.get("group") == "finding"),
            "assets": sum(1 for n in nodes if n.get("group") == "asset"),
        },
    }


def _get_status(obj: Any) -> str:
    s = getattr(obj, "status", "unknown")
    return s.value if hasattr(s, "value") else str(s)


def _get_severity(obj: Any) -> str:
    s = getattr(obj, "severity", "info")
    return s.value if hasattr(s, "value") else str(s)


def _get_confidence(obj: Any) -> str:
    s = getattr(obj, "confidence", "medium")
    return s.value if hasattr(s, "value") else str(s)


def _severity_size(severity: str) -> int:
    return {"critical": 35, "high": 28, "medium": 22, "low": 16, "info": 12}.get(severity, 12)
