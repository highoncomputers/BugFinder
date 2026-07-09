from __future__ import annotations

import re

import httpx

from bugfinder.agents.base import AgentResult, BaseAgent

S3_BUCKET_PATTERNS = re.compile(
    r"(?:[a-zA-Z0-9.-]*\.s3(?:[.-]website)?[.-]?(?:us|eu|ap|sa|ca|me|af|cn)?(?:[a-z0-9-]+)?\.amazonaws\.com)",
    re.IGNORECASE,
)
CLOUD_PROVIDERS = {
    "aws": [
        "amazonaws.com",
        "s3.amazonaws.com",
        "cloudfront.net",
        "elb.amazonaws.com",
        "ec2.amazonaws.com",
    ],
    "azure": [
        "azurewebsites.net",
        "azurefd.net",
        "windows.net",
        "azureedge.net",
        "azure-api.net",
    ],
    "gcp": [
        "cloudfunctions.net",
        "appspot.com",
        "storage.googleapis.com",
        "firebaseio.com",
        "firebaserules.com",
    ],
}


class CloudAgent(BaseAgent):
    name = "cloud.detect"
    description = "Cloud provider and resource detection"

    async def execute(self) -> AgentResult:
        base_url = self.context.target
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        findings = []
        assets = []
        headers = {"User-Agent": "BugFinder/0.1.0"}

        async with httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False) as client:
            try:
                resp = await client.get(base_url, headers=headers)
                text = resp.text
                raw_headers = dict(resp.headers)
            except Exception:
                return AgentResult(
                    agent_name=self.name,
                    status="completed",
                    summary="Could not fetch target for cloud detection",
                )

            detected_providers = set()
            header_str = str(raw_headers).lower()

            for provider, domains in CLOUD_PROVIDERS.items():
                for domain in domains:
                    if domain in text.lower() or domain in header_str:
                        detected_providers.add(provider)
                        break

            server = raw_headers.get("server", "")
            if "cloudflare" in server.lower():
                detected_providers.add("cloudflare")

            for provider in detected_providers:
                assets.append(
                    {
                        "id": f"cloud-{provider}",
                        "name": provider.upper(),
                        "asset_type": "cloud_resource",
                        "value": f"Cloud provider detected: {provider}",
                        "properties": {"provider": provider, "target": base_url},
                    }
                )

            if "amazonaws" in text or "amazonaws" in header_str:
                buckets = set(S3_BUCKET_PATTERNS.findall(text))
                for bucket in buckets:
                    assets.append(
                        {
                            "id": f"s3-{hash(bucket) & 0xFFFFFFFF}",
                            "name": bucket,
                            "asset_type": "storage",
                            "value": "Potential S3 bucket referenced",
                            "properties": {"bucket_url": bucket},
                        }
                    )

            if "cloudflare" in detected_providers:
                findings.append(
                    {
                        "title": "Cloudflare CDN Detected",
                        "description": "Target is behind Cloudflare, which may hide the real origin IP",
                        "severity": "info",
                        "category": "cloud",
                        "evidence": {"provider": "cloudflare", "target": base_url},
                    }
                )

        for f in findings:
            f["id"] = f"cloud-finding-{findings.index(f)}"
        providers = ", ".join(detected_providers) if detected_providers else "none"
        summary = f"Cloud detection: {providers}, {len(assets)} resources"
        return AgentResult(
            agent_name=self.name,
            status="completed",
            assets=assets,
            findings=findings,
            summary=summary,
        )
