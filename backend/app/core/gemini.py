"""
NetSentinel - Gemini AI Integration

Uses the Google Gemini API to:
  • Analyze raw scan data and identify vulnerabilities
  • Generate plain-English remediation advisories
  • Perform compliance checks against golden baselines
"""

import json
import logging
from datetime import datetime
from typing import Optional

import google.generativeai as genai
from app.core.config import get_settings

logger = logging.getLogger(__name__)

VULNERABILITY_ANALYSIS_PROMPT = """You are NetSentinel, an expert network security analyst AI.
Analyze the following network scan results and identify potential vulnerabilities.

For each vulnerability found, provide:
1. A clear title
2. Severity level (critical/high/medium/low/info)
3. Which port/service is affected
4. A description of the risk
5. A relevant CVE ID if applicable

Scan Data:
{scan_data}

Respond in JSON format:
{{
  "vulnerabilities": [
    {{
      "title": "...",
      "severity": "...",
      "port": ...,
      "service": "...",
      "description": "...",
      "cve_id": "..." or null
    }}
  ]
}}
"""

REMEDIATION_PROMPT = """You are NetSentinel, an expert network security remediation advisor.
Given the following vulnerability findings for host {host_ip}, provide detailed,
actionable remediation steps that a system administrator can follow.

Use plain English. Be specific with commands and configuration changes where possible.
Group steps by priority (critical first).

Findings:
{findings}

Provide your response in this format:

## Severity Summary
- Critical: X
- High: X
- Medium: X
- Low: X

## Remediation Steps

### [Priority 1 - Critical]
**Issue:** ...
**Fix:** ...
**Commands:**
```
...
```

(repeat for each finding)

## Additional Recommendations
- ...
"""

COMPLIANCE_CHECK_PROMPT = """You are NetSentinel, a compliance auditing AI.
Compare the following scan results against the golden baseline configuration
and identify any deviations or non-compliance issues.

Scan Results:
{scan_data}

Golden Baseline Rules:
{baseline_rules}

For each rule, determine if the host is COMPLIANT or NON-COMPLIANT.
Provide specific details for any non-compliance.

Respond in JSON format:
{{
  "compliance_results": [
    {{
      "rule_id": "...",
      "rule_description": "...",
      "status": "compliant" or "non_compliant",
      "details": "...",
      "remediation": "..."
    }}
  ],
  "overall_score": 0-100,
  "summary": "..."
}}
"""


class GeminiClient:
    """Client for interacting with the Google Gemini API."""

    def __init__(self):
        settings = get_settings()
        self.api_key = settings.GEMINI_API_KEY
        self.model_name = settings.GEMINI_MODEL
        self._model = None

        if self.api_key:
            genai.configure(api_key=self.api_key)
            self._model = genai.GenerativeModel(self.model_name)
            logger.info(f"Gemini AI initialized with model: {self.model_name}")
        else:
            logger.warning("No GEMINI_API_KEY set. AI features will be unavailable.")

    @property
    def is_available(self) -> bool:
        return self._model is not None

    async def analyze_vulnerabilities(self, scan_data: dict) -> list[dict]:
        """
        Analyze scan data and return a list of identified vulnerabilities.
        """
        if not self.is_available:
            return self._fallback_vulnerability_analysis(scan_data)

        try:
            prompt = VULNERABILITY_ANALYSIS_PROMPT.format(
                scan_data=json.dumps(scan_data, indent=2, default=str)
            )
            response = await self._model.generate_content_async(prompt)
            text = response.text

            # Parse JSON from response (handle markdown code fences)
            text = text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1]
                text = text.rsplit("```", 1)[0]

            result = json.loads(text)
            return result.get("vulnerabilities", [])

        except Exception as e:
            logger.error(f"Gemini vulnerability analysis failed: {e}")
            return self._fallback_vulnerability_analysis(scan_data)

    async def generate_remediation(self, host_ip: str, findings: list[dict]) -> str:
        """
        Generate human-readable remediation steps for a set of findings.
        """
        if not self.is_available:
            return self._fallback_remediation(findings)

        try:
            prompt = REMEDIATION_PROMPT.format(
                host_ip=host_ip,
                findings=json.dumps(findings, indent=2, default=str)
            )
            response = await self._model.generate_content_async(prompt)
            return response.text

        except Exception as e:
            logger.error(f"Gemini remediation generation failed: {e}")
            return self._fallback_remediation(findings)

    async def check_compliance(self, scan_data: dict, baseline_rules: list[dict]) -> dict:
        """
        Check scan results against a golden baseline configuration.
        """
        if not self.is_available:
            return {"error": "AI features unavailable. Set GEMINI_API_KEY."}

        try:
            prompt = COMPLIANCE_CHECK_PROMPT.format(
                scan_data=json.dumps(scan_data, indent=2, default=str),
                baseline_rules=json.dumps(baseline_rules, indent=2, default=str)
            )
            response = await self._model.generate_content_async(prompt)
            text = response.text.strip()

            if text.startswith("```"):
                text = text.split("\n", 1)[1]
                text = text.rsplit("```", 1)[0]

            return json.loads(text)

        except Exception as e:
            logger.error(f"Gemini compliance check failed: {e}")
            return {"error": str(e)}

    # ─── Fallback Analysis (No API Key) ───────────────────────

    @staticmethod
    def _fallback_vulnerability_analysis(scan_data: dict) -> list[dict]:
        """
        Rule-based vulnerability detection when Gemini is unavailable.
        Checks for commonly insecure services and configurations.
        """
        vulnerabilities = []
        hosts = scan_data.get("hosts", [])

        RISKY_PORTS = {
            21: ("FTP Service Detected", "high",
                 "FTP transmits credentials in plaintext. Consider using SFTP/SCP instead."),
            23: ("Telnet Service Detected", "critical",
                 "Telnet is unencrypted. Replace with SSH immediately."),
            25: ("SMTP Open Relay Risk", "medium",
                 "Open SMTP services can be exploited for spam relay. Ensure authentication is required."),
            135: ("Windows RPC Exposed", "high",
                 "MSRPC exposure can lead to remote code execution. Restrict with firewall rules."),
            139: ("NetBIOS Session Service", "high",
                 "NetBIOS can leak host information. Disable if not required."),
            445: ("SMB Service Exposed", "high",
                 "SMB has been the target of major exploits (EternalBlue). Restrict access and patch."),
            1433: ("MSSQL Exposed", "high",
                 "Database services should not be directly exposed to the network."),
            3306: ("MySQL Exposed", "high",
                 "Database services should not be directly exposed to the network."),
            3389: ("RDP Service Detected", "high",
                 "RDP is a common attack vector. Use VPN/NLA and restrict access."),
            5432: ("PostgreSQL Exposed", "high",
                 "Database services should not be directly exposed to the network."),
            5900: ("VNC Service Detected", "high",
                 "VNC often lacks strong authentication. Use SSH tunneling instead."),
            6379: ("Redis Exposed", "critical",
                 "Redis without authentication allows remote code execution. Bind to localhost and set a password."),
            27017: ("MongoDB Exposed", "critical",
                 "MongoDB without authentication is a critical data exposure risk."),
        }

        for host in hosts:
            for port_info in host.get("ports", []):
                port_num = port_info.get("port_number") or port_info.get("port")
                if port_num in RISKY_PORTS:
                    title, severity, desc = RISKY_PORTS[port_num]
                    vulnerabilities.append({
                        "title": title,
                        "severity": severity,
                        "port": port_num,
                        "service": port_info.get("service_name") or port_info.get("service", ""),
                        "description": desc,
                        "cve_id": None,
                    })

        return vulnerabilities

    @staticmethod
    def _fallback_remediation(findings: list[dict]) -> str:
        """Generate basic remediation text when Gemini is unavailable."""
        lines = ["# Remediation Report (Rule-Based)\n"]
        lines.append("*Note: AI-powered analysis unavailable. Set GEMINI_API_KEY for detailed advisories.*\n")

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.append("## Severity Summary")
        for sev, count in severity_counts.items():
            lines.append(f"- {sev.title()}: {count}")
        lines.append("")

        lines.append("## Findings\n")
        for i, f in enumerate(findings, 1):
            lines.append(f"### {i}. {f.get('title', 'Unknown Issue')}")
            lines.append(f"**Severity:** {f.get('severity', 'info').upper()}")
            lines.append(f"**Description:** {f.get('description', 'N/A')}")
            lines.append("")

        return "\n".join(lines)


# Singleton instance
gemini_client = GeminiClient()
