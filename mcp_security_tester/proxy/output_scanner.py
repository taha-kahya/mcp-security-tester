import re

from mcp_security_tester.reports.models import Finding
from mcp_security_tester.static_analyzer.detectors import (
    detect_hidden_text,
    detect_secrecy_directive,
    detect_sensitive_path,
)

# Credential patterns: (signal_name, compiled_regex)
_CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("github_token",   re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("openai_key",     re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key",    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_secret", re.compile(r"(?i)(password|secret|token|api_key)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_\-]{16,}")),
]


class OutputScanner:
    def scan(self, tool_name: str, content: list) -> list[Finding]:
        """Scan MCP tool response content for injection payloads and credentials."""
        findings: list[Finding] = []
        for text in _extract_text(content):
            findings.extend(_scan_text(tool_name, text))
        return findings


def _extract_text(content: list) -> list[str]:
    """Pull all text strings out of an MCP content list."""
    texts: list[str] = []
    for item in content:
        if isinstance(item, dict):
            if item.get("type") == "text":
                texts.append(item.get("text", ""))
        elif hasattr(item, "text"):
            texts.append(item.text)
        elif hasattr(item, "model_dump"):
            d = item.model_dump()
            if d.get("type") == "text":
                texts.append(d.get("text", ""))
    return [t for t in texts if t]


def _scan_text(tool_name: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    field = "tool_output"

    for detector in [detect_secrecy_directive, detect_sensitive_path, detect_hidden_text]:
        result = detector(tool_name, field, text)
        if result:
            result.attack_type = "output_injection"
            findings.append(result)

    for signal_name, pattern in _CREDENTIAL_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(Finding(
                attack_type="output_injection",
                severity="CRITICAL",
                tool_name=tool_name,
                field=field,
                evidence=f"Credential pattern '{signal_name}' found: {match.group()[:40]}...",
                signal=f"credential_leak_{signal_name}",
                reproduction_steps=[
                    f"Call tool '{tool_name}'.",
                    f"Response contains a {signal_name} credential in plain text.",
                    "Credentials in tool outputs can be exfiltrated via subsequent injection attacks.",
                ],
            ))

    return findings
