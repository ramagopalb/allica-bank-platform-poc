"""
Compliance-as-Code Module
Demonstrates: FCA regulatory compliance checks, OPA policy evaluation simulation,
audit trail management, Well-Architected Framework scoring, and
operational resilience requirements for Allica Bank regulated banking platform.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from enum import Enum
import re
import hashlib
import json


class ComplianceSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ComplianceFramework(str, Enum):
    FCA_OPERATIONAL_RESILIENCE = "FCA_Operational_Resilience"
    PCI_DSS = "PCI_DSS"
    ISO_27001 = "ISO_27001"
    NIST_CSF = "NIST_CSF"
    CIS_AZURE = "CIS_Azure"
    CIS_GCP = "CIS_GCP"
    AZURE_WAF = "Azure_WAF"


@dataclass
class ComplianceFinding:
    rule_id: str
    framework: ComplianceFramework
    severity: ComplianceSeverity
    resource: str
    description: str
    remediation: str
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "framework": self.framework.value,
            "severity": self.severity.value,
            "resource": self.resource,
            "description": self.description,
            "remediation": self.remediation,
            "passed": self.passed,
        }

    def is_blocking(self) -> bool:
        return not self.passed and self.severity in (
            ComplianceSeverity.CRITICAL, ComplianceSeverity.HIGH
        )


@dataclass
class ComplianceReport:
    scan_id: str
    target: str
    frameworks: list[ComplianceFramework]
    findings: list[ComplianceFinding] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
            "PASS": 0, "FAIL": 0,
        }
        for f in self.findings:
            if f.passed:
                counts["PASS"] += 1
            else:
                counts["FAIL"] += 1
                counts[f.severity.value] += 1
        return counts

    def has_blocking_failures(self) -> bool:
        return any(f.is_blocking() for f in self.findings)

    def compliance_score(self) -> float:
        if not self.findings:
            return 100.0
        passed = sum(1 for f in self.findings if f.passed)
        return (passed / len(self.findings)) * 100.0

    def findings_by_framework(self) -> dict[str, list[ComplianceFinding]]:
        result: dict[str, list[ComplianceFinding]] = {}
        for f in self.findings:
            key = f.framework.value
            result.setdefault(key, []).append(f)
        return result

    def critical_findings(self) -> list[ComplianceFinding]:
        return [f for f in self.findings
                if not f.passed and f.severity == ComplianceSeverity.CRITICAL]


# ---------------------------------------------------------------------------
# OPA-style policy evaluator (simulated)
# ---------------------------------------------------------------------------

class OPAPolicyEvaluator:
    """Simulate OPA policy evaluation for infrastructure resources."""

    BANKING_POLICIES = {
        "require_encryption_at_rest": {
            "description": "All storage resources must have encryption at rest enabled",
            "severity": ComplianceSeverity.CRITICAL,
            "framework": ComplianceFramework.FCA_OPERATIONAL_RESILIENCE,
        },
        "require_private_endpoints": {
            "description": "Databases must use private endpoints only",
            "severity": ComplianceSeverity.CRITICAL,
            "framework": ComplianceFramework.PCI_DSS,
        },
        "require_mfa_for_admin": {
            "description": "All admin roles must require MFA",
            "severity": ComplianceSeverity.HIGH,
            "framework": ComplianceFramework.ISO_27001,
        },
        "require_audit_logging": {
            "description": "All resources must have audit logging enabled",
            "severity": ComplianceSeverity.HIGH,
            "framework": ComplianceFramework.FCA_OPERATIONAL_RESILIENCE,
        },
        "require_resource_tags": {
            "description": "All resources must have environment, cost_centre, and owner tags",
            "severity": ComplianceSeverity.MEDIUM,
            "framework": ComplianceFramework.AZURE_WAF,
        },
        "deny_public_ip": {
            "description": "Resources must not have public IP addresses assigned",
            "severity": ComplianceSeverity.HIGH,
            "framework": ComplianceFramework.CIS_AZURE,
        },
        "require_backup_enabled": {
            "description": "Databases must have automated backup enabled",
            "severity": ComplianceSeverity.HIGH,
            "framework": ComplianceFramework.FCA_OPERATIONAL_RESILIENCE,
        },
        "require_tls_12_minimum": {
            "description": "All services must enforce TLS 1.2 minimum",
            "severity": ComplianceSeverity.CRITICAL,
            "framework": ComplianceFramework.PCI_DSS,
        },
    }

    def evaluate_resource(self, resource_type: str,
                          resource_config: dict[str, Any]) -> list[ComplianceFinding]:
        findings = []
        resource_name = resource_config.get("name", "unknown")

        # Check encryption at rest
        if resource_type in ("storage_account", "postgresql", "redis"):
            encrypted = resource_config.get("encryption_at_rest", False)
            policy = self.BANKING_POLICIES["require_encryption_at_rest"]
            findings.append(ComplianceFinding(
                rule_id="POL-001",
                framework=policy["framework"],
                severity=policy["severity"],
                resource=f"{resource_type}/{resource_name}",
                description=policy["description"],
                remediation="Enable encryption at rest using platform-managed or customer-managed keys",
                passed=encrypted,
            ))

        # Check private endpoint
        if resource_type in ("postgresql", "redis", "cosmos_db"):
            private_ep = resource_config.get("private_endpoint_enabled", False)
            policy = self.BANKING_POLICIES["require_private_endpoints"]
            findings.append(ComplianceFinding(
                rule_id="POL-002",
                framework=policy["framework"],
                severity=policy["severity"],
                resource=f"{resource_type}/{resource_name}",
                description=policy["description"],
                remediation="Configure private endpoint and disable public network access",
                passed=private_ep,
            ))

        # Check audit logging
        audit_log = resource_config.get("audit_logging_enabled", False)
        policy = self.BANKING_POLICIES["require_audit_logging"]
        findings.append(ComplianceFinding(
            rule_id="POL-004",
            framework=policy["framework"],
            severity=policy["severity"],
            resource=f"{resource_type}/{resource_name}",
            description=policy["description"],
            remediation="Enable diagnostic settings and send logs to Log Analytics workspace",
            passed=audit_log,
        ))

        # Check tags
        tags = resource_config.get("tags", {})
        required_tags = {"environment", "cost_centre", "owner"}
        has_required_tags = required_tags.issubset(set(tags.keys()))
        policy = self.BANKING_POLICIES["require_resource_tags"]
        findings.append(ComplianceFinding(
            rule_id="POL-005",
            framework=policy["framework"],
            severity=policy["severity"],
            resource=f"{resource_type}/{resource_name}",
            description=policy["description"],
            remediation=f"Add missing tags: {required_tags - set(tags.keys())}",
            passed=has_required_tags,
        ))

        # Check TLS
        if resource_type in ("app_service", "api_management", "load_balancer"):
            min_tls = resource_config.get("min_tls_version", "1.0")
            tls_ok = min_tls in ("1.2", "1.3")
            policy = self.BANKING_POLICIES["require_tls_12_minimum"]
            findings.append(ComplianceFinding(
                rule_id="POL-008",
                framework=policy["framework"],
                severity=policy["severity"],
                resource=f"{resource_type}/{resource_name}",
                description=policy["description"],
                remediation="Set minimum TLS version to 1.2 or higher",
                passed=tls_ok,
            ))

        # Check backup for databases
        if resource_type in ("postgresql", "cosmos_db"):
            backup = resource_config.get("backup_enabled", False)
            policy = self.BANKING_POLICIES["require_backup_enabled"]
            findings.append(ComplianceFinding(
                rule_id="POL-007",
                framework=policy["framework"],
                severity=policy["severity"],
                resource=f"{resource_type}/{resource_name}",
                description=policy["description"],
                remediation="Enable automated backup with geo-redundant storage",
                passed=backup,
            ))

        return findings


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------

@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    actor: str
    action: str
    resource: str
    outcome: str  # success / failure
    details: dict[str, Any] = field(default_factory=dict)
    ip_address: str = ""
    correlation_id: str = ""

    def checksum(self) -> str:
        data = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "outcome": self.outcome,
            "details": self.details,
            "ip_address": self.ip_address,
            "correlation_id": self.correlation_id,
        }

    def is_privileged_action(self) -> bool:
        privileged_actions = {
            "delete_resource", "modify_iam", "export_data",
            "disable_logging", "create_admin_role", "bypass_mfa",
        }
        return self.action in privileged_actions

    def requires_dual_approval(self) -> bool:
        high_risk_actions = {"delete_production", "modify_iam", "export_data"}
        return any(ha in self.action for ha in high_risk_actions)


class AuditTrailManager:
    def __init__(self):
        self._events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self._events.append(event)

    def get_privileged_events(self) -> list[AuditEvent]:
        return [e for e in self._events if e.is_privileged_action()]

    def get_failed_events(self) -> list[AuditEvent]:
        return [e for e in self._events if e.outcome == "failure"]

    def events_by_actor(self, actor: str) -> list[AuditEvent]:
        return [e for e in self._events if e.actor == actor]

    def total_events(self) -> int:
        return len(self._events)

    def compliance_summary(self) -> dict[str, int]:
        return {
            "total": self.total_events(),
            "privileged": len(self.get_privileged_events()),
            "failed": len(self.get_failed_events()),
        }


# ---------------------------------------------------------------------------
# FCA Operational Resilience checker
# ---------------------------------------------------------------------------

class FCAOperationalResilienceChecker:
    """
    Check platform configurations against FCA Operational Resilience requirements:
    - Important Business Services identified
    - Impact tolerances defined
    - Mapping of resources to services
    - Testing of resilience capabilities
    """

    REQUIRED_IMPACT_TOLERANCES = {
        "payment_processing": 4,     # hours max downtime
        "account_access": 4,
        "customer_onboarding": 24,
        "fraud_detection": 1,
        "regulatory_reporting": 72,
    }

    def __init__(self):
        self.important_business_services: list[str] = []
        self.impact_tolerances: dict[str, int] = {}
        self.resilience_tests: list[dict[str, Any]] = []

    def register_business_service(self, service_name: str,
                                   impact_tolerance_hours: int) -> None:
        self.important_business_services.append(service_name)
        self.impact_tolerances[service_name] = impact_tolerance_hours

    def record_resilience_test(self, service: str, test_type: str,
                                passed: bool, rto_achieved_hours: float) -> None:
        self.resilience_tests.append({
            "service": service,
            "test_type": test_type,
            "passed": passed,
            "rto_achieved_hours": rto_achieved_hours,
        })

    def validate_impact_tolerances(self) -> list[str]:
        issues = []
        for service, max_hours in self.REQUIRED_IMPACT_TOLERANCES.items():
            if service not in self.impact_tolerances:
                issues.append(f"FAIL: Impact tolerance not defined for '{service}'")
            elif self.impact_tolerances[service] > max_hours:
                issues.append(
                    f"FAIL: '{service}' tolerance {self.impact_tolerances[service]}h "
                    f"exceeds FCA maximum {max_hours}h"
                )
        return issues

    def validate_resilience_tests(self) -> list[str]:
        issues = []
        tested_services = {t["service"] for t in self.resilience_tests}
        for service in self.important_business_services:
            if service not in tested_services:
                issues.append(f"WARN: No resilience test recorded for '{service}'")
        failed_tests = [t for t in self.resilience_tests if not t["passed"]]
        for test in failed_tests:
            issues.append(
                f"FAIL: Resilience test failed for '{test['service']}' "
                f"({test['test_type']}) — RTO achieved: {test['rto_achieved_hours']}h"
            )
        return issues

    def is_fca_compliant(self) -> bool:
        all_issues = (
            self.validate_impact_tolerances() +
            self.validate_resilience_tests()
        )
        return not any(i.startswith("FAIL") for i in all_issues)

    def compliance_percentage(self) -> float:
        all_issues = (
            self.validate_impact_tolerances() +
            self.validate_resilience_tests()
        )
        fails = sum(1 for i in all_issues if i.startswith("FAIL"))
        total_checks = len(self.REQUIRED_IMPACT_TOLERANCES) + len(self.resilience_tests)
        if total_checks == 0:
            return 0.0
        passed = max(0, total_checks - fails)
        return (passed / total_checks) * 100.0
