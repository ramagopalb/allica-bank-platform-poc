"""
Tests for Compliance-as-Code Module
Covers: OPA policy evaluation, compliance findings, audit trail management,
FCA operational resilience checks, compliance scoring.
"""
import pytest
from devops_platform.compliance import (
    ComplianceSeverity,
    ComplianceFramework,
    ComplianceFinding,
    ComplianceReport,
    OPAPolicyEvaluator,
    AuditEvent,
    AuditTrailManager,
    FCAOperationalResilienceChecker,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def compliant_postgresql():
    return {
        "name": "allica-postgres-prod",
        "encryption_at_rest": True,
        "private_endpoint_enabled": True,
        "audit_logging_enabled": True,
        "backup_enabled": True,
        "tags": {
            "environment": "production",
            "cost_centre": "platform",
            "owner": "platform-team",
        },
    }


@pytest.fixture
def evaluator():
    return OPAPolicyEvaluator()


@pytest.fixture
def fca_checker():
    checker = FCAOperationalResilienceChecker()
    checker.register_business_service("payment_processing", 4)
    checker.register_business_service("account_access", 4)
    checker.register_business_service("fraud_detection", 1)
    checker.register_business_service("customer_onboarding", 24)
    checker.register_business_service("regulatory_reporting", 72)
    return checker


@pytest.fixture
def audit_trail():
    return AuditTrailManager()


# ---------------------------------------------------------------------------
# Compliance Finding tests
# ---------------------------------------------------------------------------

class TestComplianceFinding:
    def test_passed_finding_not_blocking(self):
        finding = ComplianceFinding(
            rule_id="POL-001",
            framework=ComplianceFramework.FCA_OPERATIONAL_RESILIENCE,
            severity=ComplianceSeverity.CRITICAL,
            resource="storage/prod-bucket",
            description="Encryption at rest required",
            remediation="Enable encryption",
            passed=True,
        )
        assert not finding.is_blocking()

    def test_failed_critical_finding_is_blocking(self):
        finding = ComplianceFinding(
            rule_id="POL-001",
            framework=ComplianceFramework.FCA_OPERATIONAL_RESILIENCE,
            severity=ComplianceSeverity.CRITICAL,
            resource="storage/prod-bucket",
            description="Encryption at rest required",
            remediation="Enable encryption",
            passed=False,
        )
        assert finding.is_blocking()

    def test_failed_medium_finding_not_blocking(self):
        finding = ComplianceFinding(
            rule_id="POL-005",
            framework=ComplianceFramework.AZURE_WAF,
            severity=ComplianceSeverity.MEDIUM,
            resource="vm/web-server",
            description="Missing tags",
            remediation="Add required tags",
            passed=False,
        )
        assert not finding.is_blocking()

    def test_to_dict_contains_all_fields(self):
        finding = ComplianceFinding(
            rule_id="POL-001",
            framework=ComplianceFramework.PCI_DSS,
            severity=ComplianceSeverity.HIGH,
            resource="postgresql/main",
            description="Test",
            remediation="Fix it",
            passed=False,
        )
        d = finding.to_dict()
        assert d["rule_id"] == "POL-001"
        assert d["framework"] == "PCI_DSS"
        assert d["severity"] == "HIGH"
        assert d["passed"] is False


# ---------------------------------------------------------------------------
# Compliance Report tests
# ---------------------------------------------------------------------------

class TestComplianceReport:
    @pytest.fixture
    def mixed_report(self):
        findings = [
            ComplianceFinding("R1", ComplianceFramework.FCA_OPERATIONAL_RESILIENCE,
                              ComplianceSeverity.CRITICAL, "res1", "desc", "fix", passed=True),
            ComplianceFinding("R2", ComplianceFramework.PCI_DSS,
                              ComplianceSeverity.HIGH, "res2", "desc", "fix", passed=True),
            ComplianceFinding("R3", ComplianceFramework.ISO_27001,
                              ComplianceSeverity.CRITICAL, "res3", "desc", "fix", passed=False),
            ComplianceFinding("R4", ComplianceFramework.AZURE_WAF,
                              ComplianceSeverity.MEDIUM, "res4", "desc", "fix", passed=False),
        ]
        return ComplianceReport(
            scan_id="SCAN-001",
            target="allica-platform",
            frameworks=[ComplianceFramework.FCA_OPERATIONAL_RESILIENCE, ComplianceFramework.PCI_DSS],
            findings=findings,
        )

    def test_compliance_score_is_50_percent(self, mixed_report):
        assert mixed_report.compliance_score() == pytest.approx(50.0)

    def test_has_blocking_failures_when_critical_fails(self, mixed_report):
        assert mixed_report.has_blocking_failures()

    def test_summary_counts_correct(self, mixed_report):
        summary = mixed_report.summary()
        assert summary["PASS"] == 2
        assert summary["FAIL"] == 2
        assert summary["CRITICAL"] == 1

    def test_no_findings_scores_100(self):
        report = ComplianceReport(
            scan_id="SCAN-000",
            target="empty",
            frameworks=[],
            findings=[],
        )
        assert report.compliance_score() == 100.0

    def test_all_pass_no_blocking_failures(self):
        findings = [
            ComplianceFinding("R1", ComplianceFramework.FCA_OPERATIONAL_RESILIENCE,
                              ComplianceSeverity.CRITICAL, "res1", "desc", "fix", passed=True),
        ]
        report = ComplianceReport("S1", "target", [], findings)
        assert not report.has_blocking_failures()

    def test_findings_grouped_by_framework(self, mixed_report):
        by_fw = mixed_report.findings_by_framework()
        assert ComplianceFramework.FCA_OPERATIONAL_RESILIENCE.value in by_fw

    def test_critical_findings_returns_only_critical_failures(self, mixed_report):
        crits = mixed_report.critical_findings()
        assert all(f.severity == ComplianceSeverity.CRITICAL for f in crits)
        assert all(not f.passed for f in crits)


# ---------------------------------------------------------------------------
# OPA Policy Evaluator tests
# ---------------------------------------------------------------------------

class TestOPAPolicyEvaluator:
    def test_compliant_postgresql_all_pass(self, evaluator, compliant_postgresql):
        findings = evaluator.evaluate_resource("postgresql", compliant_postgresql)
        assert all(f.passed for f in findings)

    def test_no_encryption_fails(self, evaluator, compliant_postgresql):
        compliant_postgresql["encryption_at_rest"] = False
        findings = evaluator.evaluate_resource("postgresql", compliant_postgresql)
        encryption_findings = [f for f in findings if f.rule_id == "POL-001"]
        assert len(encryption_findings) > 0
        assert not encryption_findings[0].passed

    def test_no_private_endpoint_fails(self, evaluator, compliant_postgresql):
        compliant_postgresql["private_endpoint_enabled"] = False
        findings = evaluator.evaluate_resource("postgresql", compliant_postgresql)
        private_ep = [f for f in findings if f.rule_id == "POL-002"]
        assert len(private_ep) > 0
        assert not private_ep[0].passed

    def test_no_audit_logging_fails(self, evaluator, compliant_postgresql):
        compliant_postgresql["audit_logging_enabled"] = False
        findings = evaluator.evaluate_resource("postgresql", compliant_postgresql)
        audit_findings = [f for f in findings if f.rule_id == "POL-004"]
        assert len(audit_findings) > 0
        assert not audit_findings[0].passed

    def test_missing_tags_fails_medium_check(self, evaluator, compliant_postgresql):
        compliant_postgresql["tags"] = {}
        findings = evaluator.evaluate_resource("postgresql", compliant_postgresql)
        tag_findings = [f for f in findings if f.rule_id == "POL-005"]
        assert len(tag_findings) > 0
        assert not tag_findings[0].passed

    def test_no_backup_fails_for_database(self, evaluator, compliant_postgresql):
        compliant_postgresql["backup_enabled"] = False
        findings = evaluator.evaluate_resource("postgresql", compliant_postgresql)
        backup_findings = [f for f in findings if f.rule_id == "POL-007"]
        assert len(backup_findings) > 0
        assert not backup_findings[0].passed

    def test_app_service_tls_check(self, evaluator):
        resource = {
            "name": "allica-api",
            "min_tls_version": "1.0",
            "audit_logging_enabled": True,
            "tags": {"environment": "prod", "cost_centre": "api", "owner": "team"},
        }
        findings = evaluator.evaluate_resource("app_service", resource)
        tls_findings = [f for f in findings if f.rule_id == "POL-008"]
        assert len(tls_findings) > 0
        assert not tls_findings[0].passed

    def test_app_service_tls_12_passes(self, evaluator):
        resource = {
            "name": "allica-api",
            "min_tls_version": "1.2",
            "audit_logging_enabled": True,
            "tags": {"environment": "prod", "cost_centre": "api", "owner": "team"},
        }
        findings = evaluator.evaluate_resource("app_service", resource)
        tls_findings = [f for f in findings if f.rule_id == "POL-008"]
        assert all(f.passed for f in tls_findings)

    def test_critical_finding_has_remediation(self, evaluator, compliant_postgresql):
        compliant_postgresql["encryption_at_rest"] = False
        findings = evaluator.evaluate_resource("postgresql", compliant_postgresql)
        critical = [f for f in findings if not f.passed and
                    f.severity == ComplianceSeverity.CRITICAL]
        assert all(len(f.remediation) > 0 for f in critical)


# ---------------------------------------------------------------------------
# Audit Trail Manager tests
# ---------------------------------------------------------------------------

class TestAuditTrailManager:
    @pytest.fixture
    def populated_trail(self, audit_trail):
        events = [
            AuditEvent("E001", "2026-03-28T10:00:00Z", "engineer@allica.bank",
                       "deploy_service", "payment-api", "success",
                       correlation_id="CORR-001"),
            AuditEvent("E002", "2026-03-28T10:05:00Z", "admin@allica.bank",
                       "modify_iam", "iam/role/admin", "success",
                       correlation_id="CORR-002"),
            AuditEvent("E003", "2026-03-28T10:10:00Z", "engineer@allica.bank",
                       "deploy_service", "account-api", "failure",
                       correlation_id="CORR-003"),
            AuditEvent("E004", "2026-03-28T10:15:00Z", "auditor@allica.bank",
                       "delete_resource", "vm/test-server", "success",
                       correlation_id="CORR-004"),
        ]
        for event in events:
            audit_trail.record(event)
        return audit_trail

    def test_total_events_count(self, populated_trail):
        assert populated_trail.total_events() == 4

    def test_failed_events_returned(self, populated_trail):
        failed = populated_trail.get_failed_events()
        assert len(failed) == 1
        assert failed[0].event_id == "E003"

    def test_privileged_events_returned(self, populated_trail):
        privileged = populated_trail.get_privileged_events()
        actions = [e.action for e in privileged]
        assert "modify_iam" in actions

    def test_events_by_actor(self, populated_trail):
        events = populated_trail.events_by_actor("engineer@allica.bank")
        assert len(events) == 2

    def test_compliance_summary_keys(self, populated_trail):
        summary = populated_trail.compliance_summary()
        assert "total" in summary
        assert "privileged" in summary
        assert "failed" in summary

    def test_audit_event_checksum_deterministic(self):
        event = AuditEvent(
            event_id="E001",
            timestamp="2026-03-28T10:00:00Z",
            actor="engineer@allica.bank",
            action="deploy_service",
            resource="payment-api",
            outcome="success",
        )
        assert event.checksum() == event.checksum()

    def test_audit_event_is_privileged_action(self):
        event = AuditEvent("E001", "2026-03-28T10:00:00Z", "admin@allica.bank",
                           "modify_iam", "iam/roles", "success")
        assert event.is_privileged_action()

    def test_audit_event_non_privileged_action(self):
        event = AuditEvent("E001", "2026-03-28T10:00:00Z", "dev@allica.bank",
                           "read_logs", "logs/app", "success")
        assert not event.is_privileged_action()

    def test_audit_event_requires_dual_approval_for_prod_delete(self):
        event = AuditEvent("E001", "2026-03-28T10:00:00Z", "admin@allica.bank",
                           "delete_production", "production/cluster", "success")
        assert event.requires_dual_approval()

    def test_empty_trail_summary(self, audit_trail):
        summary = audit_trail.compliance_summary()
        assert summary["total"] == 0


# ---------------------------------------------------------------------------
# FCA Operational Resilience Checker tests
# ---------------------------------------------------------------------------

class TestFCAOperationalResilienceChecker:
    def test_unregistered_services_fail(self):
        checker = FCAOperationalResilienceChecker()
        issues = checker.validate_impact_tolerances()
        assert len(issues) > 0
        assert all(i.startswith("FAIL") for i in issues)

    def test_compliant_checker_passes_tolerance_validation(self, fca_checker):
        issues = fca_checker.validate_impact_tolerances()
        assert not any(i.startswith("FAIL") for i in issues)

    def test_tolerance_exceeding_fca_limit_fails(self, fca_checker):
        fca_checker.impact_tolerances["fraud_detection"] = 5  # exceeds 1h limit
        issues = fca_checker.validate_impact_tolerances()
        assert any("fraud_detection" in i for i in issues)

    def test_missing_resilience_test_warns(self, fca_checker):
        issues = fca_checker.validate_resilience_tests()
        # No tests recorded for any service
        assert any("WARN" in i for i in issues)

    def test_passed_resilience_tests_no_failures(self, fca_checker):
        for service in fca_checker.important_business_services:
            fca_checker.record_resilience_test(service, "failover", True, 0.5)
        issues = fca_checker.validate_resilience_tests()
        assert not any(i.startswith("FAIL") for i in issues)

    def test_failed_resilience_test_raises_fail(self, fca_checker):
        fca_checker.record_resilience_test("payment_processing", "chaos", False, 6.0)
        issues = fca_checker.validate_resilience_tests()
        assert any(i.startswith("FAIL") for i in issues)

    def test_fully_compliant_checker_passes(self, fca_checker):
        for service in fca_checker.important_business_services:
            fca_checker.record_resilience_test(service, "failover", True, 0.5)
        assert fca_checker.is_fca_compliant()

    def test_compliance_percentage_100_when_all_pass(self, fca_checker):
        for service in fca_checker.important_business_services:
            fca_checker.record_resilience_test(service, "failover", True, 0.5)
        score = fca_checker.compliance_percentage()
        assert score == pytest.approx(100.0)

    def test_compliance_percentage_above_zero_when_tolerances_set(self, fca_checker):
        for service in fca_checker.important_business_services:
            fca_checker.record_resilience_test(service, "failover", True, 0.5)
        score = fca_checker.compliance_percentage()
        assert score > 0

    def test_empty_checker_compliance_percentage_is_zero(self):
        checker = FCAOperationalResilienceChecker()
        score = checker.compliance_percentage()
        assert score == 0.0
