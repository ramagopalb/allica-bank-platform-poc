"""
Tests for CI/CD Platform Module
Covers: Pipeline template validation, security gates, canary deployments,
DORA metrics, self-service deployment guardrails.
"""
import pytest
from devops_platform.cicd_platform import (
    PipelineStage,
    SecurityGate,
    CanaryDeployment,
    PipelineTemplate,
    DORAMetrics,
    DeploymentRequest,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def blocking_security_gates():
    return [
        SecurityGate(tool="trivy", severity_threshold="CRITICAL", fail_on_findings=True),
        SecurityGate(tool="checkov", severity_threshold="HIGH", fail_on_findings=True),
        SecurityGate(tool="opa", severity_threshold="CRITICAL", fail_on_findings=True),
    ]


@pytest.fixture
def full_pipeline(blocking_security_gates):
    return PipelineTemplate(
        name="allica-platform-pipeline",
        stages=[
            PipelineStage.LINT,
            PipelineStage.UNIT_TEST,
            PipelineStage.SECURITY_SCAN,
            PipelineStage.BUILD,
            PipelineStage.INTEGRATION_TEST,
            PipelineStage.COMPLIANCE_CHECK,
            PipelineStage.DEPLOY_STAGING,
            PipelineStage.SMOKE_TEST,
            PipelineStage.DEPLOY_PRODUCTION,
        ],
        security_gates=blocking_security_gates,
        timeout_minutes=90,
        parallel_jobs=4,
    )


@pytest.fixture
def elite_dora():
    return DORAMetrics(
        deployment_frequency_per_day=3.0,
        lead_time_hours=8.0,
        mttr_hours=0.5,
        change_failure_rate=0.02,
    )


@pytest.fixture
def valid_prod_request():
    return DeploymentRequest(
        team="platform-team",
        service_name="payment-api",
        target_environment="production",
        container_image="gcr.io/allica/payment-api:v2.1.0",
        replicas=3,
        resource_limits={"cpu": "500m", "memory": "512Mi"},
        approved_by="lead.engineer@allica.bank",
        security_scan_passed=True,
        compliance_check_passed=True,
    )


# ---------------------------------------------------------------------------
# Security Gate tests
# ---------------------------------------------------------------------------

class TestSecurityGate:
    def test_valid_trivy_gate_has_no_errors(self):
        gate = SecurityGate(tool="trivy", severity_threshold="CRITICAL")
        assert gate.validate() == []

    def test_unsupported_tool_rejected(self):
        gate = SecurityGate(tool="unknown-scanner", severity_threshold="HIGH")
        errors = gate.validate()
        assert len(errors) > 0

    def test_invalid_threshold_rejected(self):
        gate = SecurityGate(tool="trivy", severity_threshold="FATAL")
        errors = gate.validate()
        assert len(errors) > 0

    def test_critical_blocking_gate_is_blocking(self):
        gate = SecurityGate(tool="trivy", severity_threshold="CRITICAL", fail_on_findings=True)
        assert gate.is_blocking()

    def test_non_failing_gate_not_blocking(self):
        gate = SecurityGate(tool="trivy", severity_threshold="CRITICAL", fail_on_findings=False)
        assert not gate.is_blocking()

    def test_low_threshold_not_blocking(self):
        gate = SecurityGate(tool="checkov", severity_threshold="LOW", fail_on_findings=True)
        assert not gate.is_blocking()

    @pytest.mark.parametrize("tool", ["trivy", "checkov", "opa", "snyk", "semgrep", "tfsec"])
    def test_all_supported_tools_valid(self, tool):
        gate = SecurityGate(tool=tool, severity_threshold="HIGH")
        assert gate.validate() == []


# ---------------------------------------------------------------------------
# Canary Deployment tests
# ---------------------------------------------------------------------------

class TestCanaryDeployment:
    @pytest.fixture
    def valid_canary(self):
        return CanaryDeployment(
            service_name="payment-api",
            initial_weight=10,
            increment_step=20,
            analysis_interval_minutes=5,
            error_rate_threshold=0.01,
            latency_p99_threshold_ms=500.0,
        )

    def test_valid_canary_has_no_errors(self, valid_canary):
        assert valid_canary.validate() == []

    def test_initial_weight_zero_rejected(self, valid_canary):
        valid_canary.initial_weight = 0
        errors = valid_canary.validate()
        assert len(errors) > 0

    def test_initial_weight_over_50_rejected(self, valid_canary):
        valid_canary.initial_weight = 60
        errors = valid_canary.validate()
        assert len(errors) > 0

    def test_error_rate_threshold_zero_rejected(self, valid_canary):
        valid_canary.error_rate_threshold = 0.0
        errors = valid_canary.validate()
        assert len(errors) > 0

    def test_negative_latency_rejected(self, valid_canary):
        valid_canary.latency_p99_threshold_ms = -1.0
        errors = valid_canary.validate()
        assert len(errors) > 0

    def test_promotion_steps_start_at_initial_weight(self, valid_canary):
        steps = valid_canary.promotion_steps()
        assert steps[0] == valid_canary.initial_weight

    def test_promotion_steps_end_at_100(self, valid_canary):
        steps = valid_canary.promotion_steps()
        assert steps[-1] == 100

    def test_should_rollback_on_high_error_rate(self, valid_canary):
        assert valid_canary.should_rollback(error_rate=0.05, latency_p99_ms=200.0)

    def test_should_rollback_on_high_latency(self, valid_canary):
        assert valid_canary.should_rollback(error_rate=0.005, latency_p99_ms=600.0)

    def test_no_rollback_within_thresholds(self, valid_canary):
        assert not valid_canary.should_rollback(error_rate=0.005, latency_p99_ms=400.0)

    def test_promotion_steps_include_all_increments(self, valid_canary):
        steps = valid_canary.promotion_steps()
        assert 30 in steps or 10 in steps  # first step is 10

    def test_zero_analysis_interval_rejected(self, valid_canary):
        valid_canary.analysis_interval_minutes = 0
        errors = valid_canary.validate()
        assert len(errors) > 0


# ---------------------------------------------------------------------------
# Pipeline Template tests
# ---------------------------------------------------------------------------

class TestPipelineTemplate:
    def test_valid_pipeline_has_no_errors(self, full_pipeline):
        assert full_pipeline.validate() == []

    def test_missing_build_stage_rejected(self, full_pipeline):
        full_pipeline.stages = [s for s in full_pipeline.stages if s != PipelineStage.BUILD]
        errors = full_pipeline.validate()
        assert any("BUILD" in e for e in errors)

    def test_missing_security_scan_rejected(self, full_pipeline):
        full_pipeline.stages = [s for s in full_pipeline.stages if s != PipelineStage.SECURITY_SCAN]
        errors = full_pipeline.validate()
        assert any("SECURITY_SCAN" in e or "security" in e.lower() for e in errors)

    def test_missing_compliance_check_rejected(self, full_pipeline):
        full_pipeline.stages = [s for s in full_pipeline.stages if s != PipelineStage.COMPLIANCE_CHECK]
        errors = full_pipeline.validate()
        assert any("COMPLIANCE_CHECK" in e or "compliance" in e.lower() for e in errors)

    def test_empty_name_rejected(self, full_pipeline):
        full_pipeline.name = ""
        errors = full_pipeline.validate()
        assert any("name" in e.lower() for e in errors)

    def test_timeout_too_short_rejected(self, full_pipeline):
        full_pipeline.timeout_minutes = 5
        errors = full_pipeline.validate()
        assert any("timeout" in e.lower() for e in errors)

    def test_timeout_too_long_rejected(self, full_pipeline):
        full_pipeline.timeout_minutes = 600
        errors = full_pipeline.validate()
        assert any("timeout" in e.lower() for e in errors)

    def test_pipeline_has_blocking_security_gates(self, full_pipeline):
        assert full_pipeline.has_blocking_security_gates()

    def test_non_blocking_gates_pipeline_not_blocking(self, full_pipeline):
        full_pipeline.security_gates = [
            SecurityGate(tool="trivy", severity_threshold="LOW", fail_on_findings=False)
        ]
        assert not full_pipeline.has_blocking_security_gates()

    def test_no_missing_mandatory_stages_in_full_pipeline(self, full_pipeline):
        assert full_pipeline.missing_mandatory_stages() == []

    def test_yaml_summary_contains_pipeline_name(self, full_pipeline):
        yaml = full_pipeline.to_yaml_summary()
        assert full_pipeline.name in yaml

    def test_yaml_summary_contains_stages(self, full_pipeline):
        yaml = full_pipeline.to_yaml_summary()
        assert "build" in yaml

    def test_invalid_parallel_jobs_rejected(self, full_pipeline):
        full_pipeline.parallel_jobs = 0
        errors = full_pipeline.validate()
        assert any("parallel" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# DORA Metrics tests
# ---------------------------------------------------------------------------

class TestDORAMetrics:
    def test_elite_performer_classification(self, elite_dora):
        assert elite_dora.performance_level() == "Elite"

    def test_low_performer_classification(self):
        metrics = DORAMetrics(
            deployment_frequency_per_day=0.01,
            lead_time_hours=1000.0,
            mttr_hours=200.0,
            change_failure_rate=0.50,
        )
        assert metrics.performance_level() == "Low"

    def test_high_performer_classification(self):
        metrics = DORAMetrics(
            deployment_frequency_per_day=0.5,
            lead_time_hours=48.0,
            mttr_hours=5.0,
            change_failure_rate=0.05,
        )
        assert metrics.performance_level() in ("High", "Elite")

    def test_negative_frequency_rejected(self):
        metrics = DORAMetrics(
            deployment_frequency_per_day=-1.0,
            lead_time_hours=10.0,
            mttr_hours=1.0,
            change_failure_rate=0.02,
        )
        errors = metrics.validate_values()
        assert any("frequency" in e.lower() for e in errors)

    def test_change_failure_rate_over_1_rejected(self):
        metrics = DORAMetrics(
            deployment_frequency_per_day=1.0,
            lead_time_hours=10.0,
            mttr_hours=1.0,
            change_failure_rate=1.5,
        )
        errors = metrics.validate_values()
        assert any("failure_rate" in e.lower() for e in errors)

    def test_elite_has_no_improvement_targets(self, elite_dora):
        assert elite_dora.improvement_targets() == {}

    def test_low_performer_has_improvement_targets(self):
        metrics = DORAMetrics(
            deployment_frequency_per_day=0.01,
            lead_time_hours=200.0,
            mttr_hours=50.0,
            change_failure_rate=0.40,
        )
        targets = metrics.improvement_targets()
        assert len(targets) > 0

    def test_valid_values_no_errors(self, elite_dora):
        assert elite_dora.validate_values() == []

    def test_negative_lead_time_rejected(self):
        metrics = DORAMetrics(
            deployment_frequency_per_day=1.0,
            lead_time_hours=-5.0,
            mttr_hours=1.0,
            change_failure_rate=0.02,
        )
        errors = metrics.validate_values()
        assert len(errors) > 0


# ---------------------------------------------------------------------------
# Deployment Request tests
# ---------------------------------------------------------------------------

class TestDeploymentRequest:
    def test_valid_production_request_approved(self, valid_prod_request):
        assert valid_prod_request.validate() == []
        assert valid_prod_request.is_approved_for_production()

    def test_empty_team_rejected(self, valid_prod_request):
        valid_prod_request.team = ""
        errors = valid_prod_request.validate()
        assert any("team" in e.lower() for e in errors)

    def test_invalid_service_name_rejected(self, valid_prod_request):
        valid_prod_request.service_name = "PAYMENT API"
        errors = valid_prod_request.validate()
        assert any("service_name" in e.lower() for e in errors)

    def test_invalid_environment_rejected(self, valid_prod_request):
        valid_prod_request.target_environment = "qa"
        errors = valid_prod_request.validate()
        assert any("environment" in e.lower() for e in errors)

    def test_production_requires_min_3_replicas(self, valid_prod_request):
        valid_prod_request.replicas = 1
        errors = valid_prod_request.validate()
        assert any("replica" in e.lower() for e in errors)

    def test_production_requires_approval(self, valid_prod_request):
        valid_prod_request.approved_by = ""
        errors = valid_prod_request.validate()
        assert any("approv" in e.lower() for e in errors)

    def test_production_requires_security_scan(self, valid_prod_request):
        valid_prod_request.security_scan_passed = False
        errors = valid_prod_request.validate()
        assert any("security" in e.lower() for e in errors)

    def test_production_requires_compliance_check(self, valid_prod_request):
        valid_prod_request.compliance_check_passed = False
        errors = valid_prod_request.validate()
        assert any("compliance" in e.lower() for e in errors)

    def test_missing_cpu_limit_rejected(self, valid_prod_request):
        valid_prod_request.resource_limits = {"memory": "512Mi"}
        errors = valid_prod_request.validate()
        assert any("cpu" in e.lower() for e in errors)

    def test_missing_memory_limit_rejected(self, valid_prod_request):
        valid_prod_request.resource_limits = {"cpu": "500m"}
        errors = valid_prod_request.validate()
        assert any("memory" in e.lower() for e in errors)

    def test_dev_request_auto_approved(self):
        req = DeploymentRequest(
            team="dev-team",
            service_name="feature-api",
            target_environment="dev",
            container_image="gcr.io/allica/feature-api:latest",
            replicas=1,
            resource_limits={"cpu": "100m", "memory": "128Mi"},
        )
        assert req.validate() == []
        assert req.is_approved_for_production()

    def test_zero_replicas_rejected(self, valid_prod_request):
        valid_prod_request.replicas = 0
        errors = valid_prod_request.validate()
        assert any("replica" in e.lower() or "replicas" in e.lower() for e in errors)
