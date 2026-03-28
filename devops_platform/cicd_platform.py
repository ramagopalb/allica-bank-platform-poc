"""
CI/CD Platform Module
Demonstrates: Azure DevOps pipeline templates, GitHub Actions workflows,
self-service deployment guardrails, DORA metrics, canary deployments,
and security gate integration for Allica Bank platform engineering.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from enum import Enum
import re


class PipelineStage(str, Enum):
    LINT = "lint"
    UNIT_TEST = "unit_test"
    SECURITY_SCAN = "security_scan"
    BUILD = "build"
    INTEGRATION_TEST = "integration_test"
    COMPLIANCE_CHECK = "compliance_check"
    DEPLOY_STAGING = "deploy_staging"
    SMOKE_TEST = "smoke_test"
    DEPLOY_PRODUCTION = "deploy_production"
    ROLLBACK = "rollback"


@dataclass
class SecurityGate:
    tool: str  # trivy / checkov / opa / snyk / semgrep
    severity_threshold: str  # CRITICAL / HIGH / MEDIUM
    fail_on_findings: bool = True
    scan_target: str = "container_image"

    SUPPORTED_TOOLS = {"trivy", "checkov", "opa", "snyk", "semgrep", "tfsec"}

    def validate(self) -> list[str]:
        errors = []
        if self.tool not in self.SUPPORTED_TOOLS:
            errors.append(f"Unsupported security tool: {self.tool}")
        if self.severity_threshold not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            errors.append(f"Invalid severity threshold: {self.severity_threshold}")
        return errors

    def is_blocking(self) -> bool:
        return self.fail_on_findings and self.severity_threshold in ("CRITICAL", "HIGH")


@dataclass
class CanaryDeployment:
    service_name: str
    initial_weight: int = 10  # % traffic to canary
    increment_step: int = 20
    analysis_interval_minutes: int = 5
    error_rate_threshold: float = 0.01  # 1%
    latency_p99_threshold_ms: float = 500.0
    auto_promote: bool = True
    auto_rollback: bool = True

    def validate(self) -> list[str]:
        errors = []
        if not 1 <= self.initial_weight <= 50:
            errors.append("initial_weight must be 1-50%")
        if not 1 <= self.increment_step <= 50:
            errors.append("increment_step must be 1-50%")
        if self.error_rate_threshold <= 0 or self.error_rate_threshold >= 1:
            errors.append("error_rate_threshold must be between 0 and 1 exclusive")
        if self.latency_p99_threshold_ms <= 0:
            errors.append("latency_p99_threshold_ms must be > 0")
        if self.analysis_interval_minutes < 1:
            errors.append("analysis_interval_minutes must be >= 1")
        return errors

    def promotion_steps(self) -> list[int]:
        steps = []
        current = self.initial_weight
        while current < 100:
            steps.append(current)
            current = min(100, current + self.increment_step)
        steps.append(100)
        return steps

    def should_rollback(self, error_rate: float, latency_p99_ms: float) -> bool:
        return (error_rate > self.error_rate_threshold or
                latency_p99_ms > self.latency_p99_threshold_ms)


@dataclass
class PipelineTemplate:
    name: str
    stages: list[PipelineStage]
    security_gates: list[SecurityGate] = field(default_factory=list)
    environment_variables: dict[str, str] = field(default_factory=dict)
    timeout_minutes: int = 60
    parallel_jobs: int = 4

    def validate(self) -> list[str]:
        errors = []
        if not self.name:
            errors.append("Pipeline name cannot be empty")
        if PipelineStage.BUILD not in self.stages:
            errors.append("BUILD stage is mandatory")
        if PipelineStage.SECURITY_SCAN not in self.stages:
            errors.append("SECURITY_SCAN stage is mandatory for banking compliance")
        if PipelineStage.COMPLIANCE_CHECK not in self.stages:
            errors.append("COMPLIANCE_CHECK stage required for regulated environments")
        for gate in self.security_gates:
            errors.extend(gate.validate())
        if self.timeout_minutes < 10 or self.timeout_minutes > 480:
            errors.append("timeout_minutes must be between 10 and 480")
        if self.parallel_jobs < 1 or self.parallel_jobs > 20:
            errors.append("parallel_jobs must be between 1 and 20")
        return errors

    def has_blocking_security_gates(self) -> bool:
        return any(g.is_blocking() for g in self.security_gates)

    def get_mandatory_stages(self) -> list[PipelineStage]:
        return [
            PipelineStage.SECURITY_SCAN,
            PipelineStage.BUILD,
            PipelineStage.COMPLIANCE_CHECK,
        ]

    def missing_mandatory_stages(self) -> list[PipelineStage]:
        return [s for s in self.get_mandatory_stages() if s not in self.stages]

    def to_yaml_summary(self) -> str:
        lines = [
            f"pipeline: {self.name}",
            f"timeout: {self.timeout_minutes}m",
            f"parallel_jobs: {self.parallel_jobs}",
            "stages:",
        ]
        for stage in self.stages:
            lines.append(f"  - {stage.value}")
        if self.security_gates:
            lines.append("security_gates:")
            for gate in self.security_gates:
                lines.append(f"  - tool: {gate.tool}, threshold: {gate.severity_threshold}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# DORA metrics calculator
# ---------------------------------------------------------------------------

@dataclass
class DORAMetrics:
    deployment_frequency_per_day: float
    lead_time_hours: float
    mttr_hours: float
    change_failure_rate: float  # 0.0 - 1.0

    ELITE_THRESHOLDS = {
        "deployment_frequency_per_day": 1.0,    # >= daily
        "lead_time_hours": 24.0,                # < 24h
        "mttr_hours": 1.0,                      # < 1h
        "change_failure_rate": 0.05,            # < 5%
    }

    def performance_level(self) -> str:
        if (self.deployment_frequency_per_day >= self.ELITE_THRESHOLDS["deployment_frequency_per_day"] and
                self.lead_time_hours < self.ELITE_THRESHOLDS["lead_time_hours"] and
                self.mttr_hours < self.ELITE_THRESHOLDS["mttr_hours"] and
                self.change_failure_rate < self.ELITE_THRESHOLDS["change_failure_rate"]):
            return "Elite"
        if (self.deployment_frequency_per_day >= 0.142 and  # weekly
                self.lead_time_hours < 168 and              # < 1 week
                self.mttr_hours < 24 and
                self.change_failure_rate < 0.15):
            return "High"
        if (self.deployment_frequency_per_day >= 0.0333 and  # monthly
                self.lead_time_hours < 720 and               # < 1 month
                self.mttr_hours < 168 and
                self.change_failure_rate < 0.30):
            return "Medium"
        return "Low"

    def validate_values(self) -> list[str]:
        errors = []
        if self.deployment_frequency_per_day < 0:
            errors.append("deployment_frequency_per_day must be >= 0")
        if self.lead_time_hours < 0:
            errors.append("lead_time_hours must be >= 0")
        if self.mttr_hours < 0:
            errors.append("mttr_hours must be >= 0")
        if not 0.0 <= self.change_failure_rate <= 1.0:
            errors.append("change_failure_rate must be between 0.0 and 1.0")
        return errors

    def improvement_targets(self) -> dict[str, float]:
        level = self.performance_level()
        if level == "Elite":
            return {}
        targets = {}
        if self.deployment_frequency_per_day < 1.0:
            targets["deployment_frequency_per_day"] = 1.0
        if self.lead_time_hours >= 24.0:
            targets["lead_time_hours"] = 23.0
        if self.mttr_hours >= 1.0:
            targets["mttr_hours"] = 0.9
        if self.change_failure_rate >= 0.05:
            targets["change_failure_rate"] = 0.04
        return targets


# ---------------------------------------------------------------------------
# Self-service platform guardrails
# ---------------------------------------------------------------------------

@dataclass
class DeploymentRequest:
    team: str
    service_name: str
    target_environment: str  # dev / staging / production
    container_image: str
    replicas: int
    resource_limits: dict[str, str]  # cpu, memory
    approved_by: str = ""
    security_scan_passed: bool = False
    compliance_check_passed: bool = False

    VALID_ENVIRONMENTS = {"dev", "staging", "production"}
    PROD_MIN_REPLICAS = 3

    def validate(self) -> list[str]:
        errors = []
        if not self.team:
            errors.append("team is required")
        if not re.match(r'^[a-z0-9-]+$', self.service_name):
            errors.append("service_name must be lowercase alphanumeric and hyphens only")
        if self.target_environment not in self.VALID_ENVIRONMENTS:
            errors.append(f"Invalid environment: {self.target_environment}")
        if not self.container_image:
            errors.append("container_image is required")
        if self.replicas < 1:
            errors.append("replicas must be >= 1")
        if self.target_environment == "production":
            if self.replicas < self.PROD_MIN_REPLICAS:
                errors.append(f"Production requires >= {self.PROD_MIN_REPLICAS} replicas for HA")
            if not self.approved_by:
                errors.append("Production deployments require approval")
            if not self.security_scan_passed:
                errors.append("Security scan must pass before production deployment")
            if not self.compliance_check_passed:
                errors.append("Compliance check must pass before production deployment")
        if "cpu" not in self.resource_limits:
            errors.append("CPU resource limit is required")
        if "memory" not in self.resource_limits:
            errors.append("Memory resource limit is required")
        return errors

    def is_approved_for_production(self) -> bool:
        if self.target_environment != "production":
            return True
        return (bool(self.approved_by) and
                self.security_scan_passed and
                self.compliance_check_passed and
                self.replicas >= self.PROD_MIN_REPLICAS)
