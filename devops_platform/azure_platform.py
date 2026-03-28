"""
Azure Platform Infrastructure Module
Demonstrates: AKS cluster config, VNet design, Azure Firewall rules, API Management,
Well-Architected Framework compliance checks for Allica Bank SME banking platform.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import re


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class AKSNodePool:
    name: str
    vm_size: str
    node_count: int
    min_count: int
    max_count: int
    os_disk_size_gb: int = 128
    enable_auto_scaling: bool = True
    availability_zones: list[str] = field(default_factory=lambda: ["1", "2", "3"])
    node_labels: dict[str, str] = field(default_factory=dict)
    taints: list[str] = field(default_factory=list)

    def validate(self) -> list[str]:
        errors = []
        if not re.match(r'^[a-z0-9]{1,12}$', self.name):
            errors.append(f"NodePool name '{self.name}' must be 1-12 lowercase alphanumeric chars")
        if self.node_count < self.min_count:
            errors.append(f"node_count {self.node_count} < min_count {self.min_count}")
        if self.node_count > self.max_count:
            errors.append(f"node_count {self.node_count} > max_count {self.max_count}")
        if self.min_count < 1:
            errors.append("min_count must be >= 1 for HA compliance")
        if len(self.availability_zones) < 3:
            errors.append("AKS node pool must span 3 AZs for banking HA requirements")
        if self.os_disk_size_gb < 100:
            errors.append("os_disk_size_gb must be >= 100 GB")
        return errors


@dataclass
class AKSClusterConfig:
    cluster_name: str
    resource_group: str
    location: str
    kubernetes_version: str
    node_pools: list[AKSNodePool] = field(default_factory=list)
    private_cluster: bool = True
    network_policy: str = "azure"
    load_balancer_sku: str = "standard"
    enable_rbac: bool = True
    azure_ad_integration: bool = True
    defender_enabled: bool = True
    oms_agent_enabled: bool = True
    tags: dict[str, str] = field(default_factory=dict)

    def validate_well_architected(self) -> dict[str, list[str]]:
        """Validate against Azure Well-Architected Framework for banking."""
        results: dict[str, list[str]] = {
            "security": [],
            "reliability": [],
            "operational_excellence": [],
            "performance_efficiency": [],
            "cost_optimization": [],
        }
        # Security pillar
        if not self.private_cluster:
            results["security"].append("FAIL: AKS cluster must be private for banking compliance")
        if not self.enable_rbac:
            results["security"].append("FAIL: RBAC must be enabled for FCA audit requirements")
        if not self.azure_ad_integration:
            results["security"].append("FAIL: Azure AD integration required for identity governance")
        if not self.defender_enabled:
            results["security"].append("FAIL: Microsoft Defender for Containers must be enabled")
        if self.network_policy not in ("azure", "calico"):
            results["security"].append(f"FAIL: network_policy '{self.network_policy}' not supported")
        # Reliability pillar
        if not any(len(np.availability_zones) >= 3 for np in self.node_pools):
            results["reliability"].append("FAIL: At least one node pool must span 3 AZs")
        system_pools = [np for np in self.node_pools if "system" in np.name.lower()]
        if not system_pools:
            results["reliability"].append("WARN: No dedicated system node pool found")
        # Operational Excellence
        if not self.oms_agent_enabled:
            results["operational_excellence"].append("FAIL: OMS agent required for observability")
        if not self.tags.get("environment"):
            results["operational_excellence"].append("WARN: Missing 'environment' tag")
        if not self.tags.get("cost_centre"):
            results["operational_excellence"].append("WARN: Missing 'cost_centre' tag for FinOps")
        return results

    def is_waf_compliant(self) -> bool:
        results = self.validate_well_architected()
        all_issues = []
        for issues in results.values():
            all_issues.extend([i for i in issues if i.startswith("FAIL")])
        return len(all_issues) == 0


@dataclass
class VNetConfig:
    name: str
    address_space: str
    location: str
    subnets: list[dict[str, Any]] = field(default_factory=list)
    enable_ddos_protection: bool = True
    dns_servers: list[str] = field(default_factory=list)

    def validate_cidr(self) -> bool:
        cidr_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')
        return bool(cidr_pattern.match(self.address_space))

    def get_subnet_names(self) -> list[str]:
        return [s["name"] for s in self.subnets]

    def has_required_subnets(self) -> bool:
        required = {"aks-subnet", "appgw-subnet", "firewall-subnet"}
        return required.issubset(set(self.get_subnet_names()))


@dataclass
class AzureFirewallRule:
    name: str
    priority: int
    action: str  # Allow / Deny
    protocol: str  # TCP / UDP / ICMP / Any
    source_addresses: list[str]
    destination_addresses: list[str]
    destination_ports: list[str]

    def validate(self) -> list[str]:
        errors = []
        if self.action not in ("Allow", "Deny"):
            errors.append(f"Invalid action: {self.action}")
        if self.protocol not in ("TCP", "UDP", "ICMP", "Any"):
            errors.append(f"Invalid protocol: {self.protocol}")
        if not 100 <= self.priority <= 65000:
            errors.append(f"Priority {self.priority} out of range [100, 65000]")
        if not self.source_addresses:
            errors.append("source_addresses cannot be empty")
        if not self.destination_addresses:
            errors.append("destination_addresses cannot be empty")
        return errors

    def is_deny_all_egress(self) -> bool:
        return (self.action == "Deny" and
                self.destination_addresses == ["*"] and
                self.source_addresses == ["*"])


# ---------------------------------------------------------------------------
# API Management helpers
# ---------------------------------------------------------------------------

@dataclass
class APIMPolicy:
    policy_name: str
    rate_limit_calls: int
    rate_limit_renewal_period: int  # seconds
    require_subscription_key: bool = True
    cors_origins: list[str] = field(default_factory=list)
    ip_filter_allow: list[str] = field(default_factory=list)

    def to_xml_snippet(self) -> str:
        return (
            f"<rate-limit calls=\"{self.rate_limit_calls}\" "
            f"renewal-period=\"{self.rate_limit_renewal_period}\" />"
        )

    def validate_for_banking(self) -> list[str]:
        issues = []
        if not self.require_subscription_key:
            issues.append("FAIL: Subscription key required for API management in banking")
        if self.rate_limit_calls > 1000:
            issues.append("WARN: Rate limit > 1000 calls — review for DDoS exposure")
        if "*" in self.cors_origins:
            issues.append("FAIL: Wildcard CORS origin not allowed in regulated environment")
        return issues


# ---------------------------------------------------------------------------
# Well-Architected Framework scorer
# ---------------------------------------------------------------------------

class WellArchitectedScorer:
    """Score a platform configuration against Azure WAF pillars."""

    PILLARS = ["security", "reliability", "operational_excellence",
               "performance_efficiency", "cost_optimization"]

    def score_cluster(self, config: AKSClusterConfig) -> dict[str, int]:
        waf = config.validate_well_architected()
        scores = {}
        for pillar in self.PILLARS:
            issues = waf.get(pillar, [])
            fails = sum(1 for i in issues if i.startswith("FAIL"))
            warns = sum(1 for i in issues if i.startswith("WARN"))
            score = max(0, 100 - (fails * 25) - (warns * 5))
            scores[pillar] = score
        return scores

    def overall_score(self, config: AKSClusterConfig) -> float:
        scores = self.score_cluster(config)
        return sum(scores.values()) / len(scores)

    def is_production_ready(self, config: AKSClusterConfig) -> bool:
        scores = self.score_cluster(config)
        return all(v >= 75 for v in scores.values())


# ---------------------------------------------------------------------------
# Multi-region deployment planner
# ---------------------------------------------------------------------------

class MultiRegionPlanner:
    AZURE_PAIRED_REGIONS = {
        "uksouth": "ukwest",
        "ukwest": "uksouth",
        "eastus": "westus",
        "westus": "eastus",
        "northeurope": "westeurope",
        "westeurope": "northeurope",
    }

    def __init__(self, primary_region: str):
        self.primary_region = primary_region.lower()

    def get_dr_region(self) -> str | None:
        return self.AZURE_PAIRED_REGIONS.get(self.primary_region)

    def validate_ha_configuration(self, cluster: AKSClusterConfig) -> bool:
        if cluster.location.lower() != self.primary_region:
            return False
        return cluster.is_waf_compliant()

    def generate_deployment_regions(self) -> list[str]:
        dr = self.get_dr_region()
        if dr:
            return [self.primary_region, dr]
        return [self.primary_region]

    def rpo_hours(self) -> float:
        """Estimated Recovery Point Objective for multi-region active-passive."""
        return 1.0

    def rto_hours(self) -> float:
        """Estimated Recovery Time Objective for multi-region active-passive."""
        return 4.0
