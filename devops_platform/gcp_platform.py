"""
GCP Platform Infrastructure Module
Demonstrates: GKE cluster config, VPC design, Cloud Armor security policies,
Cloud Run serverless workloads, multi-region HA for Allica Bank platform engineering.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import re


@dataclass
class GKENodePool:
    name: str
    machine_type: str
    initial_node_count: int
    min_node_count: int
    max_node_count: int
    disk_size_gb: int = 100
    preemptible: bool = False
    spot: bool = False
    locations: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    taints: list[dict[str, str]] = field(default_factory=list)

    def validate(self) -> list[str]:
        errors = []
        if not re.match(r'^[a-z][a-z0-9-]{0,39}$', self.name):
            errors.append(f"NodePool name '{self.name}' invalid format")
        if self.initial_node_count < self.min_node_count:
            errors.append(f"initial_node_count {self.initial_node_count} < min_node_count")
        if self.initial_node_count > self.max_node_count:
            errors.append(f"initial_node_count {self.initial_node_count} > max_node_count")
        if self.disk_size_gb < 100:
            errors.append("disk_size_gb must be >= 100 GB")
        if len(self.locations) < 3:
            errors.append("Node pool should span >= 3 zones for HA")
        return errors

    def is_cost_optimised(self) -> bool:
        return self.spot or self.preemptible


@dataclass
class GKEClusterConfig:
    cluster_name: str
    project_id: str
    region: str
    network: str
    subnetwork: str
    node_pools: list[GKENodePool] = field(default_factory=list)
    private_cluster: bool = True
    master_ipv4_cidr_block: str = "172.16.0.0/28"
    enable_private_nodes: bool = True
    enable_workload_identity: bool = True
    enable_shielded_nodes: bool = True
    enable_binary_authorization: bool = True
    release_channel: str = "REGULAR"
    network_policy_enabled: bool = True
    database_encryption_key: str = ""
    labels: dict[str, str] = field(default_factory=dict)

    def validate_security(self) -> list[str]:
        issues = []
        if not self.private_cluster:
            issues.append("FAIL: GKE cluster must be private for banking workloads")
        if not self.enable_private_nodes:
            issues.append("FAIL: Private nodes required to prevent public IP exposure")
        if not self.enable_workload_identity:
            issues.append("FAIL: Workload Identity required for least-privilege service accounts")
        if not self.enable_shielded_nodes:
            issues.append("FAIL: Shielded nodes required for hardware-level security")
        if not self.enable_binary_authorization:
            issues.append("FAIL: Binary Authorization required for regulated workloads")
        if not self.network_policy_enabled:
            issues.append("FAIL: Network policy required for east-west traffic control")
        if not self.database_encryption_key:
            issues.append("WARN: No CMEK configured for etcd encryption at rest")
        if self.release_channel not in ("REGULAR", "STABLE"):
            issues.append(f"WARN: Release channel '{self.release_channel}' not recommended for prod")
        return issues

    def is_compliant(self) -> bool:
        issues = self.validate_security()
        return not any(i.startswith("FAIL") for i in issues)

    def terraform_resource_name(self) -> str:
        return f"google_container_cluster.{self.cluster_name.replace('-', '_')}"


@dataclass
class VPCConfig:
    name: str
    project_id: str
    auto_create_subnetworks: bool = False
    subnets: list[dict[str, Any]] = field(default_factory=list)
    shared_vpc_host: bool = False

    def validate(self) -> list[str]:
        errors = []
        if self.auto_create_subnetworks:
            errors.append("FAIL: auto_create_subnetworks must be false for controlled VPC design")
        subnet_names = [s["name"] for s in self.subnets]
        required = {"gke-subnet", "serverless-subnet"}
        missing = required - set(subnet_names)
        if missing:
            errors.append(f"WARN: Missing subnets: {', '.join(missing)}")
        return errors

    def get_secondary_ranges(self) -> list[dict[str, str]]:
        ranges = []
        for s in self.subnets:
            for sr in s.get("secondary_ip_ranges", []):
                ranges.append({"subnet": s["name"], **sr})
        return ranges


@dataclass
class CloudArmorPolicy:
    policy_name: str
    rules: list[dict[str, Any]] = field(default_factory=list)
    adaptive_protection_enabled: bool = True

    def has_owasp_ruleset(self) -> bool:
        return any("owasp" in str(r).lower() for r in self.rules)

    def has_rate_limiting(self) -> bool:
        return any(r.get("action") == "rate_based_ban" for r in self.rules)

    def has_deny_all_default(self) -> bool:
        for r in self.rules:
            if r.get("priority") == 2147483647 and r.get("action") == "deny(403)":
                return True
        return False

    def validate_for_banking(self) -> list[str]:
        issues = []
        if not self.has_owasp_ruleset():
            issues.append("FAIL: OWASP managed rules required for banking API protection")
        if not self.has_rate_limiting():
            issues.append("FAIL: Rate-based banning required to prevent credential stuffing")
        if not self.adaptive_protection_enabled:
            issues.append("WARN: Enable adaptive protection for DDoS mitigation")
        return issues


@dataclass
class CloudRunService:
    service_name: str
    region: str
    container_image: str
    min_instances: int = 1
    max_instances: int = 100
    allow_unauthenticated: bool = False
    vpc_connector: str = ""
    service_account: str = ""
    env_vars: dict[str, str] = field(default_factory=dict)
    secrets: list[str] = field(default_factory=list)

    def validate_security(self) -> list[str]:
        issues = []
        if self.allow_unauthenticated:
            issues.append("FAIL: Unauthenticated access not permitted in banking workloads")
        if not self.vpc_connector:
            issues.append("FAIL: VPC connector required for private network access")
        if not self.service_account:
            issues.append("FAIL: Dedicated service account required (no default compute SA)")
        if self.min_instances < 1:
            issues.append("WARN: min_instances=0 causes cold starts — undesirable for banking latency")
        return issues

    def is_compliant(self) -> bool:
        issues = self.validate_security()
        return not any(i.startswith("FAIL") for i in issues)


# ---------------------------------------------------------------------------
# Terraform module generator
# ---------------------------------------------------------------------------

class TerraformModuleGenerator:
    """Generate Terraform HCL snippets for GCP resources."""

    def gke_cluster_hcl(self, config: GKEClusterConfig) -> str:
        return f"""resource "google_container_cluster" "{config.cluster_name}" {{
  name     = "{config.cluster_name}"
  location = "{config.region}"
  project  = "{config.project_id}"

  network    = "{config.network}"
  subnetwork = "{config.subnetwork}"

  private_cluster_config {{
    enable_private_nodes    = {str(config.enable_private_nodes).lower()}
    enable_private_endpoint = true
    master_ipv4_cidr_block  = "{config.master_ipv4_cidr_block}"
  }}

  workload_identity_config {{
    workload_pool = "{config.project_id}.svc.id.goog"
  }}

  release_channel {{
    channel = "{config.release_channel}"
  }}

  remove_default_node_pool = true
  initial_node_count       = 1

  labels = {{
{chr(10).join(f'    {k} = "{v}"' for k, v in config.labels.items())}
  }}
}}"""

    def node_pool_hcl(self, cluster_name: str, pool: GKENodePool) -> str:
        return f"""resource "google_container_node_pool" "{pool.name}" {{
  name       = "{pool.name}"
  cluster    = google_container_cluster.{cluster_name}.name
  location   = google_container_cluster.{cluster_name}.location
  node_count = {pool.initial_node_count}

  autoscaling {{
    min_node_count = {pool.min_node_count}
    max_node_count = {pool.max_node_count}
  }}

  node_config {{
    machine_type = "{pool.machine_type}"
    disk_size_gb = {pool.disk_size_gb}
    spot         = {str(pool.spot).lower()}

    workload_metadata_config {{
      mode = "GKE_METADATA"
    }}

    shielded_instance_config {{
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }}
  }}
}}"""

    def vpc_hcl(self, config: VPCConfig) -> str:
        return f"""resource "google_compute_network" "{config.name}" {{
  name                    = "{config.name}"
  project                 = "{config.project_id}"
  auto_create_subnetworks = {str(config.auto_create_subnetworks).lower()}
}}"""
