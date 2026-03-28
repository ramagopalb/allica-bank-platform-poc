"""
Tests for GCP Platform Infrastructure Module
Covers: GKE cluster security validation, VPC config, Cloud Armor policies,
Cloud Run service compliance, Terraform HCL generation.
"""
import pytest
from devops_platform.gcp_platform import (
    GKENodePool,
    GKEClusterConfig,
    VPCConfig,
    CloudArmorPolicy,
    CloudRunService,
    TerraformModuleGenerator,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def valid_gke_pool():
    return GKENodePool(
        name="main-pool",
        machine_type="n2-standard-4",
        initial_node_count=3,
        min_node_count=3,
        max_node_count=9,
        disk_size_gb=100,
        locations=["europe-west2-a", "europe-west2-b", "europe-west2-c"],
    )


@pytest.fixture
def valid_gke_cluster(valid_gke_pool):
    return GKEClusterConfig(
        cluster_name="allica-gke-prod",
        project_id="allica-platform-prod",
        region="europe-west2",
        network="vpc-platform-prod",
        subnetwork="gke-subnet",
        node_pools=[valid_gke_pool],
        private_cluster=True,
        enable_private_nodes=True,
        enable_workload_identity=True,
        enable_shielded_nodes=True,
        enable_binary_authorization=True,
        network_policy_enabled=True,
        database_encryption_key="projects/allica/locations/global/keyRings/platform/cryptoKeys/gke",
        labels={"environment": "production", "team": "platform"},
    )


@pytest.fixture
def valid_vpc():
    return VPCConfig(
        name="vpc-platform-prod",
        project_id="allica-platform-prod",
        auto_create_subnetworks=False,
        subnets=[
            {
                "name": "gke-subnet",
                "region": "europe-west2",
                "ip_cidr_range": "10.0.0.0/20",
                "secondary_ip_ranges": [
                    {"range_name": "pods", "ip_cidr_range": "10.4.0.0/14"},
                    {"range_name": "services", "ip_cidr_range": "10.8.0.0/20"},
                ],
            },
            {"name": "serverless-subnet", "region": "europe-west2", "ip_cidr_range": "10.1.0.0/28"},
        ],
    )


# ---------------------------------------------------------------------------
# GKE Node Pool tests
# ---------------------------------------------------------------------------

class TestGKENodePool:
    def test_valid_pool_has_no_errors(self, valid_gke_pool):
        assert valid_gke_pool.validate() == []

    def test_invalid_name_rejected(self):
        pool = GKENodePool(
            name="INVALID_POOL",
            machine_type="n2-standard-4",
            initial_node_count=3,
            min_node_count=1,
            max_node_count=9,
            locations=["a", "b", "c"],
        )
        errors = pool.validate()
        assert len(errors) > 0

    def test_initial_below_min_rejected(self):
        pool = GKENodePool(
            name="main-pool",
            machine_type="n2-standard-4",
            initial_node_count=0,
            min_node_count=3,
            max_node_count=9,
            locations=["a", "b", "c"],
        )
        errors = pool.validate()
        assert any("min_node_count" in e for e in errors)

    def test_initial_above_max_rejected(self):
        pool = GKENodePool(
            name="main-pool",
            machine_type="n2-standard-4",
            initial_node_count=12,
            min_node_count=3,
            max_node_count=9,
            locations=["a", "b", "c"],
        )
        errors = pool.validate()
        assert any("max_node_count" in e for e in errors)

    def test_fewer_than_3_zones_warned(self):
        pool = GKENodePool(
            name="main-pool",
            machine_type="n2-standard-4",
            initial_node_count=2,
            min_node_count=1,
            max_node_count=9,
            locations=["a", "b"],
        )
        errors = pool.validate()
        assert any("zone" in e.lower() or "3" in e for e in errors)

    def test_small_disk_rejected(self):
        pool = GKENodePool(
            name="main-pool",
            machine_type="n2-standard-4",
            initial_node_count=3,
            min_node_count=1,
            max_node_count=9,
            disk_size_gb=50,
            locations=["a", "b", "c"],
        )
        errors = pool.validate()
        assert any("disk" in e.lower() for e in errors)

    def test_spot_pool_is_cost_optimised(self):
        pool = GKENodePool(
            name="spot-pool",
            machine_type="n2-standard-4",
            initial_node_count=3,
            min_node_count=0,
            max_node_count=10,
            spot=True,
            locations=["a", "b", "c"],
        )
        assert pool.is_cost_optimised()

    def test_on_demand_pool_not_cost_optimised(self, valid_gke_pool):
        assert not valid_gke_pool.is_cost_optimised()


# ---------------------------------------------------------------------------
# GKE Cluster Config tests
# ---------------------------------------------------------------------------

class TestGKEClusterConfig:
    def test_compliant_cluster_passes(self, valid_gke_cluster):
        assert valid_gke_cluster.is_compliant()

    def test_non_private_cluster_fails(self, valid_gke_cluster):
        valid_gke_cluster.private_cluster = False
        issues = valid_gke_cluster.validate_security()
        assert any("private" in i.lower() for i in issues)

    def test_no_private_nodes_fails(self, valid_gke_cluster):
        valid_gke_cluster.enable_private_nodes = False
        issues = valid_gke_cluster.validate_security()
        assert any("private" in i.lower() for i in issues)

    def test_workload_identity_disabled_fails(self, valid_gke_cluster):
        valid_gke_cluster.enable_workload_identity = False
        issues = valid_gke_cluster.validate_security()
        assert any("Workload Identity" in i or "workload_identity" in i.lower() for i in issues)

    def test_shielded_nodes_disabled_fails(self, valid_gke_cluster):
        valid_gke_cluster.enable_shielded_nodes = False
        issues = valid_gke_cluster.validate_security()
        assert any("shield" in i.lower() or "Shielded" in i for i in issues)

    def test_binary_auth_disabled_fails(self, valid_gke_cluster):
        valid_gke_cluster.enable_binary_authorization = False
        issues = valid_gke_cluster.validate_security()
        assert any("Binary Authorization" in i or "binary" in i.lower() for i in issues)

    def test_network_policy_disabled_fails(self, valid_gke_cluster):
        valid_gke_cluster.network_policy_enabled = False
        issues = valid_gke_cluster.validate_security()
        assert any("network policy" in i.lower() or "Network policy" in i for i in issues)

    def test_no_cmek_warns(self, valid_gke_cluster):
        valid_gke_cluster.database_encryption_key = ""
        issues = valid_gke_cluster.validate_security()
        assert any("CMEK" in i or "encryption" in i.lower() for i in issues)

    def test_terraform_resource_name_format(self, valid_gke_cluster):
        resource_name = valid_gke_cluster.terraform_resource_name()
        assert resource_name.startswith("google_container_cluster.")
        assert "-" not in resource_name.split(".")[1]

    def test_non_standard_release_channel_warns(self, valid_gke_cluster):
        valid_gke_cluster.release_channel = "RAPID"
        issues = valid_gke_cluster.validate_security()
        assert any("RAPID" in i or "channel" in i.lower() for i in issues)


# ---------------------------------------------------------------------------
# VPC Config tests
# ---------------------------------------------------------------------------

class TestVPCConfig:
    def test_valid_vpc_has_no_errors(self, valid_vpc):
        errors = valid_vpc.validate()
        assert not any(e.startswith("FAIL") for e in errors)

    def test_auto_create_subnetworks_rejected(self):
        vpc = VPCConfig(
            name="test-vpc",
            project_id="test-project",
            auto_create_subnetworks=True,
        )
        errors = vpc.validate()
        assert any("auto_create" in e.lower() for e in errors)

    def test_missing_gke_subnet_warns(self):
        vpc = VPCConfig(
            name="test-vpc",
            project_id="test-project",
            auto_create_subnetworks=False,
            subnets=[{"name": "serverless-subnet"}],
        )
        errors = vpc.validate()
        assert any("gke-subnet" in e for e in errors)

    def test_secondary_ranges_extracted(self, valid_vpc):
        ranges = valid_vpc.get_secondary_ranges()
        range_names = [r["range_name"] for r in ranges]
        assert "pods" in range_names
        assert "services" in range_names


# ---------------------------------------------------------------------------
# Cloud Armor Policy tests
# ---------------------------------------------------------------------------

class TestCloudArmorPolicy:
    @pytest.fixture
    def banking_armor_policy(self):
        return CloudArmorPolicy(
            policy_name="allica-banking-waf",
            rules=[
                {
                    "priority": 1000,
                    "action": "rate_based_ban",
                    "match": "evaluatePreconfiguredExpr('xss-v33-stable')",
                },
                {
                    "priority": 2000,
                    "action": "deny",
                    "match": "evaluatePreconfiguredExpr('owasp-top-10')",
                    "description": "OWASP top 10 blocking",
                },
                {
                    "priority": 2147483647,
                    "action": "deny(403)",
                    "match": "true",
                    "description": "Default deny all",
                },
            ],
            adaptive_protection_enabled=True,
        )

    def test_owasp_ruleset_detected(self, banking_armor_policy):
        assert banking_armor_policy.has_owasp_ruleset()

    def test_rate_limiting_detected(self, banking_armor_policy):
        assert banking_armor_policy.has_rate_limiting()

    def test_deny_all_default_detected(self, banking_armor_policy):
        assert banking_armor_policy.has_deny_all_default()

    def test_valid_policy_passes_banking_check(self, banking_armor_policy):
        issues = banking_armor_policy.validate_for_banking()
        assert not any(i.startswith("FAIL") for i in issues)

    def test_no_owasp_fails(self):
        policy = CloudArmorPolicy(
            policy_name="test",
            rules=[{"priority": 1000, "action": "allow"}],
        )
        issues = policy.validate_for_banking()
        assert any("OWASP" in i for i in issues)

    def test_no_rate_limiting_fails(self):
        policy = CloudArmorPolicy(
            policy_name="test",
            rules=[
                {"priority": 1000, "action": "deny", "match": "owasp rules"},
            ],
        )
        issues = policy.validate_for_banking()
        assert any("rate" in i.lower() for i in issues)

    def test_adaptive_protection_disabled_warns(self):
        policy = CloudArmorPolicy(
            policy_name="test",
            rules=[
                {"priority": 1000, "action": "rate_based_ban", "match": "owasp"},
                {"priority": 2000, "action": "deny", "match": "owasp-top-10"},
            ],
            adaptive_protection_enabled=False,
        )
        issues = policy.validate_for_banking()
        assert any("adaptive" in i.lower() or "DDoS" in i for i in issues)


# ---------------------------------------------------------------------------
# Cloud Run Service tests
# ---------------------------------------------------------------------------

class TestCloudRunService:
    @pytest.fixture
    def valid_cloud_run_service(self):
        return CloudRunService(
            service_name="payment-processor",
            region="europe-west2",
            container_image="europe-west2-docker.pkg.dev/allica/platform/payment-svc:v1.2.3",
            min_instances=1,
            max_instances=50,
            allow_unauthenticated=False,
            vpc_connector="projects/allica-platform-prod/locations/europe-west2/connectors/vpc-conn",
            service_account="payment-svc@allica-platform-prod.iam.gserviceaccount.com",
        )

    def test_valid_service_is_compliant(self, valid_cloud_run_service):
        assert valid_cloud_run_service.is_compliant()

    def test_unauthenticated_access_fails(self, valid_cloud_run_service):
        valid_cloud_run_service.allow_unauthenticated = True
        issues = valid_cloud_run_service.validate_security()
        assert any("unauthenticated" in i.lower() for i in issues)

    def test_no_vpc_connector_fails(self, valid_cloud_run_service):
        valid_cloud_run_service.vpc_connector = ""
        issues = valid_cloud_run_service.validate_security()
        assert any("VPC connector" in i or "vpc_connector" in i.lower() for i in issues)

    def test_no_service_account_fails(self, valid_cloud_run_service):
        valid_cloud_run_service.service_account = ""
        issues = valid_cloud_run_service.validate_security()
        assert any("service account" in i.lower() for i in issues)

    def test_zero_min_instances_warns(self, valid_cloud_run_service):
        valid_cloud_run_service.min_instances = 0
        issues = valid_cloud_run_service.validate_security()
        assert any("cold start" in i.lower() or "min_instances" in i.lower() for i in issues)


# ---------------------------------------------------------------------------
# Terraform Module Generator tests
# ---------------------------------------------------------------------------

class TestTerraformModuleGenerator:
    def test_gke_cluster_hcl_contains_cluster_name(self, valid_gke_cluster):
        gen = TerraformModuleGenerator()
        hcl = gen.gke_cluster_hcl(valid_gke_cluster)
        assert valid_gke_cluster.cluster_name in hcl

    def test_gke_cluster_hcl_contains_project_id(self, valid_gke_cluster):
        gen = TerraformModuleGenerator()
        hcl = gen.gke_cluster_hcl(valid_gke_cluster)
        assert valid_gke_cluster.project_id in hcl

    def test_gke_cluster_hcl_has_private_cluster_config(self, valid_gke_cluster):
        gen = TerraformModuleGenerator()
        hcl = gen.gke_cluster_hcl(valid_gke_cluster)
        assert "private_cluster_config" in hcl

    def test_gke_cluster_hcl_has_workload_identity(self, valid_gke_cluster):
        gen = TerraformModuleGenerator()
        hcl = gen.gke_cluster_hcl(valid_gke_cluster)
        assert "workload_identity_config" in hcl

    def test_node_pool_hcl_contains_pool_name(self, valid_gke_cluster, valid_gke_pool):
        gen = TerraformModuleGenerator()
        hcl = gen.node_pool_hcl(valid_gke_cluster.cluster_name, valid_gke_pool)
        assert valid_gke_pool.name in hcl

    def test_node_pool_hcl_has_autoscaling(self, valid_gke_cluster, valid_gke_pool):
        gen = TerraformModuleGenerator()
        hcl = gen.node_pool_hcl(valid_gke_cluster.cluster_name, valid_gke_pool)
        assert "autoscaling" in hcl

    def test_vpc_hcl_contains_vpc_name(self, valid_vpc):
        gen = TerraformModuleGenerator()
        hcl = gen.vpc_hcl(valid_vpc)
        assert valid_vpc.name in hcl

    def test_vpc_hcl_has_auto_create_false(self, valid_vpc):
        gen = TerraformModuleGenerator()
        hcl = gen.vpc_hcl(valid_vpc)
        assert "false" in hcl
