"""
Tests for Azure Platform Infrastructure Module
Covers: AKS config validation, VNet design, Azure Firewall rules,
Well-Architected Framework scoring, multi-region deployment planning.
"""
import pytest
from devops_platform.azure_platform import (
    AKSNodePool,
    AKSClusterConfig,
    VNetConfig,
    AzureFirewallRule,
    APIMPolicy,
    WellArchitectedScorer,
    MultiRegionPlanner,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def valid_node_pool():
    return AKSNodePool(
        name="systempool",
        vm_size="Standard_D4s_v3",
        node_count=3,
        min_count=3,
        max_count=9,
        availability_zones=["1", "2", "3"],
    )


@pytest.fixture
def valid_cluster(valid_node_pool):
    return AKSClusterConfig(
        cluster_name="allica-aks-prod",
        resource_group="rg-platform-prod",
        location="uksouth",
        kubernetes_version="1.28.0",
        node_pools=[valid_node_pool],
        private_cluster=True,
        enable_rbac=True,
        azure_ad_integration=True,
        defender_enabled=True,
        oms_agent_enabled=True,
        tags={"environment": "production", "cost_centre": "platform", "owner": "platform-team"},
    )


@pytest.fixture
def valid_vnet():
    return VNetConfig(
        name="vnet-platform-prod",
        address_space="10.0.0.0/16",
        location="uksouth",
        subnets=[
            {"name": "aks-subnet", "address_prefix": "10.0.1.0/24"},
            {"name": "appgw-subnet", "address_prefix": "10.0.2.0/24"},
            {"name": "firewall-subnet", "address_prefix": "10.0.3.0/24"},
        ],
        enable_ddos_protection=True,
    )


# ---------------------------------------------------------------------------
# AKS Node Pool tests
# ---------------------------------------------------------------------------

class TestAKSNodePool:
    def test_valid_node_pool_has_no_errors(self, valid_node_pool):
        assert valid_node_pool.validate() == []

    def test_invalid_name_rejected(self):
        pool = AKSNodePool(
            name="INVALID-POOL-NAME",
            vm_size="Standard_D4s_v3",
            node_count=3,
            min_count=1,
            max_count=9,
            availability_zones=["1", "2", "3"],
        )
        errors = pool.validate()
        assert any("name" in e.lower() for e in errors)

    def test_node_count_below_min_rejected(self):
        pool = AKSNodePool(
            name="systempool",
            vm_size="Standard_D4s_v3",
            node_count=0,
            min_count=3,
            max_count=9,
            availability_zones=["1", "2", "3"],
        )
        errors = pool.validate()
        assert any("min_count" in e for e in errors)

    def test_node_count_above_max_rejected(self):
        pool = AKSNodePool(
            name="systempool",
            vm_size="Standard_D4s_v3",
            node_count=12,
            min_count=3,
            max_count=9,
            availability_zones=["1", "2", "3"],
        )
        errors = pool.validate()
        assert any("max_count" in e for e in errors)

    def test_less_than_3_azs_fails_banking_ha(self):
        pool = AKSNodePool(
            name="systempool",
            vm_size="Standard_D4s_v3",
            node_count=2,
            min_count=1,
            max_count=9,
            availability_zones=["1", "2"],
        )
        errors = pool.validate()
        assert any("AZ" in e or "3 AZ" in e for e in errors)

    def test_small_disk_rejected(self):
        pool = AKSNodePool(
            name="systempool",
            vm_size="Standard_D4s_v3",
            node_count=3,
            min_count=1,
            max_count=9,
            os_disk_size_gb=50,
            availability_zones=["1", "2", "3"],
        )
        errors = pool.validate()
        assert any("disk" in e.lower() or "os_disk" in e.lower() for e in errors)

    def test_zero_min_count_fails_ha_compliance(self):
        pool = AKSNodePool(
            name="systempool",
            vm_size="Standard_D4s_v3",
            node_count=3,
            min_count=0,
            max_count=9,
            availability_zones=["1", "2", "3"],
        )
        errors = pool.validate()
        assert any("min_count" in e.lower() or "HA" in e for e in errors)

    def test_name_too_long_rejected(self):
        pool = AKSNodePool(
            name="toolongnodepoolname",
            vm_size="Standard_D4s_v3",
            node_count=3,
            min_count=1,
            max_count=9,
            availability_zones=["1", "2", "3"],
        )
        errors = pool.validate()
        assert len(errors) > 0


# ---------------------------------------------------------------------------
# AKS Cluster Config tests
# ---------------------------------------------------------------------------

class TestAKSClusterConfig:
    def test_waf_compliant_cluster_passes(self, valid_cluster):
        assert valid_cluster.is_waf_compliant()

    def test_non_private_cluster_fails_security(self, valid_cluster):
        valid_cluster.private_cluster = False
        results = valid_cluster.validate_well_architected()
        assert any("private" in i.lower() for i in results["security"])

    def test_rbac_disabled_fails_security(self, valid_cluster):
        valid_cluster.enable_rbac = False
        results = valid_cluster.validate_well_architected()
        assert any("RBAC" in i for i in results["security"])

    def test_azure_ad_disabled_fails_security(self, valid_cluster):
        valid_cluster.azure_ad_integration = False
        results = valid_cluster.validate_well_architected()
        assert any("AD" in i or "identity" in i.lower() for i in results["security"])

    def test_defender_disabled_fails_security(self, valid_cluster):
        valid_cluster.defender_enabled = False
        results = valid_cluster.validate_well_architected()
        assert any("Defender" in i for i in results["security"])

    def test_oms_disabled_fails_operational_excellence(self, valid_cluster):
        valid_cluster.oms_agent_enabled = False
        results = valid_cluster.validate_well_architected()
        assert any("OMS" in i or "observability" in i.lower() for i in results["operational_excellence"])

    def test_missing_environment_tag_warns(self, valid_cluster):
        valid_cluster.tags = {"cost_centre": "platform"}
        results = valid_cluster.validate_well_architected()
        assert any("environment" in i.lower() for i in results["operational_excellence"])

    def test_missing_cost_centre_tag_warns(self, valid_cluster):
        valid_cluster.tags = {"environment": "production"}
        results = valid_cluster.validate_well_architected()
        assert any("cost_centre" in i.lower() for i in results["operational_excellence"])

    def test_invalid_network_policy_fails(self, valid_cluster):
        valid_cluster.network_policy = "kubenet"
        results = valid_cluster.validate_well_architected()
        assert any("network_policy" in i.lower() for i in results["security"])


# ---------------------------------------------------------------------------
# VNet Config tests
# ---------------------------------------------------------------------------

class TestVNetConfig:
    def test_valid_vnet_has_required_subnets(self, valid_vnet):
        assert valid_vnet.has_required_subnets()

    def test_valid_cidr(self, valid_vnet):
        assert valid_vnet.validate_cidr()

    def test_invalid_cidr_rejected(self):
        vnet = VNetConfig(name="test", address_space="not-a-cidr", location="uksouth")
        assert not vnet.validate_cidr()

    def test_missing_aks_subnet_fails(self, valid_vnet):
        valid_vnet.subnets = [
            {"name": "appgw-subnet"},
            {"name": "firewall-subnet"},
        ]
        assert not valid_vnet.has_required_subnets()

    def test_subnet_names_returned_correctly(self, valid_vnet):
        names = valid_vnet.get_subnet_names()
        assert "aks-subnet" in names
        assert "appgw-subnet" in names
        assert "firewall-subnet" in names

    def test_empty_subnets_fails_required_check(self):
        vnet = VNetConfig(name="test", address_space="10.0.0.0/16", location="uksouth")
        assert not vnet.has_required_subnets()


# ---------------------------------------------------------------------------
# Azure Firewall Rule tests
# ---------------------------------------------------------------------------

class TestAzureFirewallRule:
    def test_valid_rule_has_no_errors(self):
        rule = AzureFirewallRule(
            name="allow-aks-egress",
            priority=200,
            action="Allow",
            protocol="TCP",
            source_addresses=["10.0.1.0/24"],
            destination_addresses=["*"],
            destination_ports=["443"],
        )
        assert rule.validate() == []

    def test_invalid_action_rejected(self):
        rule = AzureFirewallRule(
            name="test",
            priority=200,
            action="DROP",
            protocol="TCP",
            source_addresses=["10.0.0.0/8"],
            destination_addresses=["*"],
            destination_ports=["443"],
        )
        errors = rule.validate()
        assert any("action" in e.lower() for e in errors)

    def test_invalid_protocol_rejected(self):
        rule = AzureFirewallRule(
            name="test",
            priority=200,
            action="Allow",
            protocol="GRE",
            source_addresses=["10.0.0.0/8"],
            destination_addresses=["*"],
            destination_ports=["any"],
        )
        errors = rule.validate()
        assert any("protocol" in e.lower() for e in errors)

    def test_priority_out_of_range_rejected(self):
        rule = AzureFirewallRule(
            name="test",
            priority=99,
            action="Allow",
            protocol="TCP",
            source_addresses=["10.0.0.0/8"],
            destination_addresses=["*"],
            destination_ports=["443"],
        )
        errors = rule.validate()
        assert any("priority" in e.lower() for e in errors)

    def test_deny_all_egress_detection(self):
        rule = AzureFirewallRule(
            name="deny-all",
            priority=65000,
            action="Deny",
            protocol="Any",
            source_addresses=["*"],
            destination_addresses=["*"],
            destination_ports=["*"],
        )
        assert rule.is_deny_all_egress()

    def test_non_deny_all_not_detected(self):
        rule = AzureFirewallRule(
            name="allow-https",
            priority=200,
            action="Allow",
            protocol="TCP",
            source_addresses=["10.0.0.0/8"],
            destination_addresses=["*"],
            destination_ports=["443"],
        )
        assert not rule.is_deny_all_egress()

    def test_empty_source_addresses_rejected(self):
        rule = AzureFirewallRule(
            name="test",
            priority=200,
            action="Allow",
            protocol="TCP",
            source_addresses=[],
            destination_addresses=["*"],
            destination_ports=["443"],
        )
        errors = rule.validate()
        assert any("source" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# APIM Policy tests
# ---------------------------------------------------------------------------

class TestAPIMPolicy:
    def test_valid_policy_passes_banking_check(self):
        policy = APIMPolicy(
            policy_name="sme-banking-api",
            rate_limit_calls=100,
            rate_limit_renewal_period=60,
            require_subscription_key=True,
            cors_origins=["https://app.allica.bank"],
        )
        issues = policy.validate_for_banking()
        assert not any(i.startswith("FAIL") for i in issues)

    def test_no_subscription_key_fails(self):
        policy = APIMPolicy(
            policy_name="test",
            rate_limit_calls=100,
            rate_limit_renewal_period=60,
            require_subscription_key=False,
        )
        issues = policy.validate_for_banking()
        assert any("Subscription" in i for i in issues)

    def test_wildcard_cors_fails_banking(self):
        policy = APIMPolicy(
            policy_name="test",
            rate_limit_calls=100,
            rate_limit_renewal_period=60,
            require_subscription_key=True,
            cors_origins=["*"],
        )
        issues = policy.validate_for_banking()
        assert any("CORS" in i or "wildcard" in i.lower() for i in issues)

    def test_xml_snippet_contains_rate_limit(self):
        policy = APIMPolicy(
            policy_name="test",
            rate_limit_calls=50,
            rate_limit_renewal_period=30,
        )
        xml = policy.to_xml_snippet()
        assert "50" in xml
        assert "30" in xml
        assert "rate-limit" in xml


# ---------------------------------------------------------------------------
# Well-Architected Scorer tests
# ---------------------------------------------------------------------------

class TestWellArchitectedScorer:
    def test_fully_compliant_cluster_scores_100(self, valid_cluster):
        scorer = WellArchitectedScorer()
        scores = scorer.score_cluster(valid_cluster)
        assert all(v == 100 for v in scores.values())

    def test_overall_score_is_average_of_pillars(self, valid_cluster):
        scorer = WellArchitectedScorer()
        scores = scorer.score_cluster(valid_cluster)
        expected = sum(scores.values()) / len(scores)
        assert scorer.overall_score(valid_cluster) == pytest.approx(expected)

    def test_non_compliant_cluster_not_production_ready(self, valid_cluster):
        valid_cluster.private_cluster = False
        valid_cluster.enable_rbac = False
        valid_cluster.azure_ad_integration = False
        scorer = WellArchitectedScorer()
        assert not scorer.is_production_ready(valid_cluster)

    def test_compliant_cluster_is_production_ready(self, valid_cluster):
        scorer = WellArchitectedScorer()
        assert scorer.is_production_ready(valid_cluster)

    def test_all_pillars_present_in_scores(self, valid_cluster):
        scorer = WellArchitectedScorer()
        scores = scorer.score_cluster(valid_cluster)
        for pillar in WellArchitectedScorer.PILLARS:
            assert pillar in scores


# ---------------------------------------------------------------------------
# Multi-Region Planner tests
# ---------------------------------------------------------------------------

class TestMultiRegionPlanner:
    def test_uksouth_pairs_with_ukwest(self):
        planner = MultiRegionPlanner("uksouth")
        assert planner.get_dr_region() == "ukwest"

    def test_ukwest_pairs_with_uksouth(self):
        planner = MultiRegionPlanner("ukwest")
        assert planner.get_dr_region() == "uksouth"

    def test_unknown_region_returns_none(self):
        planner = MultiRegionPlanner("australiaeast")
        assert planner.get_dr_region() is None

    def test_deployment_regions_includes_primary(self):
        planner = MultiRegionPlanner("uksouth")
        regions = planner.generate_deployment_regions()
        assert "uksouth" in regions

    def test_deployment_regions_includes_dr(self):
        planner = MultiRegionPlanner("uksouth")
        regions = planner.generate_deployment_regions()
        assert "ukwest" in regions

    def test_rpo_under_4_hours(self):
        planner = MultiRegionPlanner("uksouth")
        assert planner.rpo_hours() <= 4.0

    def test_rto_under_8_hours(self):
        planner = MultiRegionPlanner("uksouth")
        assert planner.rto_hours() <= 8.0

    def test_valid_cluster_passes_ha_validation(self, valid_cluster):
        planner = MultiRegionPlanner("uksouth")
        assert planner.validate_ha_configuration(valid_cluster)

    def test_wrong_region_cluster_fails_ha_validation(self, valid_cluster):
        valid_cluster.location = "eastus"
        planner = MultiRegionPlanner("uksouth")
        assert not planner.validate_ha_configuration(valid_cluster)
