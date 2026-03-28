# Allica Bank Platform Engineering POC

**Candidate:** Ram Gopal Reddy Basireddy
**Role:** Senior Platform Engineer
**Company:** Allica Bank (UK's fastest-growing SME fintech bank)
**GitHub:** https://github.com/ramagopalb/allica-bank-platform-poc

---

## What this POC demonstrates

This POC showcases platform engineering capabilities directly aligned to the Allica Bank role:

| Capability | Module | Allica Bank Relevance |
|---|---|---|
| Azure multi-region platform | `azure_platform.py` | AKS, VNet, Azure Firewall, API Management |
| GCP cloud platform | `gcp_platform.py` | GKE, VPC, Cloud Armor, Cloud Run serverless |
| CI/CD self-service platform | `cicd_platform.py` | Azure DevOps + GitHub Actions, canary deploy, DORA |
| Compliance-as-code | `compliance.py` | FCA Operational Resilience, OPA policies, audit trails |

---

## Architecture

```
devops_platform/
├── azure_platform.py   # AKS cluster configs, VNet, Azure Firewall, Well-Architected scoring
├── gcp_platform.py     # GKE clusters, VPC, Cloud Armor WAF, Cloud Run, Terraform HCL
├── cicd_platform.py    # Pipeline templates, security gates, canary deployments, DORA metrics
└── compliance.py       # OPA policy evaluation, FCA resilience checks, audit trail management

tests/
├── test_azure_platform.py   # AKS, VNet, WAF, multi-region HA tests
├── test_gcp_platform.py     # GKE, VPC, Cloud Armor, Cloud Run, Terraform tests
├── test_cicd_platform.py    # Pipeline, security gates, canary, DORA, guardrails tests
└── test_compliance.py       # OPA, FCA, audit trail, compliance scoring tests
```

---

## Running the tests

```bash
pip install pytest
cd POC_Project
pytest tests/ -v
```

---

## Key technical themes

- **Azure + GCP multi-cloud**: AKS (Azure) and GKE (GCP) with Terraform DRY modules
- **Well-Architected Framework**: All 5 pillars scored programmatically against cluster configs
- **FCA Operational Resilience**: Impact tolerance validation, business service mapping, resilience test tracking
- **Self-service guardrails**: Deployment request validation with production approval gates
- **Compliance-as-code**: OPA-style policy evaluation for 8 banking-specific policies
- **Canary deployments**: Configurable traffic splitting with automated error-rate rollback
- **DORA metrics**: Performance level classification (Elite/High/Medium/Low) with improvement targets
- **Audit trail**: Immutable event recording with privileged action detection and checksums
