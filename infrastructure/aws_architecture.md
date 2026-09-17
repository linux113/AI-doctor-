# AI Doctor — AWS Phase 2 Architecture Specification

## Overview

AI Doctor is an autonomous developer troubleshooting and recovery agent. In the local MVP, the core Detect → Diagnose → Fix → Verify → Retry loop runs locally. In Phase 2, the components map directly to AWS native services:

```
                  ┌──────────────────────┐
                  │    Next.js UI        │
                  │ (Amplify / S3+CloudF)│
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │   Amazon API Gateway │
                  └──────────┬───────────┘
                             │
                 ┌───────────┴────────────┐
                 ▼                        ▼
       ┌───────────────────┐    ┌───────────────────┐
       │ AWS Lambda (API)  │    │ AWS Lambda (Heal) │
       └─────────┬─────────┘    └─────────┬─────────┘
                 │                        │
                 ▼                        ▼
       ┌───────────────────┐    ┌──────────────────────────┐
       │  Amazon DynamoDB  │    │    AWS Strands Agent     │
       │(AIDoctorIncidents)│    │(Troubleshooting Runtime) │
       └───────────────────┘    └─────────────┬────────────┘
                                              │
                     ┌────────────────────────┼────────────────────────┐
                     ▼                        ▼                        ▼
         ┌───────────────────────┐┌───────────────────────┐┌───────────────────────┐
         │    Amazon Bedrock     ││   Amazon CloudWatch   ││  Safe Remediation     │
         │  (Claude 3.5 Sonnet)  ││    (Logs & Alarms)    ││ (Step Functions / SSM)│
         └───────────────────────┘└───────────────────────┘└───────────────────────┘
```

## Service Mapping

| Local MVP Component | Phase 2 AWS Target Service | Purpose |
|---|---|---|
| **Incident Storage (`backend/storage.py`)** | **Amazon DynamoDB** | Persistent document storage for incidents, evidence, and audit logs. |
| **Backend API (`backend/main.py`)** | **AWS Lambda + Amazon API Gateway** | Serverless REST API endpoints for detection, diagnosis, and healing. |
| **Doctor Runner (`runner/doctor_runner.py`)** | **AWS Strands Agents + AWS Step Functions** | Multi-step agentic investigation and verified remediation state machine. |
| **Reasoning Engine (`agent/strands_agent.py`)**| **Amazon Bedrock (Claude 3.5 Sonnet)** | Foundation model synthesizing system evidence into root cause explanations. |
| **Diagnostic Log Collector** | **Amazon CloudWatch Logs & Metrics** | Real-time log filtering and synthetic canary monitoring. |
| **Remediation Execution** | **AWS Systems Manager (SSM) Automation** | Secure, audited runbooks enforcing the remediation allowlist without SSH. |
| **Diagnostic Evidence Bundles** | **Amazon S3** | Durable storage for crash dumps, full log extracts, and audit reports. |
| **Frontend Web Dashboard** | **AWS Amplify Hosting** | Globally distributed, high-performance web dashboard with CI/CD. |

## Security & IAM Controls
- **Least Privilege**: Lambdas and Agents receive scoped IAM roles restricting SSM documents to the allowlist.
- **Data Protection**: Secrets stored in AWS Secrets Manager; PII and tokens redacted via CloudWatch log data protection policies.
- **Audit Trails**: AWS CloudTrail records every remediation document execution for regulatory compliance.
