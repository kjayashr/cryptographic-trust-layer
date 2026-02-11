# Cryptographic Trust Layer for Enterprise AI

**Thesis:** As AI systems shift from generating outputs to executing actions, enterprises need a cryptographic enforcement layer that makes AI behavior verifiable, policy-bound, and auditable - with the same guarantees applied to financial transactions and code signing today.

---

## 1. The Shift That Breaks the Current Stack

Traditional AI returns text. A human reviews it and acts. The blast radius of a compromised model is limited to bad advice.

Agentic AI executes. It calls APIs, modifies infrastructure, moves money, and interacts with other agents - autonomously, at machine speed, across trust boundaries.

```mermaid
graph LR
    subgraph "Pre-2024: Human-in-the-Loop"
        A[Prompt] --> B[Inference] --> C[Text] --> D[Human Acts]
    end

    subgraph "2024+: Autonomous Execution"
        E[Goal] --> F[Agent Reasoning]
        F --> G[API Calls]
        F --> H[Infra Mutations]
        F --> I[Financial Transactions]
        F --> J[Cross-Org Agent Calls]
    end

    style D fill:#2d6a4f,color:#fff
    style G fill:#9d0208,color:#fff
    style H fill:#9d0208,color:#fff
    style I fill:#9d0208,color:#fff
    style J fill:#9d0208,color:#fff
```

A compromised agent in this model has the same impact profile as a compromised privileged service account - lateral movement, privilege escalation, data exfiltration - except it operates with less observability and no established identity framework.

The current stack (guardrails, prompt filtering, output scanning, logging) was designed to monitor AI. It was not designed to **enforce and prove** what AI is allowed to do.

---

## 2. Threat Model: AI Agent Attack Surface

Six attack vectors specific to agentic AI systems, mapped against what existing controls cover and where the gaps are.

```mermaid
graph TB
    subgraph "AI Agent Attack Chain"
        direction TB
        T1["T1 - Model Supply Chain\nPoisoned weights · backdoored LoRA adapters\ntyposquatted model repos · compromised\ntraining data · dependency confusion"]
        T2["T2 - Input Manipulation\nDirect prompt injection · indirect injection\nvia RAG context · jailbreaks · instruction\nhierarchy bypass · context poisoning"]
        T3["T3 - Identity & Authorization\nAgent impersonation · credential theft\nover-provisioned service accounts\nprivilege escalation via tool chaining"]
        T4["T4 - Action Execution\nUnauthorized API calls · parameter tampering\nreplay attacks · TOCTOU between policy\nevaluation and execution"]
        T5["T5 - Observability\nLog tampering · silent policy drift\nphantom actions · broken causal chains\nacross multi-agent workflows"]
        T6["T6 - Cross-Boundary\nRogue agent-to-agent traffic · unverified\ninter-org interactions · MITM on agent\ncommunication · trust delegation abuse"]
    end

    T1 --> T2 --> T3 --> T4 --> T5 --> T6

    style T1 fill:#03071e,color:#fff
    style T2 fill:#370617,color:#fff
    style T3 fill:#6a040f,color:#fff
    style T4 fill:#9d0208,color:#fff
    style T5 fill:#d00000,color:#fff
    style T6 fill:#e85d04,color:#fff
```

| Vector | Existing Coverage | Gap |
|---|---|---|
| T1 - Supply Chain | SCA tools scan code dependencies, not model artifacts | No model provenance, no AI-SBOM, no runtime hash verification |
| T2 - Input Manipulation | Guardrails, prompt filters | Addressed at input - but if injection succeeds, nothing prevents execution |
| T3 - Identity | IAM, RBAC | Agents inherit service account privileges; no per-agent, per-action identity |
| T4 - Execution | API gateways, rate limits | No cryptographic binding between policy decision and action execution |
| T5 - Observability | SIEM, logging | Logs are mutable; no tamper-evident chain of custody for AI actions |
| T6 - Cross-Boundary | mTLS at network layer | No application-layer agent identity, no signed intent verification |

The trust layer closes T1, T3, T4, T5, and T6. It hardens the boundary at T2 by ensuring that even a successful prompt injection cannot bypass cryptographic execution gates.

---

## 3. Architecture Overview

```mermaid
graph TB
    subgraph "AI Agent Runtime"
        A["Agent\n(reasoning engine)"] -->|"Proposes action\n(untrusted intent)"| B["Structured\nAction Request"]
    end

    subgraph "Cryptographic Trust Layer"
        B --> PDP{"Policy Decision\nPoint (PDP)"}
        PDP -->|"Evaluate"| PE["Policy Engine\n(OPA/Rego · Cedar)"]
        PE -->|ALLOW| CS["Signing Service\n(Ed25519 · ES256)"]
        PE -->|DENY| DR["Signed Denial\nRecord"]
        CS --> SAE["Signed Action\nEnvelope (SAE)"]
    end

    subgraph "Execution Boundary"
        SAE -->|"Signature verified\nbefore execution"| PEP["Policy Enforcement\nPoint (PEP)"]
        PEP --> TGT["Target System\n(API · Service · Infra)"]
    end

    subgraph "Audit Plane"
        CS --> MA["Merkle\nAnchoring"]
        DR --> MA
        MA --> IAS["Immutable Audit Store\n(append-only · hash-chained)"]
    end

    style PDP fill:#e76f51,color:#fff
    style CS fill:#264653,color:#fff
    style PEP fill:#264653,color:#fff
    style IAS fill:#2a9d8f,color:#fff
    style DR fill:#9d0208,color:#fff
```

The architecture separates three concerns: the **Policy Decision Point** evaluates whether an action is permitted, the **Signing Service** produces the cryptographic proof, and the **Policy Enforcement Point** at the execution boundary refuses to execute anything without a valid signature. This separation means a compromised agent cannot bypass enforcement - it does not hold signing keys.

---

## 4. Deployment Topology

Three deployment models depending on where the enterprise is in its agent maturity.

```mermaid
graph TB
    subgraph "Model A - Sidecar (Per-Agent Enforcement)"
        direction LR
        A1["Agent Process"] --> A2["Trust Sidecar\n(PDP + PEP)"]
        A2 --> A3["Target API"]
        A2 --> A4["Audit Plane"]
    end

    subgraph "Model B - Gateway (Centralized Choke Point)"
        direction LR
        B1["Agent 1"] --> B4["Trust Gateway\n(reverse proxy mode)"]
        B2["Agent 2"] --> B4
        B3["Agent 3"] --> B4
        B4 --> B5["Target APIs"]
        B4 --> B6["Audit Plane"]
    end

    subgraph "Model C - SDK (Embedded in Agent Framework)"
        direction LR
        C1["Agent Framework\n(LangChain · CrewAI · AutoGen)"] --> C2["Trust SDK\n(library calls)"]
        C2 --> C3["Remote Signing Service\n(keys never local)"]
        C3 --> C4["Target APIs"]
        C2 --> C5["Audit Plane"]
    end

    style A2 fill:#e76f51,color:#fff
    style B4 fill:#e76f51,color:#fff
    style C2 fill:#e76f51,color:#fff
    style C3 fill:#264653,color:#fff
```

| Model | Latency | Control Granularity | Deployment Effort | Best For |
|---|---|---|---|---|
| **Sidecar** | <5ms (local PDP) | Per-agent, per-action | Medium (K8s DaemonSet/sidecar injection) | Kubernetes-native agent deployments |
| **Gateway** | 10-30ms (network hop) | Centralized policy, all agents | Low (reverse proxy, no agent changes) | Rapid deployment, legacy agent systems |
| **SDK** | <2ms (in-process) + signing RTT | Deepest (pre-action hooks) | High (code integration) | Agent framework developers, tight control |

In all three models, **signing keys never reside on the agent**. The agent can request execution but cannot self-authorize. This is the hard separation between intelligence and authority.

---

## 5. PKI Architecture & Key Management

The first question any security architect asks: *who holds the keys, how are they managed, and what happens when they're compromised?*

```mermaid
graph TB
    subgraph "Certificate Hierarchy"
        ROOT["Root CA\n(offline · HSM-backed · air-gapped)\nLifetime: 10 years\nUsage: Signs intermediate CAs only"]
        INT["Intermediate CA - Agent Identity\n(online · HSM-backed · FIPS 140-2 L3)\nLifetime: 2 years\nUsage: Issues agent certificates"]
        INT2["Intermediate CA - Policy Signing\n(online · HSM-backed)\nLifetime: 2 years\nUsage: Signs policy artifacts"]
        INT3["Intermediate CA - Audit Anchoring\n(online · HSM-backed)\nLifetime: 2 years\nUsage: Signs Merkle roots"]

        ROOT --> INT
        ROOT --> INT2
        ROOT --> INT3

        AGENT1["Agent Cert\nSubject: agent-procurement-prod-01\nLifetime: 24h (auto-rotated)\nKey: Ed25519\nExtensions: allowed-actions,\nmax-risk-score, org-boundary"]
        AGENT2["Agent Cert\nSubject: agent-finance-prod-03\nLifetime: 24h (auto-rotated)\nKey: Ed25519"]
        POLICY["Policy Signing Cert\nSigns OPA/Rego bundles\nLifetime: 90 days"]

        INT --> AGENT1
        INT --> AGENT2
        INT2 --> POLICY
    end

    subgraph "Key Storage"
        HSM["HSM / Cloud KMS\n(AWS KMS · Azure Key Vault\n· GCP Cloud HSM)\nRoot + intermediate private keys\nFIPS 140-2 Level 3"]
        AGENT_STORE["Ephemeral Key Store\nAgent signing keys\nIn-memory only · never persisted\nProvisioned via SPIFFE/SPIRE"]
    end

    INT --> HSM
    AGENT1 --> AGENT_STORE

    subgraph "Revocation"
        OCSP["OCSP Responder\n(stapled to every SAE)\nReal-time revocation check"]
        CRL["CRL Distribution Point\nFallback for offline verification\nDelta CRLs every 5 minutes"]
    end

    INT --> OCSP
    INT --> CRL

    style ROOT fill:#264653,color:#fff
    style INT fill:#2a9d8f,color:#fff
    style INT2 fill:#2a9d8f,color:#fff
    style INT3 fill:#2a9d8f,color:#fff
    style HSM fill:#e76f51,color:#fff
```

Key design decisions:

- **Short-lived agent certificates (24h)** limit the blast radius of key compromise. Automatic rotation via SPIFFE/SPIRE eliminates manual certificate management.
- **Signing keys are never on the agent.** Agents authenticate to the signing service, which holds keys in HSM. The agent proves identity; the service produces the signature.
- **Separate CA chains** for agent identity, policy signing, and audit anchoring. Compromise of one chain does not compromise the others.
- **OCSP stapling on every SAE** means the verifier can confirm the signing certificate was valid at the exact moment of signing without a network call to the CA.

---

## 6. Data Plane / Control Plane Separation

```mermaid
graph LR
    subgraph "Control Plane (low frequency, high trust)"
        CP1["Policy Management\nVersion, sign, distribute\nOPA/Rego bundles"]
        CP2["Certificate Lifecycle\nIssue, rotate, revoke\nagent certificates"]
        CP3["Model Registry\nRegister, attest, revoke\nmodel provenance"]
        CP4["Audit Configuration\nAnchoring frequency,\nretention policy,\ntransparency log config"]
    end

    subgraph "Data Plane (high frequency, low latency)"
        DP1["Policy Evaluation\nPer-action PDP calls\nTarget: <5ms p99"]
        DP2["Action Signing\nEd25519 signature\nper authorized action\nTarget: <2ms"]
        DP3["Signature Verification\nAt execution boundary\n(PEP)\nTarget: <1ms"]
        DP4["Audit Event Emission\nAsync append to\nimmutable store\nTarget: non-blocking"]
    end

    CP1 -.->|"Signed policy\nbundle push"| DP1
    CP2 -.->|"Cert provisioning\nvia SPIFFE"| DP2
    CP3 -.->|"Provenance\ncert distribution"| DP1

    style CP1 fill:#264653,color:#fff
    style CP2 fill:#264653,color:#fff
    style CP3 fill:#264653,color:#fff
    style CP4 fill:#264653,color:#fff
    style DP1 fill:#e76f51,color:#fff
    style DP2 fill:#e76f51,color:#fff
    style DP3 fill:#e76f51,color:#fff
    style DP4 fill:#e76f51,color:#fff
```

The control plane is secured with higher privilege and lower frequency access. The data plane is optimized for per-action evaluation at low latency. Policy bundles are signed and pushed to local PDP caches - the data plane never calls back to the control plane during action evaluation. This eliminates the control plane as a latency bottleneck and as a single point of failure.

**Latency budget for the full trust layer inline path:**

| Step | Target p99 | Notes |
|---|---|---|
| Policy evaluation (PDP) | <5ms | Local OPA evaluation against cached signed bundle |
| Cryptographic signing | <2ms | Ed25519 is fast; HSM-backed ES256 adds ~1ms |
| Signature verification (PEP) | <1ms | Ed25519 verify is sub-millisecond |
| Audit emission | 0ms (async) | Fire-and-forget to local buffer, batched to store |
| **Total inline overhead** | **<8ms p99** | Comparable to a service mesh sidecar hop |

For context: an LLM inference call takes 500ms-5s. An 8ms enforcement layer is noise.

---

## 7. The Signed Action Envelope (SAE)

The atomic unit of trust. A JWS-format object that cryptographically binds identity, policy, action, provenance, and timestamp into a single verifiable artifact.

```mermaid
graph TB
    subgraph "SAE Structure (JWS Compact Serialization)"
        direction TB
        HEADER["JOSE Header\nalg: EdDSA (Ed25519) | ES256\nkid: SHA-256 fingerprint of signing cert\ntyp: application/sae+jwt\nx5c: certificate chain (optional)"]

        subgraph "Payload Claims"
            direction TB
            C1["iss - Issuer\nAgent X.509 Subject DN\ne.g. CN=agent-procurement-prod-01,\nOU=finance,O=acme-corp"]
            C2["sub - Subject (target)\nAPI endpoint or service identifier\ne.g. api.vendor.com/v2/orders"]
            C3["act - Action descriptor\nStructured intent: method, params,\nclassification (PII/financial/infra)"]
            C4["pol - Policy binding\nSHA-256 of OPA bundle evaluated\n+ policy version + decision ID"]
            C5["mod - Model provenance\nSHA-256 of model artifact\n+ SBOM reference + SLSA level"]
            C6["iat / exp / nbf - Temporal\nIssued-at, expiry (short: 30-300s),\nnot-before (prevents pre-dating)"]
            C7["jti - Unique ID (nonce)\nPrevents replay attacks\nIdempotency key for execution"]
            C8["ctx - Execution context\nSession ID, parent SAE chain hash,\nrisk score, data classification level"]
        end

        SIG["Signature\nEd25519 over BASE64URL(header).BASE64URL(payload)\nVerifiable by any party holding the public key"]
    end

    HEADER --> C1
    C1 --- C2 --- C3 --- C4 --- C5 --- C6 --- C7 --- C8
    C8 --> SIG

    style HEADER fill:#264653,color:#fff
    style SIG fill:#9d0208,color:#fff
```

**What this gives you that logs do not:**

| Property | How |
|---|---|
| Non-repudiation | Asymmetric signature - the signing key is in HSM, not on the agent |
| Integrity | Any byte change invalidates the signature |
| Replay prevention | Short-lived expiry + unique `jti` nonce |
| Policy binding | `pol` claim locks the exact policy version evaluated - detects retroactive policy changes |
| Provenance binding | `mod` claim locks the exact model hash - detects model swaps |
| Causal chaining | `ctx.parent_chain` links multi-step agent workflows into a verifiable DAG |
| Independent verifiability | Any party with the public key and OCSP response can verify, offline |

---

## 8. Multi-Agent Workflow: Chain of Custody

Real agent systems are not single-step. A procurement workflow might chain 4-5 agents across systems. The trust layer maintains cryptographic chain of custody across the entire execution DAG.

```mermaid
sequenceDiagram
    participant U as User / Trigger
    participant A1 as Agent: Request Analyzer
    participant TL as Trust Layer
    participant A2 as Agent: Budget Checker
    participant A3 as Agent: Approval Router
    participant A4 as Agent: PO Generator
    participant ERP as ERP System

    U->>A1: "Order 500 units of part X from Vendor Y"
    A1->>TL: Propose: classify request (SAE₀ - root)
    TL->>TL: Evaluate policy → ALLOW → sign SAE₁
    TL->>A1: SAE₁ (parent: root)

    A1->>A2: Forward: check budget
    A2->>TL: Propose: query budget API (parent: SAE₁)
    TL->>TL: Evaluate → ALLOW → sign SAE₂
    TL->>A2: SAE₂ (parent: SAE₁)

    A2->>A3: Forward: budget approved, route for sign-off
    A3->>TL: Propose: request human approval (parent: SAE₂)
    TL->>TL: Evaluate → ALLOW (requires human for >$10k) → sign SAE₃
    TL->>A3: SAE₃ (parent: SAE₂, pending: human_approval)

    Note over A3,TL: Human approver signs off (out of band)

    A3->>A4: Forward: approved, generate PO
    A4->>TL: Propose: create PO in ERP (parent: SAE₃ + human sig)
    TL->>TL: Evaluate → ALLOW (human approval verified) → sign SAE₄
    TL->>A4: SAE₄ (parent: SAE₃)
    A4->>ERP: Execute PO creation with SAE₄

    Note over U,ERP: Full chain: SAE₁ → SAE₂ → SAE₃ → SAE₄
    Note over U,ERP: Any SAE can be independently verified
    Note over U,ERP: Causal DAG is reconstructable from parent hashes
```

Every step is independently signed. The `parent_chain` field in each SAE points to the hash of the previous SAE, forming a verifiable directed acyclic graph. During incident response or audit, the entire causal chain can be reconstructed and cryptographically verified - from trigger to execution.

---

## 9. Kill Chain & Mitigation Mapping

Mapping trust layer controls against an AI-specific attack lifecycle.

```mermaid
graph TB
    subgraph "AI Agent Kill Chain → Trust Layer Coverage"
        direction TB

        KC1["1. RECONNAISSANCE\nMap agent capabilities,\ntool access, permission scope"]
        M1["Agent capability obfuscation\nMinimal tool surface exposure"]

        KC2["2. SUPPLY CHAIN\nPoisoned weights, malicious adapters,\nbackdoored dependencies"]
        M2["Model provenance (AI-SBOM)\nSLSA attestation\nRuntime hash verification\nSCA for model dependencies"]

        KC3["3. INITIAL ACCESS\nPrompt injection, RAG poisoning,\njailbreak, context manipulation"]
        M3["Guardrails handle input filtering.\nTrust layer ensures: even if injection\nsucceeds, execution requires signed\nauthorization the agent cannot forge"]

        KC4["4. EXECUTION\nUnauthorized API calls,\nparameter tampering, replay"]
        M4["Policy-gated signing\nSAE with nonce + expiry\nTOCTOU-safe atomic binding"]

        KC5["5. PRIVILEGE ESCALATION\nTool chaining, inherited permissions,\nservice account abuse"]
        M5["Per-action least privilege\nJIT credential scoping\nNo standing agent permissions\nShort-lived certs (24h)"]

        KC6["6. LATERAL MOVEMENT\nAgent-to-agent pivoting,\ncross-system traversal"]
        M6["mTLS agent mesh\nSigned cross-agent SAEs\nEgress/ingress policy gates\nAgent allowlisting"]

        KC7["7. IMPACT\nData exfiltration, financial fraud,\ninfra damage, reputational harm"]
        M7["Immutable audit trail\nReal-time anomaly detection\nAutomatic agent quarantine\nForensic chain of custody"]
    end

    KC1 --- M1
    KC2 --- M2
    KC3 --- M3
    KC4 --- M4
    KC5 --- M5
    KC6 --- M6
    KC7 --- M7

    style KC1 fill:#264653,color:#fff
    style KC2 fill:#264653,color:#fff
    style KC3 fill:#264653,color:#fff
    style KC4 fill:#264653,color:#fff
    style KC5 fill:#264653,color:#fff
    style KC6 fill:#264653,color:#fff
    style KC7 fill:#264653,color:#fff
    style M2 fill:#e76f51,color:#fff
    style M3 fill:#e76f51,color:#fff
    style M4 fill:#e76f51,color:#fff
    style M5 fill:#e76f51,color:#fff
    style M6 fill:#e76f51,color:#fff
    style M7 fill:#e76f51,color:#fff
```

Existing AI security operates primarily at Stage 3 (input filtering). The trust layer covers Stages 2, 4, 5, 6, and 7 - where autonomous execution creates actual damage.

---

## 10. Integration Architecture: SIEM / XDR / SOAR

The trust layer is not a standalone product. It emits structured events into the existing security operations stack and consumes signals from it.

```mermaid
graph TB
    subgraph "Trust Layer Event Emission"
        SAE_EVENTS["SAE Lifecycle Events\naction.authorized\naction.denied\naction.expired\naction.replayed (attempted)"]
        PROV_EVENTS["Provenance Events\nmodel.registered\nmodel.hash_mismatch\nmodel.cert_revoked\nmodel.drift_detected"]
        POLICY_EVENTS["Policy Events\npolicy.evaluated\npolicy.denied\npolicy.drift_detected\npolicy.bundle_updated"]
        CERT_EVENTS["Certificate Events\ncert.issued\ncert.rotated\ncert.revoked\ncert.expiry_warning"]
    end

    subgraph "Integration Layer"
        NORM["Event Normalization\nCEF · LEEF · OCSF\n(Open Cybersecurity\nSchema Framework)"]
    end

    subgraph "Security Operations"
        SIEM["SIEM / XDR\n(Splunk · Sentinel\n· QRadar · Chronicle)"]
        SOAR["SOAR\n(Phantom · Tines\n· Torq · Swimlane)"]
        TIP["Threat Intel Platform\nAgent behavioral IOCs\nModel supply chain IOCs"]
    end

    SAE_EVENTS --> NORM
    PROV_EVENTS --> NORM
    POLICY_EVENTS --> NORM
    CERT_EVENTS --> NORM

    NORM --> SIEM
    SIEM -->|"Correlation rules\ntrigger playbooks"| SOAR
    SOAR -->|"Automated response:\nrevoke cert, quarantine\nagent, block model"| SAE_EVENTS
    SIEM --> TIP

    subgraph "Inbound Signals (consumed by Trust Layer)"
        RISK["Risk Scoring Feeds\nUser risk score from UEBA\nEndpoint risk from XDR\nNetwork anomalies from NDR"]
    end

    RISK -->|"Dynamic policy\ninput signals"| POLICY_EVENTS

    style NORM fill:#e76f51,color:#fff
    style SIEM fill:#264653,color:#fff
    style SOAR fill:#264653,color:#fff
```

The integration is bidirectional. The trust layer emits events into SIEM for correlation and alerting. SOAR playbooks can call back into the trust layer to revoke certificates, quarantine agents, or block models. Risk scores from XDR/UEBA feed into the policy engine as dynamic context - so a high-risk endpoint score can automatically elevate the policy threshold for agents running on that endpoint.

**Event schema:** All events conform to OCSF (Open Cybersecurity Schema Framework) for vendor-neutral ingestion, with CEF/LEEF mappings for legacy SIEM compatibility.

---

## 11. Runtime Attestation: Continuous Verification

Deployment-time verification is insufficient. The trust layer performs continuous runtime checks on five dimensions.

```mermaid
graph LR
    subgraph "Attestation Checks (continuous cycle)"
        direction TB
        R1["MODEL INTEGRITY\nPeriodic hash of loaded weights\nvs. signed provenance cert.\nFrequency: every 60s + on each action"]
        R2["POLICY STATE\nHash of active policy bundle\nvs. last signed version from\ncontrol plane.\nFrequency: every 30s"]
        R3["BEHAVIORAL BASELINE\nAction frequency, API call patterns,\nresource access scope vs.\nestablished baseline.\nMethod: statistical + ML anomaly"]
        R4["CERTIFICATE HEALTH\nOCSP check, expiry countdown,\nrevocation status.\nMethod: OCSP stapling on\nevery SAE issuance"]
        R5["ENVIRONMENT INTEGRITY\nTPM-backed remote attestation\nof runtime host. Secure enclave\nverification (SGX · TDX · SEV-SNP)\nwhere available"]
    end

    R1 --> V{"Attestation\nVerdict"}
    R2 --> V
    R3 --> V
    R4 --> V
    R5 --> V

    V -->|"HEALTHY"| CONT["Continue\nRefresh attestation token\nAttach to next SAE"]
    V -->|"DEGRADED"| DEG["Elevated scrutiny\nReduce trust score\nTighten policy thresholds\nAlert SOC (P3)"]
    V -->|"FAILED"| BLOCK["Quarantine agent\nRevoke certificate\nKill signing capability\nSOC alert (P1)\nSOAR playbook: isolate"]

    style V fill:#e76f51,color:#fff
    style BLOCK fill:#9d0208,color:#fff
    style DEG fill:#e9c46a,color:#000
    style CONT fill:#2d6a4f,color:#fff
```

The three-state model (healthy / degraded / failed) avoids the binary problem of hard-blocking on transient issues. A degraded state tightens controls without killing the agent - similar to how EDR can quarantine a process vs. killing it.

---

## 12. Immutable Audit: Tiered Anchoring

Not every AI event needs cryptographic immutability. The trust layer applies tiered anchoring based on trust criticality.

```mermaid
graph TB
    subgraph "Event Tiers"
        TIER1["TIER 1 - Operational\nInference calls · debug traces\nperformance metrics\n→ Standard log pipeline"]
        TIER2["TIER 2 - Security\nPolicy denials · anomaly detections\nguardrail triggers · access denials\n→ SIEM + SOC triage"]
        TIER3["TIER 3 - Trust-Critical\nSigned action executions · model deployments\npolicy changes · cross-org interactions\ncert issuance/revocation\n→ Cryptographic anchoring"]
    end

    TIER1 -->|"Syslog / OCSF"| SIEM["SIEM / Log Store"]
    TIER2 -->|"OCSF + enrichment"| SIEM
    TIER3 -->|"Signed event + Merkle proof"| MERKLE["Merkle Tree\n(append-only · hash-chained)"]

    MERKLE -->|"Root hash published\nevery N minutes"| TLOG["Transparency Log\n(independently verifiable\nby any party)"]
    MERKLE -->|"On-demand\nproof export"| AUDIT["Regulator / Auditor\nPackage"]
    MERKLE -->|"Forensic query\nby SAE chain"| IR["Incident Response\nEvidence Bundle"]

    style TIER3 fill:#e76f51,color:#fff
    style MERKLE fill:#264653,color:#fff
    style TLOG fill:#2a9d8f,color:#fff
```

The transparency log model is borrowed from Certificate Transparency (RFC 6962). Merkle roots are published on a fixed schedule. Any party can independently verify that a specific event was included in the log at the claimed time - without trusting the log operator.

---

## 13. Incident Response: Forensic Workflow

Scenario: SOC detects an unauthorized $200k wire transfer initiated by an AI agent.

```mermaid
sequenceDiagram
    participant SOC as SOC Analyst
    participant XSIAM as SIEM / XDR
    participant TL as Trust Layer API
    participant AUDIT as Immutable Store
    participant XSOAR as SOAR Platform

    Note over SOC,XSOAR: T+0: Alert fires - anomalous financial action

    SOC->>XSIAM: Triage alert: agent-finance-prod-03, $200k transfer
    XSIAM->>TL: Query: SAE chain for transaction ID TXN-4829
    TL->>AUDIT: Retrieve Merkle proof + full SAE chain
    AUDIT-->>TL: 6 SAEs in causal chain + Merkle inclusion proofs
    TL-->>XSIAM: Enriched forensic timeline

    Note over SOC,XSOAR: T+2min: SOC has cryptographic answers

    SOC->>SOC: Agent identity: CN=agent-finance-prod-03 (cert valid at time)
    SOC->>SOC: Model: SHA-256 a3f8c2... (matches approved provenance)
    SOC->>SOC: Policy: v2.7.1 hash b91d0e... (MISMATCH - policy was altered)
    SOC->>SOC: Root cause: policy drift at T-3h allowed $200k without dual auth

    Note over SOC,XSOAR: T+3min: Automated containment

    SOC->>XSOAR: Trigger playbook: compromised-policy-response
    XSOAR->>TL: Revoke agent-finance-prod-03 certificate
    XSOAR->>TL: Roll back policy to last signed good version (v2.7.0)
    XSOAR->>TL: Quarantine all agents evaluating policy v2.7.1
    TL-->>XSOAR: Confirmation: 3 agents quarantined, certs revoked
```

Without the trust layer: the SOC reconstructs this from scattered, mutable logs across 4+ systems. It takes days. The evidence is legally contestable. With the trust layer: cryptographic proof in minutes, including the exact policy version that was tampered with.

---

## 14. Defense-in-Depth: Where This Sits

```mermaid
graph TB
    subgraph "Enterprise AI Security Stack"
        direction TB
        L5["LAYER 5 - AI Application Security\nPrompt filtering · output guardrails · content moderation\nDLP for AI outputs · PII/PHI scanning\n(AI security platforms)"]
        L4["LAYER 4 - Agent Governance\nRBAC/ABAC for agents · tool permissions\nrate limiting · human-in-the-loop gates\n(AI platforms + IAM)"]
        L3["LAYER 3 - Cryptographic Trust\nAction signing · policy-gated execution\nmodel provenance · runtime attestation\nagent PKI · immutable audit"]
        L2["LAYER 2 - Platform Security\nContainer security · secrets management\nmicrosegmentation · API gateway · CWPP\n(CNAPP platforms)"]
        L1["LAYER 1 - Infrastructure Security\nCSPM · XDR · NDR · endpoint protection\n(Security operations platforms)"]
    end

    L5 --> L4 --> L3 --> L2 --> L1

    L5 -.->|"Content decisions"| L3
    L4 -.->|"Access decisions"| L3
    L3 -.->|"Cryptographic enforcement"| L2
    L1 -.->|"Risk signals (XDR/NDR)"| L3

    style L3 fill:#e76f51,color:#fff
```

Layer 3 does not replace anything above or below it. It makes the decisions at every other layer **provable**. Layer 5 detects a risky prompt - Layer 3 proves the action was blocked. Layer 4 decides an agent lacks permission - Layer 3 produces a signed denial. Layer 1 detects an endpoint anomaly - Layer 3 consumes that signal to tighten policy thresholds.

---

## 15. Zero Trust for AI: NIST 800-207 Mapping

| NIST ZTA Principle | Traditional Implementation | AI Trust Layer Implementation |
|---|---|---|
| All resources require verification | Device posture, user identity | Agent identity (X.509), model provenance, tool attestation |
| Communication secured regardless of location | mTLS, VPN, ZTNA | mTLS agent mesh + signed action envelopes |
| Per-session resource access | Session tokens, JIT access | Per-action policy evaluation, no standing privileges |
| Dynamic policy enforcement | ABAC, risk-adaptive access | OPA/Rego with real-time context (risk score, time, classification) |
| Continuous monitoring of asset posture | EDR, UEBA, vulnerability scanning | Runtime attestation (model hash, policy drift, behavior baseline) |
| Strict authentication and authorization | MFA, SSO, conditional access | Cryptographic enforcement - no execution without valid SAE |

---

## 16. Regulatory Alignment

| Regulation | Key Requirement | Trust Layer Mapping |
|---|---|---|
| **EU AI Act** | Traceability, logging, human oversight for high-risk AI | SAE chain of custody, policy-gated human escalation |
| **NIST AI RMF** | Govern, Map, Measure, Manage AI risk | Provenance, attestation, continuous policy evaluation |
| **SOX §404** | Internal controls over financial reporting | Signed authorization for financial AI actions |
| **DORA** | Digital operational resilience (EU financial sector) | Immutable audit, incident reconstruction, third-party agent risk |
| **PCI DSS v4.0** | Cardholder data protection | DLP integration via policy engine, signed actions on payment APIs |
| **FedRAMP / FISMA** | Continuous monitoring, tamper-evident logging | Runtime attestation, Merkle-anchored audit |
| **ISO 27001:2022** | Information security management | Agent PKI, access control, audit trail |

---

## 17. Market Timing

```mermaid
timeline
    title Convergence Window
    2023 : AI generates text - blast radius is low
         : AI security = guardrails and prompt filtering
         : No regulatory framework for AI actions
    2024 : Agentic AI enters production
         : EU AI Act finalized - DORA effective
         : First enterprise AI agent incidents reported
         : Security teams realize: logs are not proof
    2025 : Multi-agent systems cross organizational boundaries
         : AI audit requirements become active
         : Cyber insurance begins requiring AI action provenance
         : CISOs shift budget from dashboards to guarantees
    2026+ : AI systems held to the same standard as financial systems
          : Cryptographic trust for AI becomes table stakes
          : The trust layer becomes invisible infrastructure
```

---

## Appendix A: Glossary

| Term | Definition |
|---|---|
| **SAE** | Signed Action Envelope - JWS object binding agent identity, policy, action, provenance, and timestamp into a single verifiable artifact |
| **PDP** | Policy Decision Point - evaluates whether an action is permitted under current policy |
| **PEP** | Policy Enforcement Point - verifies SAE signature at execution boundary; rejects unsigned actions |
| **AI-SBOM** | AI Software Bill of Materials - manifest of model components: base model, fine-tune data, adapters, dependencies |
| **SLSA** | Supply-chain Levels for Software Artifacts - framework for supply chain integrity applied to model provenance |
| **SPIFFE/SPIRE** | Secure Production Identity Framework - standard for issuing and rotating workload identities; used for agent certificate provisioning |
| **OPA/Rego** | Open Policy Agent - policy-as-code engine; Rego is its declarative query language |
| **Cedar** | Amazon's policy language - alternative to Rego for fine-grained authorization |
| **OCSF** | Open Cybersecurity Schema Framework - vendor-neutral event schema for SIEM interoperability |
| **CEF/LEEF** | Common Event Format / Log Event Extended Format - standard event formats for SIEM ingestion |
| **TOCTOU** | Time-of-Check to Time-of-Use - race condition between policy evaluation and action execution |
| **OCSP** | Online Certificate Status Protocol - real-time certificate revocation checking |
| **mTLS** | Mutual TLS - both parties authenticate via certificates during TLS handshake |
| **HSM** | Hardware Security Module - tamper-resistant hardware for key storage and cryptographic operations |
| **Merkle Tree** | Hash tree structure where each leaf is hashed and combined upward; enables efficient and verifiable proof of inclusion |

---

## Appendix B: Open Questions

Areas where I am looking for feedback and pressure-testing from security leaders.

1. **Build vs. buy signal** - At what point do enterprise security platforms absorb this as a feature vs. this standing alone as a category? What signals should I watch for?
2. **Agent identity standard** - No industry standard exists yet for AI agent identity. Is this a SPIFFE extension? A new X.509 profile? Or something entirely new?
3. **Policy language** - OPA/Rego vs. Cedar vs. custom DSL. What are enterprises actually adopting for policy-as-code today?
4. **Confidential computing** - How far should I push TEE-based attestation (SGX/TDX/SEV-SNP) vs. software-only? Is customer readiness there?
5. **Multi-cloud key management** - Unified HSM abstraction across AWS KMS, Azure Key Vault, GCP Cloud HSM, or vendor-specific integrations first?
6. **Scale testing** - What happens at 10,000 agents generating 1M+ SAEs per hour? Where do the Merkle tree and audit store become bottlenecks?
7. **Go-to-market** - Should this land first with the CISO organization, platform engineering, or AI/ML teams? Who owns this budget?
