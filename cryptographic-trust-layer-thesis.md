# Cryptographic Trust Layer for Enterprise AI

**Thesis:** As AI systems shift from generating outputs to executing actions, enterprises need a cryptographic enforcement layer that makes AI behavior verifiable, policy-bound, and auditable - with the same guarantees applied to financial transactions and code signing today.

---

## The Big Picture (10,000ft View)

**The Problem in Plain English:**

Today's AI takes actions. AI agents send emails, move money, change infrastructure settings, and coordinate with other AI agents, autonomously, faster than any human could review.

But here's the problem: there's no way to **prove** who authorized an AI to do something, what rules it was following, or whether those rules were tampered with. It's like having employees who can sign any contract, access any account, and make any purchase, with no receipts, no signatures, and no audit trail.

Current AI security tools (guardrails, prompt filters, logging) are like putting a suggestion box at the door of a bank vault. They *ask* AI to behave. They don't *enforce* it.

**What We're Building:**

A cryptographic enforcement layer that applies the same trust guarantees we require for financial transactions and code signing to every AI agent action. Before any agent can execute a consequential action, three things must happen:

1. **Identity verification** -- the agent authenticates via short-lived X.509 certificate, proving exactly which agent, running which model version, is requesting execution
2. **Policy-gated authorization** -- the action is evaluated against signed, versioned policy in real time. No standing privileges. Every action is individually adjudicated
3. **Cryptographic proof of authorization** -- the trust layer issues a signed, timestamped, non-repudiable receipt (Signed Action Envelope) binding identity, policy, and action into a single verifiable artifact

No valid signature, no execution. Not flagged. Not logged for later. **Blocked.**

```mermaid
graph LR
    A["AI Agent<br/>wants to do something"] --> B["Trust Layer<br/>checks identity + policy"]
    B -->|"Approved"| C["Signed Receipt<br/>cryptographic proof"]
    C --> D["Action Executes<br/>with verifiable proof"]
    B -->|"Denied"| E["Action Blocked<br/>denial on record"]

    style B fill:#e76f51,color:#fff
    style C fill:#2a9d8f,color:#fff
    style E fill:#9d0208,color:#fff
```

**A Simple Analogy:**

Think of how credit card transactions work today:
- Your card has an **identity** (card number, chip, issuing bank)
- Each purchase is **authorized in real-time** (Is this card valid? Is there enough credit? Is this purchase suspicious?)
- Every transaction produces a **signed, timestamped record** that both the bank and merchant can independently verify
- If the card is stolen, it can be **revoked instantly**, and all future transactions are blocked

We're building the exact same thing, but for AI agent actions instead of credit card purchases. Every AI action gets an identity check, a policy check, a cryptographic receipt, and the ability to be revoked in real-time.

**Three guarantees this provides:**

| Guarantee | What it means | Why it matters |
|---|---|---|
| **Verifiable** | Anyone can independently check if an AI action was properly authorized | No more "trust us, the AI was supposed to do that" |
| **Tamper-proof** | The record of what happened cannot be altered after the fact | Regulators, auditors, and incident responders get evidence, not just logs |
| **Enforceable** | Without cryptographic authorization, the action physically cannot execute | A locked gate, not a guardrail or a suggestion |

---

## 2. Threat Model: AI Agent Attack Surface

Nine attack vectors specific to agentic AI systems, mapped against what existing controls cover and where the gaps are.

```mermaid
graph LR
    subgraph "AI Agent Attack Chain"
        direction LR
        T1["T1 - Model Supply Chain<br/>Poisoned weights, backdoored adapters,<br/>typosquatted repos, training data attacks"]
        T2["T2 - Input Manipulation<br/>Prompt injection, RAG poisoning,<br/>jailbreaks, context manipulation"]
        T3["T3 - Identity and Authorization<br/>Agent impersonation, credential theft,<br/>privilege escalation via tool chaining"]
        T4["T4 - Action Execution<br/>Unauthorized API calls, replay attacks,<br/>TOCTOU between policy and execution"]
        T5["T5 - Output Integrity<br/>Insecure outputs, malicious URLs,<br/>code injection via generated content"]
        T6["T6 - Data Exfiltration<br/>Sensitive data leaks via model responses,<br/>training data extraction, PII exposure"]
        T7["T7 - Confabulation<br/>Hallucinated outputs presented as fact,<br/>fabricated citations, false attestations"]
        T8["T8 - Observability<br/>Log tampering, silent policy drift,<br/>broken causal chains across workflows"]
        T9["T9 - Cross-Boundary<br/>Rogue agent-to-agent traffic,<br/>unverified inter-org interactions"]
    end

    T1 --> T2 --> T3 --> T4 --> T5 --> T6 --> T7 --> T8 --> T9

    style T1 fill:#03071e,color:#fff
    style T2 fill:#370617,color:#fff
    style T3 fill:#6a040f,color:#fff
    style T4 fill:#9d0208,color:#fff
    style T5 fill:#d00000,color:#fff
    style T6 fill:#dc2f02,color:#fff
    style T7 fill:#e85d04,color:#fff
    style T8 fill:#f48c06,color:#fff
    style T9 fill:#faa307,color:#000
```

| Vector | Existing Coverage | Trust Layer Role |
|---|---|---|
| T1 - Supply Chain | SCA tools scan code dependencies; AI security platforms add model scanning and deserialization checks | Trust layer adds runtime hash verification, AI-SBOM provenance binding, and SLSA attestation -- proving the model in production matches the model that was approved |
| T2 - Input Manipulation | Guardrails, prompt filters, content classification | Addressed at input by runtime security platforms. Trust layer hardens the boundary: even if injection succeeds, execution requires signed authorization |
| T3 - Identity | IAM, RBAC, posture management | Agents inherit service account privileges. Trust layer enforces per-agent, per-action cryptographic identity via short-lived X.509 certificates |
| T4 - Execution | API gateways, rate limits, agent policy enforcement | No cryptographic binding between policy decision and action execution. Trust layer closes this with signed action envelopes and TOCTOU-safe enforcement |
| T5 - Output Integrity | AI runtime security platforms scan outputs for malicious content, URLs, and code injection | Trust layer adds signed provenance: the output can be traced back to the exact agent, model version, and policy that produced it |
| T6 - Data Exfiltration | DLP, content filtering, topic guardrails in AI agent security platforms | Trust layer adds policy-gated enforcement on data-touching actions: outbound data transfers require signed authorization matching data classification policy |
| T7 - Confabulation | Hallucination detection via grounding checks against knowledge sources | Outside the trust layer's scope. This is a model fidelity problem best addressed at the application and runtime security layer |
| T8 - Observability | SIEM, logging, continuous monitoring platforms | Logs are mutable. Trust layer provides tamper-evident, Merkle-anchored chain of custody for all AI actions |
| T9 - Cross-Boundary | mTLS at network layer | No application-layer agent identity. Trust layer adds signed intent verification and cross-agent SAE chains |

The trust layer closes T1, T3, T4, T8, and T9 directly. It strengthens T2, T5, and T6 by adding cryptographic enforcement beneath existing runtime security controls. T7 (confabulation) is correctly addressed at the application layer and is out of scope for cryptographic enforcement.

---

## 3. Architecture Overview

```mermaid
graph TB
    subgraph "AI Agent Runtime"
        A["Agent<br/>(reasoning engine)"] -->|"Proposes action<br/>(untrusted intent)"| B["Structured<br/>Action Request"]
    end

    subgraph "Cryptographic Trust Layer"
        B --> PDP{"Policy Decision<br/>Point (PDP)"}
        PDP -->|"Evaluate"| PE["Policy Engine<br/>(OPA/Rego · Cedar)"]
        PE -->|ALLOW| CS["Signing Service<br/>(Ed25519 · ES256)"]
        PE -->|DENY| DR["Signed Denial<br/>Record"]
        CS --> SAE["Signed Action<br/>Envelope (SAE)"]
    end

    subgraph "Execution Boundary"
        SAE -->|"Signature verified<br/>before execution"| PEP["Policy Enforcement<br/>Point (PEP)"]
        PEP --> TGT["Target System<br/>(API · Service · Infra)"]
    end

    subgraph "Audit Plane"
        CS --> MA["Merkle<br/>Anchoring"]
        DR --> MA
        MA --> IAS["Immutable Audit Store<br/>(append-only · hash-chained)"]
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
        A1["Agent Process"] --> A2["Trust Sidecar<br/>(PDP + PEP)"]
        A2 --> A3["Target API"]
        A2 --> A4["Audit Plane"]
    end

    subgraph "Model B - Gateway (Centralized Choke Point)"
        direction LR
        B1["Agent 1"] --> B4["Trust Gateway<br/>(reverse proxy)"]
        B2["Agent 2"] --> B4
        B3["Agent 3"] --> B4
        B4 --> B5["Target APIs"]
        B4 --> B6["Audit Plane"]
    end

    subgraph "Model C - SDK (Embedded in Agent Framework)"
        direction LR
        C1["Agent Framework<br/>(LangChain · CrewAI)"] --> C2["Trust SDK<br/>(library calls)"]
        C2 --> C3["Remote Signing Service<br/>(keys never local)"]
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
        ROOT["Root CA<br/>Offline · HSM-backed · Air-gapped<br/>Lifetime: 10 years"]
        INT["Intermediate CA - Agent Identity<br/>Online · HSM · FIPS 140-2 L3<br/>Lifetime: 2 years"]
        INT2["Intermediate CA - Policy Signing<br/>Online · HSM-backed<br/>Lifetime: 2 years"]
        INT3["Intermediate CA - Audit Anchoring<br/>Online · HSM-backed<br/>Lifetime: 2 years"]

        ROOT --> INT
        ROOT --> INT2
        ROOT --> INT3

        AGENT1["Agent Cert<br/>agent-procurement-prod-01<br/>24h lifetime · Ed25519 · auto-rotated"]
        AGENT2["Agent Cert<br/>agent-finance-prod-03<br/>24h lifetime · Ed25519"]
        POLICY["Policy Signing Cert<br/>Signs OPA/Rego bundles<br/>90-day lifetime"]

        INT --> AGENT1
        INT --> AGENT2
        INT2 --> POLICY
    end

    subgraph "Key Storage"
        HSM["HSM / Cloud KMS<br/>AWS KMS · Azure Key Vault<br/>GCP Cloud HSM · FIPS 140-2 L3"]
        AGENT_STORE["Ephemeral Key Store<br/>In-memory only · never persisted<br/>Provisioned via SPIFFE/SPIRE"]
    end

    INT --> HSM
    AGENT1 --> AGENT_STORE

    subgraph "Revocation"
        OCSP["OCSP Responder<br/>Stapled to every SAE<br/>Real-time revocation check"]
        CRL["CRL Distribution Point<br/>Delta CRLs every 5 minutes"]
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
        CP1["Policy Management<br/>Version, sign, distribute<br/>OPA/Rego bundles"]
        CP2["Certificate Lifecycle<br/>Issue, rotate, revoke<br/>agent certificates"]
        CP3["Model Registry<br/>Register, attest, revoke<br/>model provenance"]
        CP4["Audit Configuration<br/>Anchoring frequency,<br/>retention, transparency log"]
    end

    subgraph "Data Plane (high frequency, low latency)"
        DP1["Policy Evaluation<br/>Per-action PDP calls<br/>Target: p99 under 5ms"]
        DP2["Action Signing<br/>Ed25519 per action<br/>Target: under 2ms"]
        DP3["Signature Verification<br/>At PEP boundary<br/>Target: under 1ms"]
        DP4["Audit Event Emission<br/>Async append to store<br/>Target: non-blocking"]
    end

    CP1 -.->|"Signed policy<br/>bundle push"| DP1
    CP2 -.->|"Cert provisioning<br/>via SPIFFE"| DP2
    CP3 -.->|"Provenance<br/>cert distribution"| DP1

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
        HEADER["JOSE Header<br/>alg: EdDSA or ES256<br/>kid: SHA-256 fingerprint<br/>typ: application/sae+jwt"]

        subgraph "Payload Claims"
            direction TB
            C1["iss - Issuer<br/>Agent X.509 Subject DN"]
            C2["sub - Subject<br/>Target API endpoint or service"]
            C3["act - Action descriptor<br/>Method, params, classification"]
            C4["pol - Policy binding<br/>SHA-256 of evaluated OPA bundle"]
            C5["mod - Model provenance<br/>SHA-256 of model artifact + SBOM ref"]
            C6["iat / exp / nbf - Temporal<br/>Issued-at, expiry (30-300s), not-before"]
            C7["jti - Unique ID<br/>Nonce for replay prevention"]
            C8["ctx - Execution context<br/>Session ID, parent SAE chain hash,<br/>risk score, data classification"]
        end

        SIG["Signature<br/>Ed25519 over header.payload<br/>Verifiable by any party with public key"]
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
    A1->>TL: Propose: classify request (root)
    TL->>TL: Evaluate policy, ALLOW, sign SAE1
    TL->>A1: SAE1 (parent: root)

    A1->>A2: Forward: check budget
    A2->>TL: Propose: query budget API (parent: SAE1)
    TL->>TL: Evaluate, ALLOW, sign SAE2
    TL->>A2: SAE2 (parent: SAE1)

    A2->>A3: Forward: budget approved, route for sign-off
    A3->>TL: Propose: request human approval (parent: SAE2)
    TL->>TL: Evaluate, ALLOW (requires human for > $10k), sign SAE3
    TL->>A3: SAE3 (parent: SAE2, pending: human_approval)

    Note over A3,TL: Human approver signs off (out of band)

    A3->>A4: Forward: approved, generate PO
    A4->>TL: Propose: create PO in ERP (parent: SAE3 + human sig)
    TL->>TL: Evaluate, ALLOW (human approval verified), sign SAE4
    TL->>A4: SAE4 (parent: SAE3)
    A4->>ERP: Execute PO creation with SAE4

    Note over U,ERP: Full chain: SAE1 -> SAE2 -> SAE3 -> SAE4
    Note over U,ERP: Any SAE can be independently verified
    Note over U,ERP: Causal DAG is reconstructable from parent hashes
```

Every step is independently signed. The `parent_chain` field in each SAE points to the hash of the previous SAE, forming a verifiable directed acyclic graph. During incident response or audit, the entire causal chain can be reconstructed and cryptographically verified - from trigger to execution.

---

## 9. Kill Chain & Mitigation Mapping

Mapping trust layer controls against an AI-specific attack lifecycle.

```mermaid
graph TB
    subgraph "AI Agent Kill Chain with Trust Layer Coverage"
        direction TB

        KC1["1. RECONNAISSANCE<br/>Map agent capabilities and scope"]
        M1["Mitigation: Capability obfuscation,<br/>minimal tool surface exposure"]

        KC2["2. SUPPLY CHAIN<br/>Poisoned weights, malicious adapters"]
        M2["Mitigation: Model provenance via AI-SBOM,<br/>SLSA attestation, runtime hash verification"]

        KC3["3. INITIAL ACCESS<br/>Prompt injection, RAG poisoning"]
        M3["Mitigation: Even if injection succeeds,<br/>execution requires signed authorization"]

        KC4["4. EXECUTION<br/>Unauthorized API calls, replay"]
        M4["Mitigation: Policy-gated signing,<br/>SAE with nonce + expiry, TOCTOU-safe"]

        KC5["5. PRIVILEGE ESCALATION<br/>Tool chaining, inherited permissions"]
        M5["Mitigation: Per-action least privilege,<br/>JIT scoping, short-lived certs (24h)"]

        KC6["6. LATERAL MOVEMENT<br/>Agent-to-agent pivoting"]
        M6["Mitigation: mTLS agent mesh,<br/>signed cross-agent SAEs, allowlisting"]

        KC7["7. OUTPUT MANIPULATION<br/>Insecure outputs, malicious content,<br/>data exfiltration via responses"]
        M7["Mitigation: Runtime security platforms<br/>scan outputs. Trust layer adds signed<br/>provenance binding to every response"]

        KC8["8. IMPACT<br/>Data exfil, financial fraud, infra damage"]
        M8["Mitigation: Immutable audit trail,<br/>auto quarantine, forensic chain of custody"]
    end

    KC1 --- M1
    KC2 --- M2
    KC3 --- M3
    KC4 --- M4
    KC5 --- M5
    KC6 --- M6
    KC7 --- M7
    KC8 --- M8

    style KC1 fill:#264653,color:#fff
    style KC2 fill:#264653,color:#fff
    style KC3 fill:#264653,color:#fff
    style KC4 fill:#264653,color:#fff
    style KC5 fill:#264653,color:#fff
    style KC6 fill:#264653,color:#fff
    style KC7 fill:#264653,color:#fff
    style KC8 fill:#264653,color:#fff
    style M2 fill:#e76f51,color:#fff
    style M3 fill:#e76f51,color:#fff
    style M4 fill:#e76f51,color:#fff
    style M5 fill:#e76f51,color:#fff
    style M6 fill:#e76f51,color:#fff
    style M7 fill:#e9c46a,color:#000
    style M8 fill:#e76f51,color:#fff
```

AI security platforms increasingly address Stages 2, 3, and 7 with model scanning, input filtering, and output guardrails. The trust layer covers Stages 2, 4, 5, 6, and 8 -- the execution and post-execution stages where autonomous action creates actual damage. At Stage 7, the trust layer complements runtime output scanning by binding provenance to every output.

---

## 10. Integration Architecture: SIEM / XDR / SOAR

The trust layer is not a standalone product. It emits structured events into the existing security operations stack and consumes signals from it.

```mermaid
graph TB
    subgraph "Trust Layer Event Emission"
        SAE_EVENTS["SAE Lifecycle Events<br/>authorized · denied<br/>expired · replayed"]
        PROV_EVENTS["Provenance Events<br/>registered · hash mismatch<br/>cert revoked · drift detected"]
        POLICY_EVENTS["Policy Events<br/>evaluated · denied<br/>drift · bundle updated"]
        CERT_EVENTS["Certificate Events<br/>issued · rotated<br/>revoked · expiry warning"]
    end

    subgraph "Integration Layer"
        NORM["Event Normalization<br/>CEF · LEEF · OCSF"]
    end

    subgraph "Security Operations"
        SIEM["SIEM / XDR<br/>Splunk · Sentinel<br/>QRadar · Chronicle"]
        SOAR["SOAR<br/>Phantom · Tines<br/>Torq · Swimlane"]
        TIP["Threat Intel Platform<br/>Agent behavioral IOCs"]
    end

    SAE_EVENTS --> NORM
    PROV_EVENTS --> NORM
    POLICY_EVENTS --> NORM
    CERT_EVENTS --> NORM

    NORM --> SIEM
    SIEM -->|"Correlation rules<br/>trigger playbooks"| SOAR
    SOAR -->|"Auto response:<br/>revoke, quarantine, block"| SAE_EVENTS
    SIEM --> TIP

    subgraph "Inbound Signals"
        RISK["Risk Scoring Feeds<br/>UEBA · XDR · NDR"]
    end

    RISK -->|"Dynamic policy<br/>input signals"| POLICY_EVENTS

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
    subgraph "Attestation Checks (continuous)"
        direction TB
        R1["MODEL INTEGRITY<br/>Hash of loaded weights vs.<br/>signed provenance cert (every 60s)"]
        R2["POLICY STATE<br/>Hash of active policy bundle<br/>vs. last signed version (every 30s)"]
        R3["BEHAVIORAL BASELINE<br/>Action frequency and API patterns<br/>vs. established baseline"]
        R4["CERTIFICATE HEALTH<br/>OCSP check, expiry, revocation<br/>on every SAE issuance"]
        R5["ENVIRONMENT INTEGRITY<br/>TPM remote attestation,<br/>secure enclave verification"]
    end

    R1 --> V{"Attestation<br/>Verdict"}
    R2 --> V
    R3 --> V
    R4 --> V
    R5 --> V

    V -->|"HEALTHY"| CONT["Continue<br/>Refresh attestation token"]
    V -->|"DEGRADED"| DEG["Elevated scrutiny<br/>Reduce trust score<br/>Alert SOC (P3)"]
    V -->|"FAILED"| BLOCK["Quarantine agent<br/>Revoke certificate<br/>SOC alert (P1)"]

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
        TIER1["TIER 1 - Operational<br/>Inference calls, debug traces,<br/>performance metrics"]
        TIER2["TIER 2 - Security<br/>Policy denials, anomaly detections,<br/>guardrail triggers, access denials"]
        TIER3["TIER 3 - Trust-Critical<br/>Signed action executions,<br/>model deployments, policy changes"]
    end

    TIER1 -->|"Syslog / OCSF"| SIEM["SIEM / Log Store"]
    TIER2 -->|"OCSF + enrichment"| SIEM
    TIER3 -->|"Signed event +<br/>Merkle proof"| MERKLE["Merkle Tree<br/>(append-only · hash-chained)"]

    MERKLE -->|"Root hash published<br/>every N minutes"| TLOG["Transparency Log<br/>(independently verifiable)"]
    MERKLE -->|"On-demand<br/>proof export"| AUDIT["Regulator / Auditor<br/>Package"]
    MERKLE -->|"Forensic query<br/>by SAE chain"| IR["Incident Response<br/>Evidence Bundle"]

    style TIER3 fill:#e76f51,color:#fff
    style MERKLE fill:#264653,color:#fff
    style TLOG fill:#2a9d8f,color:#fff
```

The transparency log model is borrowed from Certificate Transparency (RFC 6962). Merkle roots are published on a fixed schedule. Any party can independently verify that a specific event was included in the log at the claimed time - without trusting the log operator.

---

## 13. Incident Response: Forensic Workflow

Scenario: SOC detects an unauthorized $200k wire transfer initiated by an AI agent.

![Incident Response: Forensic Workflow](network-security.png)

Without the trust layer: the SOC reconstructs this from scattered, mutable logs across 4+ systems. It takes days. The evidence is legally contestable. With the trust layer: cryptographic proof in minutes, including the exact policy version that was tampered with.

---

## 14. Defense-in-Depth: Where This Sits

```mermaid
graph TB
    subgraph "Enterprise AI Security Stack"
        direction TB
        L5["LAYER 5 - AI Application & Runtime Security<br/>Model scanning, prompt filtering, output guardrails,<br/>hallucination detection, DLP, agent security, red teaming"]
        L4["LAYER 4 - Agent Governance<br/>RBAC/ABAC, posture management, tool permissions,<br/>rate limiting, human-in-the-loop gates"]
        L3["LAYER 3 - Cryptographic Trust<br/>Action signing, policy-gated execution,<br/>model provenance, runtime attestation"]
        L2["LAYER 2 - Platform Security<br/>Container security, secrets management,<br/>microsegmentation, API gateway"]
        L1["LAYER 1 - Infrastructure Security<br/>CSPM, XDR, NDR, endpoint protection"]
    end

    L5 --> L4 --> L3 --> L2 --> L1

    L5 -.->|"Content decisions"| L3
    L4 -.->|"Access decisions"| L3
    L3 -.->|"Cryptographic enforcement"| L2
    L1 -.->|"Risk signals"| L3

    style L3 fill:#e76f51,color:#fff
```

Layer 3 does not replace anything above or below it. It makes the decisions at every other layer **provable**. Layer 5 -- where AI security platforms provide model scanning, runtime protection, agent guardrails, and red teaming -- makes content-level and behavioral decisions. Layer 3 provides the cryptographic substrate that binds those decisions to verifiable proof. Layer 5 detects a risky prompt -- Layer 3 proves the action was blocked. Layer 4 decides an agent lacks permission -- Layer 3 produces a signed denial. Layer 1 detects an endpoint anomaly -- Layer 3 consumes that signal to tighten policy thresholds. The trust layer is the enforcement backbone that the rest of the stack depends on for non-repudiation.

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
