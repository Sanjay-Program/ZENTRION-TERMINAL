# 33 — OPEN-SOURCE STRATEGY & LICENSING

*Not legal advice; all licensing decisions require professional legal review before implementation.*

## 33.1 Candidate models

| Model | Description | Pros | Cons |
|---|---|---|---|
| Fully open source (Apache-2.0/MIT) | everything OSS | maximal trust, contributions | no revenue protection |
| **Open-core** | runtime+CLI core OSS; cloud/enterprise/compliance features proprietary | community trust + sustainable business | must keep the split honest — core must be genuinely complete, not crippleware |
| Source-available (BSL-style) | code visible, limited use | protects competitors copying | community friction |
| Proprietary | closed | control | low trust, kills adoption for a security product |

## 33.2 Recommendation: **open-core with Apache-2.0 core**
Rationale: a security runtime lives or dies on auditability — users must be able
to inspect the code that guards their machine. Apache-2.0 (permissive + patent
grant) is friendly to both community and future enterprise adoption.

Component split:
| Component | License | Notes |
|---|---|---|
| core runtime, CLI, policy/capability/broker/sandbox adapters | Apache-2.0 | the trust surface — inspectable |
| SDKs | Apache-2.0 | |
| schemas, docs | Apache-2.0 / CC-BY | |
| registry *server* | AGPL-3.0 or proprietary | anti-freeride for hosted registry (future) |
| marketplace / cloud control plane | proprietary (future) | |
| enterprise features | commercial (future) | |
| third-party tools/models | own licenses | recorded per package; some (nmap NPSL) restrict redistribution — registry metadata records this rather than rehosting where license forbids |

## 33.3 Strategy flexibility
Design requirement: the *core* remains Apache-2.0; the company retains the
right to change licensing of **cloud/enterprise/registry components** it solely
controls. Contribution licensing (CLA vs DCO) is an open question (Q-OS-1) to
be settled with legal counsel before accepting outside contributions.

## 33.4 Product tiers (see 34) must respect this: FREE tier = full local runtime, no artificial crippling.
