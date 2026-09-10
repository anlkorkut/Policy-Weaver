# Dataverse Connector Bank-Scale Security and Reliability Review

**Assessment date:** 2026-08-31<br>
**Public-documentation context:** 2026-08-31<br>
**Target scale:** approximately 500 Dataverse security roles, 12,500 users, and 25 column security profiles<br>
**Assessment mode:** offline source/test review only; no tenant, service, production-data, or canary access

## 1. Findings

### Critical

#### C1. Alternate Fabric access planes are outside strict validation — **source-verified defect**

- **Impact:** A mapped identity with Fabric workspace Admin, Member, or Contributor access, or an item-level `Write`-equivalent grant, can read outside generated OneLake row and column constraints. An exact-parity assertion is therefore false even when every generated Data Access Role (DAR) is correct.
- **Trigger:** A consumer is granted an elevated workspace role or item permission outside the connector-managed DAR collection.
- **Evidence:** Strict validation checks only DAR names and `DefaultReader` (`policyweaver/weaver.py:221-255`). The Fabric client inventories only `/dataAccessRoles` (`policyweaver/core/api/fabric.py:55-121`). Tests cover unmanaged DARs and `DefaultReader`, not workspace/item grants (`tests/test_fabric_data_access_role_reliability.py:541-565`). Public Fabric documentation distinguishes Viewer/item `Read` from Admin/Member/Contributor and item `Write`; `ReadAll` is represented through `DefaultReader`, which the connector does check.
- **Remediation/test:** Add a mandatory preflight inventory or independently controlled attestation for workspace roles, item permissions, SQL endpoint permissions/mode, and other access paths. Fail if a mapped consumer has an elevated bypass. Test Viewer, item `Read`, `ReadAll`, item `Write`, and every workspace role separately. Explicitly exclude platform administrators from the parity population.
- **Production gate:** **BLOCK** until this boundary is proved and continuously monitored.

#### C2. Dataverse masking and `Read unmasked` are not modeled — **source-verified defect**

- **Impact:** If OneLake contains an original value, a user entitled only to a masked Dataverse value can receive the full value. One-record unmask semantics also cannot be expressed by OneLake's whole-column allow/hide model.
- **Trigger:** A secured column has a masking rule, `Read=Allowed`, and `Read unmasked` is either `Not Allowed` or `One record`.
- **Evidence:** Extraction requests only `canread` (`policyweaver/plugins/dataverse/api.py:587-605`); the model stores only `can_read` (`policyweaver/plugins/dataverse/model.py:89-113`); `can_read == 4` becomes an unrestricted column allowlist grant (`policyweaver/plugins/dataverse/client.py:1902-1925`).
- **Remediation/test:** Extract masking assignments and `Read unmasked` state. Strict mode must fail when masking coverage is unknown or cannot be represented. Permit full-column access only when all mapped consumers have all-record unmask authorization or the physical destination is independently and provably masked. Test all documented unmask states and destination representations.
- **Production gate:** **BLOCK** until masking is proved absent or translated without exposing original values.

#### C3. Partial secured-column discovery can fail open — **runtime-verified defect**

- **Impact:** A readable table incorrectly classified as having no secured columns receives no `ColumnConstraint`, exposing all its columns.
- **Trigger:** `EntityDefinitions` omits a candidate table, omits `Attributes`, or returns a structurally valid but incomplete relationship.
- **Evidence:** Only tables discovered through returned `Attributes` proceed to detailed metadata (`policyweaver/plugins/dataverse/api.py:242-247,643-665`). Missing table metadata is silently skipped while constructing CLS (`policyweaver/plugins/dataverse/client.py:1869-1900`). Strict validation requires CLS to be enabled but does not prove metadata completeness (`policyweaver/plugins/dataverse/client.py:206-213`). The Tester probe supplied an `EntityDefinitions` result without `Attributes`; the secured-table result was zero and the process exited successfully.
- **Remediation/test:** Track every readable candidate table from privilege discovery through metadata completion. Require exactly one complete result per candidate and fail closed on missing tables, missing `Attributes`, incomplete nested pages, or duplicates. Add strict-mode tests for each partial-response form.
- **Production gate:** **BLOCK** until completeness is enforced.

### High

#### H1. Extraction is paged but not a deterministic, coherent authorization snapshot — **design risk**

- **Impact:** Concurrent changes to users, teams, roles, privileges, business units, or field profiles can produce a mixed-time entitlement model, causing temporary overgrant or undergrant.
- **Trigger:** Security metadata changes during the sequential multi-query extraction.
- **Evidence:** Top-level and expanded relationship paging follow next links (`policyweaver/plugins/dataverse/api.py:108-164`), with nested paging tested (`tests/test_dataverse_bulk_relationship_extraction.py:71-93`). Extraction then executes independent collections sequentially (`policyweaver/plugins/dataverse/api.py:175-255`). Request headers do not request change tracking (`policyweaver/plugins/dataverse/api.py:101-107`), and representative queries have no deterministic `$orderby` (`policyweaver/plugins/dataverse/api.py:303-312,378-382,428-456,490-499,572-589,647-651`).
- **Remediation/test:** Use stable unique ordering where supported, assign a generation identifier, record collection versions/counts, validate cross-collection references, and restart on detected change. A separate versioned/incremental design is needed because Dataverse change tracking cannot simply be combined with the connector's current expanded queries. Test insert, delete, membership, role-depth, and BU changes between synthetic pages.

#### H2. Empty or sharply reduced authoritative output lacks a change budget — **runtime-verified defect**

- **Impact:** A structurally valid empty or partial extraction can remove every managed DAR. Conversely, an exception before publication preserves stale grants and can leave revoked Dataverse access active in Fabric.
- **Trigger:** A legitimately empty source, an accepted partial response, a filtering/configuration error, or an exception before apply.
- **Evidence:** Empty mapping deliberately returns `policies=[]` (`policyweaver/plugins/dataverse/client.py:503-510`) and is asserted by `tests/test_fabric_data_access_role_reliability.py:369-413`. Reconciliation performs an authoritative ETag-guarded replacement without minimum-count, deletion-percentage, or member/permission change thresholds (`policyweaver/weaver.py:303-428`). Failure before `apply_role` leaves the existing target collection unchanged (`policyweaver/weaver.py:117-135`). The Tester strict-empty probe completed with zero policies.
- **Remediation/test:** Persist a trusted baseline; enforce minimum source counts and role/member/permission deletion budgets; require two-person override for exceptional reductions; produce a dry-run diff and a protected before-image. Test valid empty, large deletion, partial extraction, abort-before-PUT, conflict, and rollback.

#### H3. Role amplification makes common bank-scale distributions infeasible — **design risk**

- **Impact:** Exact mapping can exceed the 1,000-role support-escalated item limit by more than an order of magnitude. Unsafe coalescing would break Basic ownership or CLS isolation.
- **Trigger:** Large Basic memberships, many all-user Global roles, divergent field-profile signatures, more than 500 permissions, or row-filter chunking.
- **Evidence:** Capacity preflight distinguishes principal-specific, divergent-CLS, shared-member, and permission chunks (`policyweaver/plugins/dataverse/client.py:687-783`) and counts member/CLS chunks (`policyweaver/plugins/dataverse/client.py:790-856`). Final generated capacity is checked again after row splitting (`policyweaver/plugins/dataverse/client.py:516-536`). Tests confirm failure before generation and 500-member chunking (`tests/test_dataverse_role_capacity.py:67-106`).
- **Remediation/test:** Run the formulas in Section 7 against redacted cardinalities before deployment. If the projection exceeds 1,000, use item/data-layout partitioning or a different enforcement architecture; do not merge identities with different ownership or column grants. Add 12,500-user/500-role synthetic performance and memory tests.

#### H4. System Administrator column-security bypass is under-mapped — **source-verified defect**

- **Impact:** Dataverse System Administrators can lose secured-column access in Fabric.
- **Trigger:** A System Administrator has table read access but no explicit matching field security profile (FSP) grant.
- **Evidence:** Effective CLS starts with unsecured columns and adds secured columns only from FSP permissions where `can_read == 4` (`policyweaver/plugins/dataverse/client.py:1225-1259,1842-1925`). An unmatched profile produces an empty allowlist (`tests/test_dataverse_cls_isolation.py:1268-1292`). Microsoft documents that Dataverse column security does not apply to System Administrators.
- **Remediation/test:** Detect the System Administrator entitlement through stable role metadata rather than localized names and grant all otherwise readable columns, or explicitly exclude those administrators from the mapped population. Test an administrator without an FSP.
- **Production gate:** **BLOCK or exclude** affected administrators until handled.

#### H5. Process-global source and authentication state are unsafe for concurrent runs — **design risk**

- **Impact:** Two overlapping syncs in one process can use the wrong Dataverse origin or authentication object.
- **Trigger:** Concurrent runs for different environments or identities.
- **Evidence:** Connector initialization writes the Dataverse origin to process environment state (`policyweaver/plugins/dataverse/client.py:45-55`), and the API client reads it globally (`policyweaver/plugins/dataverse/api.py:49-55`). Each orchestration run reinitializes shared authentication state (`policyweaver/weaver.py:91-101`).
- **Remediation/test:** Inject immutable origin and authentication dependencies per run. Until then, enforce one isolated process per sync. Add a deterministic two-client interleaving test.

### Medium

#### M1. Eligibility filtering exists, but nullable fields are accepted — **source-verified defect**

- **Impact:** An identity with unknown state, access mode, or licensing status can be mapped. An explicitly ineligible assigned identity instead blocks the entire strict export, which is safer but operationally disruptive.
- **Trigger:** `azurestate`, `accessmode`, or `islicensed` is null/omitted, or a prebuilt environment supplies a disabled user.
- **Evidence:** Extraction filters explicitly disabled users and selects eligibility fields (`policyweaver/plugins/dataverse/api.py:303-337`). Resolution rejects known nonactive states, access modes 1/3/5, and unlicensed interactive users, and maps application users to service principals (`policyweaver/plugins/dataverse/client.py:1812-1827`). `None` is accepted, and `is_disabled` is not rechecked. Strict mode turns unresolved assigned identities into an export failure (`policyweaver/plugins/dataverse/client.py:551-581`). Tests cover application, administrative, and unlicensed users (`tests/test_dataverse_permission_object_resolution.py:66-148`).
- **Remediation/test:** In strict mode, reject unknown eligibility values and explicitly recheck disabled state. Emit categorized counts without identity details. Test every null and contradictory combination.

#### M2. Dormant `table_permissions.has_read=False` entries grant access — **source-verified defect**

- **Impact:** A caller-provided or imported alternate table-permission entry marked non-readable can become a table grant.
- **Trigger:** The alternate `DataverseEnvironment.table_permissions` path is used rather than API-derived compact privileges.
- **Evidence:** The model defines `has_read` (`policyweaver/plugins/dataverse/model.py:176-196`), but the alternate branch adds every entry without checking it (`policyweaver/plugins/dataverse/client.py:863-883`). The normal extractor path emits compact permissions as readable (`policyweaver/plugins/dataverse/client.py:927-945`).
- **Remediation/test:** Reject or ignore entries unless `has_read is True`, or remove the dormant input path. Add a test proving a false value cannot generate any scope.

#### M3. Async orchestration wraps synchronous network and mapping work — **design risk**

- **Impact:** The event loop is blocked during extraction, translation, and Fabric REST operations; cancellation and multi-run scheduling are unreliable at scale.
- **Trigger:** Large or slow syncs invoked from an asynchronous host.
- **Evidence:** `WeaverAgent.run` is asynchronous but calls synchronous `src.map_policy(...)` before awaiting publication (`policyweaver/weaver.py:79-135`). Dataverse uses synchronous `requests` (`policyweaver/plugins/dataverse/api.py:49-95`), and Fabric uses the synchronous REST proxy (`policyweaver/core/api/rest.py:74-91`).
- **Remediation/test:** Either expose an explicitly synchronous batch API or move blocking work to isolated workers with cancellation/deadline propagation. Test cancellation and event-loop responsiveness.

#### M4. Request retries have no end-to-end run deadline — **design risk**

- **Impact:** Sequential collections, paging, retries, and readback can exceed a bank's maintenance window while leaving the old authorization set active.
- **Trigger:** Repeated throttling, slow pages, or intermittent service failures across many collections.
- **Evidence:** Dataverse configures per-request retries/timeouts (`policyweaver/plugins/dataverse/api.py:49-58,86-95`); the generic REST proxy similarly retries GET/PUT/DELETE and applies request timeouts (`policyweaver/core/api/rest.py:25-57,74-91`). No orchestration-level deadline spans the full run (`policyweaver/weaver.py:79-135`).
- **Remediation/test:** Add a run deadline, retry budget, cancellation propagation, and explicit terminal state. Alert when stale target authorization exceeds the agreed objective. Test cumulative retry exhaustion rather than only individual calls.

### Low

#### L1. Component and callback naming obscure operational behavior — **documentation gap**

- **Impact:** Operators may mistake the connector for a native Dataverse plug-in or assume callback “snapshots” are point-in-time source snapshots. Misspelled callback names also increase integration errors.
- **Trigger:** Architecture, runbook, or callback integration based only on names.
- **Evidence:** The component is an external Web API client and batch synchronizer (`policyweaver/plugins/dataverse/api.py:29-34`; `policyweaver/weaver.py:72-135`), not a Dataverse sandbox `IPlugin`. Parameters and setter names contain `hndlr`/`snaphot` spellings (`policyweaver/weaver.py:79-109,1196-1207`). Snapshot callbacks serialize already-generated objects; they do not create a coherent source snapshot (`policyweaver/weaver.py:1130-1166`).
- **Remediation/test:** Consistently call it an external connector/synchronizer, document synchronous execution, and introduce correctly spelled aliases with deprecation tests.

## 2. Overall verdict and use boundary

### Production exact-parity verdict: **NO-GO**

At approximately **R≈500 roles and U≈12,500 users**, the connector is **not approved for production use where exact Dataverse effective-access parity is a hard requirement**. The critical access-plane, masking, and secured-metadata gates alone prevent approval. Snapshot consistency, mass-change protection, administrator semantics, concurrency, and scale feasibility are additional blockers.

Required production gates:

1. Inventory and continuously validate workspace, item, SQL, and other access planes.
2. Model masking/`Read unmasked`, or prove masking absent and destination values safe.
3. Make secured-column discovery complete and fail closed.
4. Add deterministic extraction and a defensible consistency/versioning strategy.
5. Add minimum counts, change budgets, independent approval, before-image, and rollback.
6. Prove projected and reconciled DAR counts remain within the supported item quota.
7. Map or exclude System Administrators.
8. Retain strict blockers for POA/POAA, hierarchy security, RecordFilter, dynamic group-team assignments, unknown depth/inheritance, unresolved identities, and unsupported RLS/CLS composition.
9. Isolate each environment/run in its own process until global state is removed.
10. Repair the alternate false-read permission path and fail closed on unknown user eligibility.

**Offline assessment:** Appropriate. Static analysis, unit tests, synthetic projections, and dry-run payload review can continue without service access.

**Sandbox conditional use:** Acceptable only with synthetic/non-sensitive data, isolated single-run processes, strict mode, Viewer/item-Read consumers, verified absence of masking and unsupported mechanisms, a role projection below the confirmed quota, external change-budget/approval controls, and no claim of production parity.

## 3. Business problem and component type

Policy Weaver must translate cumulative Dataverse read entitlements—security roles, team membership, BU-scoped privilege depth, ownership, and FSP grants—into cumulative Fabric OneLake DARs without granting any extra row/column or omitting any authorized row/column.

The reviewed component is an **external synchronous Python batch extractor, translator, and reconciler**:

1. Call Dataverse Web API collections.
2. Build an in-memory `DataverseEnvironment`.
3. Validate strict coverage and unsupported mechanisms.
4. Aggregate roles, principals, tables, depths, ownership, and CLS signatures.
5. Expand/split to Fabric-compatible roles.
6. Compare with the current Fabric DAR collection.
7. Perform ETag-guarded authoritative replacement and readback verification.

It is not a native Dataverse plug-in and does not execute inside the Dataverse transaction pipeline (`policyweaver/plugins/dataverse/api.py:29-34`; `policyweaver/weaver.py:72-135`).

## 4. Architecture, trust flow, and state transitions

### Trust flow

| Stage | Input/trust boundary | Transformation | Output/control |
|---|---|---|---|
| 1. Bootstrap | Local validated configuration and run identity | Select connector and initialize run | Process-global state remains a concurrency concern (`policyweaver/weaver.py:79-116`; `policyweaver/plugins/dataverse/client.py:45-55`) |
| 2. Extract | Dataverse OData responses | Sequentially load organization hierarchy settings, BUs, users/relationships, teams/relationships, roles, privileges, FSPs, secured-column metadata, and POAA | In-memory environment (`policyweaver/plugins/dataverse/api.py:166-255`) |
| 3. Validate | In-memory environment | Strict unsupported-feature, assignment-context, identity, BU-topology, capacity, and composition checks | Fail before generation for recognized unsupported states (`policyweaver/plugins/dataverse/client.py:206-383,551-783`) |
| 4. Translate | Validated roles/principals | Highest-depth aggregation, dedupe, ownership/CLS grouping, member/permission/row chunking | `RolePolicyExport` (`policyweaver/plugins/dataverse/client.py:389-545,900-945`) |
| 5. Snapshot callback | Generated export | Serialize generated model | Audit hook, not a source-consistency mechanism (`policyweaver/weaver.py:1130-1166`) |
| 6. Reconcile | Current Fabric DAR collection | Strict target-boundary check, stable sort, canonical comparison, preserve IDs | No-op when canonical collections match (`policyweaver/weaver.py:221-255,303-380,430-449`) |
| 7. Publish | Complete desired collection plus collection ETag | Dry-run PUT, authoritative PUT, complete readback | Optimistic concurrency and exact verification (`policyweaver/weaver.py:371-428`) |

### State transitions and failure behavior

1. **Idle → Extracting:** synchronous calls begin.
2. **Extracting → Validated model:** all collections are held in memory; there is no common source timestamp.
3. **Validated model → Desired DAR collection:** role expansion and deterministic local sorting occur.
4. **Desired → No-op:** canonical current and desired collections are equal.
5. **Desired → Dry-run validated:** the current collection ETag is required.
6. **Dry-run → Applied:** the complete desired collection replaces the managed target state.
7. **Applied → Verified:** a complete readback must canonically equal the requested collection.

Failure transitions:

- **Before apply:** the target is unchanged; source revocations can remain as stale overgrant.
- **Structurally valid empty desired state:** managed roles can be removed.
- **Concurrent target modification:** `If-Match` should prevent an unguarded overwrite.
- **Ambiguous apply error:** readback can establish that the requested collection nevertheless succeeded.
- **Verification mismatch:** the run fails, but no automatic rollback is present.
- **No cross-system transaction:** Dataverse extraction and Fabric publication are not atomic with each other.

## 5. Security-mechanism classification

| Dataverse mechanism | Classification | Current behavior and exact-parity implication |
|---|---|---|
| Role copies/templates | **Supported with qualification** | Published role instances are extracted with `parent_root_role_id`; privilege records can be sourced from the root role while retaining the role instance/BU context (`policyweaver/plugins/dataverse/api.py:428-456,490-565`). Missing privilege joins abort. |
| Privilege depths/masks | **Supported for 1/2/4/8** | Masks map to Basic/Local/Deep/Global; unknown values rank below known values and fail closed (`policyweaver/plugins/dataverse/api.py:460-565`; `policyweaver/plugins/dataverse/client.py:1365-1367,1491-1530`). |
| RecordFilter mask 16 | **Unsupported; strict blocker** | Mask 16 is not normalized to a standard depth, and the extracted record-filter reference causes strict rejection (`policyweaver/plugins/dataverse/api.py:460-565`; `policyweaver/plugins/dataverse/client.py:241-249`). |
| BU hierarchy and ownership | **Supported core mapping** | Deep traverses role BU plus descendants, Local uses role BU, and Basic uses owner IDs; malformed topology fails strict validation (`policyweaver/plugins/dataverse/client.py:327-383,1369-1390,1491-1530`). |
| Direct user roles | **Supported** | Direct assignments are deduplicated per role; separate Fabric roles remain cumulative across multiple Dataverse roles (`policyweaver/plugins/dataverse/client.py:914-925`). Basic is split per effective identity. |
| Owner teams | **Supported with expansion** | Team role members are expanded to users. Direct Basic ownership includes owner teams; per-principal roles prevent peer-owner overgrant (`policyweaver/plugins/dataverse/client.py:1050-1190`). |
| Access teams | **Not mapped as sharing entitlements** | Access-team record access is sharing-based and falls under the POA gap. Access teams are intentionally excluded from Basic ownership scope (`policyweaver/plugins/dataverse/client.py:1185-1190`). |
| Entra/group teams | **Extracted; strict role/FSP assignments blocked** | Membership is expanded for translation, but strict mode rejects role-assigned or FSP-assigned group-team records because dynamic/filtered membership cannot be proved from the extracted snapshot (`policyweaver/plugins/dataverse/client.py:225-239`). |
| POA record sharing | **Not implemented; external attestation only** | Strict mode requires `poa_read_access_status='verified_empty'`; this is a human/external assertion, not programmatic proof (`policyweaver/plugins/dataverse/client.py:318-325`; `policyweaver/plugins/dataverse/model.py:335-338`). Current effect is generally undergrant, not overgrant. |
| Hierarchy security | **Unsupported; strict blocker** | Manager/position hierarchy security causes strict failure (`policyweaver/plugins/dataverse/client.py:214-224`). |
| FSP/field permissions | **Supported core grant union, incomplete parity** | Profiles assigned through users/teams are unioned; `can_read == 4` grants a secured column. Masking and System Administrator bypass remain unhandled (`policyweaver/plugins/dataverse/client.py:1196-1259,1842-1925`). |
| Table permissions | **Supported from read privileges; alternate path unsafe** | API-derived compact entries use readable privileges and highest depth. Dormant caller-supplied entries ignore false `has_read` (`policyweaver/plugins/dataverse/client.py:863-945`). |
| Column permissions | **Allowlist translation** | Unsecured columns plus FSP-readable secured columns are granted. Missing table metadata can remove the constraint entirely; no masking semantics exist (`policyweaver/plugins/dataverse/client.py:1842-1925`). |
| Disabled/application users | **Partially supported** | Extraction filters explicit disabled users; known administrative/unlicensed interactive modes are rejected; application identities become service principals. Nullable fields fail open (`policyweaver/plugins/dataverse/api.py:303-337`; `policyweaver/plugins/dataverse/client.py:1812-1827`). |
| Impersonation/delegation | **Not modeled; scope exclusion required** | The user extraction/model covers identity, state, mode, license, BU, roles, teams, and profiles, but no impersonation/delegation entitlement (`policyweaver/plugins/dataverse/api.py:303-337`; `policyweaver/plugins/dataverse/model.py:9-29`). Validate such flows separately. |
| Deny/override | **No explicit deny model** | Translation processes positive read grants and uses greatest recognized depth within a role/table (`policyweaver/plugins/dataverse/client.py:900-945`). Dataverse and Fabric grants are cumulative; unmanaged/bypass grants can therefore override intended restrictions. Unknown depth is converted to deny-all rather than an allow. |

**Multiple roles and overlapping memberships:** Role assignments are set-deduplicated, resolved identities are deduplicated by Entra/application identity, and FSP grants are unioned. Different Dataverse roles normally become cumulative Fabric roles. When multiple generated roles would combine CLS and RLS on the same user/table in an unsupported way, preflight blocks rather than guessing (`policyweaver/plugins/dataverse/client.py:591-685`).

## 6. Pipeline behavior trace

| Concern | Observed behavior | Assessment |
|---|---|---|
| Aggregation | Role/table read privileges retain the highest recognized depth; principals are grouped by role/BU (`policyweaver/plugins/dataverse/client.py:900-945`). | Correct for cumulative depth within a role/table; cross-role grants remain separate and cumulative. |
| Dedupe | Assignment IDs use sets; shared-role identities, Basic identities, and CLS groups have identity-key dedupe (`policyweaver/plugins/dataverse/client.py:914-925,445-460,1067-1084,1295-1315`). | Positive; limits duplicate membership and unstable output. |
| Depth normalization | Bitmasks 1/2/4/8 map to Basic/Local/Deep/Global; other values become Unknown (`policyweaver/plugins/dataverse/api.py:460-565`). | Positive fail-closed behavior for malformed and RecordFilter depths. |
| Paging | Top-level next links are followed with origin and cycle checks (`policyweaver/plugins/dataverse/api.py:108-147`). | Positive completeness/security control. |
| Expanded paging | Nested relationship next links are followed (`policyweaver/plugins/dataverse/api.py:149-164`). | Positive; the claim that expanded relationships are not paged is rejected. |
| Incrementals | No watermark/change-token state is used; each run re-extracts collections. | Full-refresh only; no coherent cross-collection version. |
| Deletions | Desired DARs are authoritatively reconciled; empty is valid (`policyweaver/plugins/dataverse/client.py:503-510`; `policyweaver/weaver.py:303-428`). | Correct for convergence, dangerous without change budgets. |
| Snapshot | Callbacks serialize generated source/Fabric objects (`policyweaver/weaver.py:1130-1166`). | Useful audit hook; not a source point-in-time snapshot. |
| Idempotency | Stable sorting and canonical comparison skip identical updates (`policyweaver/weaver.py:303-380,430-449`). | Strong positive. |
| Transactions | ETag protects the target collection, followed by complete readback (`policyweaver/weaver.py:371-428`). | Strong target-side control; no source-target atomic transaction or automatic rollback. |
| Concurrency | Source origin and authentication state are process-global (`policyweaver/plugins/dataverse/client.py:45-55`; `policyweaver/weaver.py:91-101`). | Unsafe for concurrent multi-environment runs. |
| Partial failures | Malformed collection shape, cross-origin paging, cycles, incomplete privilege joins, and invalid BU topology abort. Partial secured-table discovery can still be accepted. | Mixed fail-closed/fail-open behavior; C3 is critical. |
| Retries | Per-request retry/backoff and timeouts exist (`policyweaver/plugins/dataverse/api.py:49-58`; `policyweaver/core/api/rest.py:44-57`). | Positive locally; no end-to-end deadline. |
| Recovery | Pre-apply failure preserves current roles; ambiguous PUT is followed by readback. | Avoids blind retry overwrite, but stale access and no rollback remain. |
| Reconciliation | Complete current/desired collections are compared, dry-run with ETag, replaced, then verified (`policyweaver/weaver.py:303-428`). | Strong deterministic target control once desired state is trustworthy. |

## 7. Scale model

Let:

- \(m_r\) = distinct resolvable identities in Dataverse role \(r\), after required expansion/dedupe;
- \(t_r\) = tables/permissions in role \(r\);
- \(m_{r,s}\) = identities in role \(r\) sharing CLS signature \(s\).

Before row-filter chunks:

- **Principal-specific/Basic:**<br>
  \[
  N_r=m_r\times\left\lceil\frac{t_r}{500}\right\rceil
  \]
- **Shared Global:**<br>
  \[
  N_r=\left\lceil\frac{m_r}{500}\right\rceil\times
      \left\lceil\frac{t_r}{500}\right\rceil
  \]
- **CLS signature groups:**<br>
  \[
  N_r=\sum_s\left\lceil\frac{m_{r,s}}{500}\right\rceil\times
      \left\lceil\frac{t_r}{500}\right\rceil
  \]

Row-filter length chunks can multiply these counts further.

Consequences:

- One Basic role assigned to 12,500 users and at most 500 tables needs **at least 12,500 Fabric roles**.
- 500 all-Global roles, each assigned to all 12,500 users and at most 500 tables, need **500 × 25 = 12,500 role chunks**.
- These are required-role projections, not generated over-cap payloads: the connector's preflight rejects when the configured cap would be exceeded (`policyweaver/plugins/dataverse/client.py:687-783`).
- Current public limits are **250 roles per item by default**, support escalation to **1,000**, **500 users or user groups per role**, and **500 permissions per role**. A target-specific escalation must still be validated before deployment.

### Memory and CPU

- The compact role map avoids multiplying every user by every table (`policyweaver/plugins/dataverse/client.py:900-945`; `tests/test_dataverse_compact_role_mapping.py:14-75`).
- CLS still creates a table/column grant set and then a `frozenset` per effective user for each role under evaluation (`policyweaver/plugins/dataverse/client.py:1196-1259`). A divergent role can recompute signatures during divergence checks, capacity counting, composition preflight, and construction.
- Peak CLS memory should be modeled approximately per active role, \(O(\max_r(m_r C_r))\), not asserted as \(O(RUC)\) simultaneously. Overlapping users nevertheless cause repeated allocation and CPU across roles.
- BU descendant traversal rebuilds the child map each call (`policyweaver/plugins/dataverse/client.py:1369-1390`), including repeated Deep/per-principal work.
- Expanded membership, permission, and row-filter chunks amplify payload size and serialization/readback cost.

The repository's offline scale harness was run with 12,500 users, 500 roles, 25 profiles, five roles per user, 10 BUs, 100 owner teams, 10 tables per role, and a 1,000-role cap. The direct-role scenario completed in **25.238 seconds** with **453.42 MiB peak traced Python allocation**, producing 500 roles, 62,500 memberships, 5,000 table scopes, and 3,330 row constraints. The overlapping owner-team scenario was blocked; the 12,500-user Basic scenario and multi-role RLS/CLS scenario were blocked as expected. This synthetic result measures mapper behavior only; it does not model API latency, JSON response residency, publication payload size, retries, propagation, or the customer's real entitlement distribution.

## 8. Bank-grade operations and controls

| Control area | Required control | Current assessment |
|---|---|---|
| Least privilege | Consumers must be Viewer/item-Read only unless explicitly excluded; inventory all alternate grants. | **Critical gap** outside DAR validation. |
| Segregation of duties | Separate source assessment, diff approval, and publication; require two approvers for exceptional revocation/expansion. | Not embedded in core reconciliation. |
| Privilege escalation | Treat workspace/item role changes, quota escalation, and administrator exclusions as controlled exceptions with expiry/review. | Target quota and bypass population need external governance. |
| Deterministic output | Stable paging/version, stable ordering, canonical desired payload, immutable run inputs. | Local output is sorted/canonical; source paging is not deterministic or coherent. |
| Audit and lineage | Record run ID, source generation evidence, counts, hashes, approved diff, target ETag, result, and readback hash. | Snapshot callbacks and readback are useful hooks, but do not provide complete lineage by themselves. |
| Approval and rollback | Dry-run, protected before-image, change budgets, approval, restore procedure, and post-restore verification. | Dry-run/readback exist; embedded approval, budget, and automatic rollback do not. |
| Fail-open/fail-closed | Unknown security state must block publication. | Many unsupported mechanisms fail closed; masking, secured-table discovery, and nullable eligibility do not. |
| Stale exposure | Alert when source revocation is not published within the agreed objective. | Pre-apply failure preserves stale target grants without an age alarm. |
| Monitoring | Counts and deltas for roles, members, permissions, constraints, unresolved identities, rejected mechanisms, runtime, retries, and propagation age. | Logging exists, but no complete bank control loop is evidenced. |
| Sensitive metadata | Treat snapshots/diffs as restricted security metadata; minimize identity detail, encrypt, restrict access, and set retention. | Callback payloads can contain entitlement identities; operators must not place raw snapshots in general logs. |
| Configuration governance | Version, review, and attest policy-affecting settings and target identity; validate changes before apply. | URL shape validation is positive (`policyweaver/plugins/dataverse/client.py:57-91`), but change approval is external. |

Propagation expectations must be part of operations: role-definition changes take **about five minutes**; user-group changes take **about one hour**, and some engines may require **an additional hour**. Verification and incident thresholds must not assume immediate convergence.

## 9. Positive findings

1. Unknown/malformed depth and RecordFilter paths fail closed rather than defaulting to Global (`policyweaver/plugins/dataverse/api.py:460-565`; `policyweaver/plugins/dataverse/client.py:241-249,1491-1530`).
2. Strict mode blocks known unrepresentable hierarchy security, POAA, unverified POA, dynamic group-team assignments, unknown inheritance, missing role/BU context, unresolved identities, unsupported RLS/CLS composition, and quota overflow (`policyweaver/plugins/dataverse/client.py:206-383,551-783`).
3. Basic ownership is split per identity, preventing users in a shared DAR from seeing each other's owned records (`policyweaver/plugins/dataverse/client.py:417-437,1050-1190`).
4. Deep and Local filters are BU-aware, and strict mode validates hierarchy completeness/cycles before use (`policyweaver/plugins/dataverse/client.py:327-383,1369-1390,1491-1530`).
5. FSP grants are cumulative and identities with different CLS signatures are isolated (`policyweaver/plugins/dataverse/client.py:1196-1348`).
6. Paging validates response shape, rejects cross-origin links, detects cycles, and follows expanded next links (`policyweaver/plugins/dataverse/api.py:108-164`; `tests/test_dataverse_bulk_relationship_extraction.py:20-99`).
7. Role/member/permission/row-filter limits are preflighted and rechecked after expansion (`policyweaver/plugins/dataverse/client.py:687-856,1635-1764`).
8. Fabric reconciliation is stable, idempotent, ETag-guarded, dry-run validated, and readback verified (`policyweaver/weaver.py:303-449`).
9. Configuration validates a required HTTPS origin and rejects embedded user information or non-origin paths (`policyweaver/plugins/dataverse/client.py:57-91`).
10. The compact role map avoids a full principal × table materialization (`policyweaver/plugins/dataverse/client.py:900-945`).

## 10. Tests and observed results

### Parent-validated safe selection

```powershell
.\.venv-x64\Scripts\python.exe -m pytest -q `
  tests/test_dataverse_basic_owner_isolation.py `
  tests/test_dataverse_bulk_relationship_extraction.py `
  tests/test_dataverse_business_unit_query_filter.py `
  tests/test_dataverse_cls_isolation.py `
  tests/test_dataverse_compact_role_mapping.py `
  tests/test_dataverse_config_validation.py `
  tests/test_dataverse_depth_precedence.py `
  tests/test_dataverse_permission_object_resolution.py `
  tests/test_dataverse_rls_toggle_override.py `
  tests/test_dataverse_role_capacity.py `
  tests/test_dataverse_role_naming_context.py `
  tests/test_dataverse_row_constraint_length.py `
  tests/test_dataverse_row_filter_columns.py `
  tests/test_dataverse_weaver_rls_serialization.py `
  tests/test_fabric_data_access_role_reliability.py
```

**Result:** `188 passed in 2.73s`.

This was parent-validated evidence, not independently rerun by the Tester.

```powershell
.\.venv-x64\Scripts\python.exe -m ruff check `
  policyweaver/plugins/dataverse `
  policyweaver/weaver.py `
  policyweaver/core/api/fabric.py `
  policyweaver/core/api/rest.py
```

**Result:** `All checks passed!`.

```powershell
.\.venv-x64\Scripts\python.exe -m pytest -q `
  tests/test_fabric_data_access_role_reliability.py `
  -k "empty_dataverse or reconciliation"
```

**Result:** `6 passed, 16 deselected in 3.18s`.

```powershell
.\.venv-x64\Scripts\python.exe scripts/dataverse_scale_preflight.py `
  --users 12500 --roles 500 --profiles 25 --roles-per-user 5 `
  --business-units 10 --owner-teams 100 --tables-per-role 10 `
  --role-limit 1000 --output <temporary-output>
```

**Result:** direct-role mapping succeeded in 25.238 seconds at 453.42 MiB peak traced allocation; owner-team overlap, Basic-role capacity, and multi-role RLS/CLS scenarios blocked. The temporary output was removed.

### Parent safe inline probes

Three additional nonpersistent, no-network probes used synthetic in-memory models and existing fake Fabric APIs:

1. **Strict empty authoritative replacement:** strict validation passed, zero roles were exported, dry-run plus authoritative PUT occurred, and the resulting managed role count was zero. This reproduces H2 end to end.
2. **System Administrator CLS:** strict validation passed; an unsecured column was granted and a secured column was omitted for an administrator without an FSP. This reproduces H4 as undergrant.
3. **Role-less Entra group-team ownership:** strict validation passed and included the synthetic group-team ID in the direct Basic user's ownership predicate. This supports H1's dynamic-membership snapshot risk; it does not reinstate the separate direct-Basic/team-correlation defect rejected by Fact Checker.

### Tester safe inline probes

The Tester ran only two nonpersistent inline probes:

1. **Strict empty model validation:** accepted; generated zero policies; exit code 0.
2. **Missing `Attributes` in secured-table discovery:** returned zero secured tables; exit code 0.

The exact commands remain in session evidence and are not duplicated in this report. The Tester did **not** rerun the 188-test suite. Passing tests establish implementation consistency, not coverage of the critical production gaps.

## 11. Ten-claim adjudication

| # | Adjudication | Result |
|---|---|---|
| 1 | Component type | **Confirmed:** external Python Web API synchronizer, not a native Dataverse plug-in. |
| 2 | Fabric workspace/item boundary | **Confirmed — Critical gate:** strict validation covers DARs/`DefaultReader`, not elevated workspace/item access. Viewer/item `Read` alone are not blanket data grants; `ReadAll` is addressed through `DefaultReader`. |
| 3 | Masking | **Confirmed — Critical gate:** column security and masking are distinct; masking and `Read unmasked` are absent. |
| 4 | Paging/snapshot | **Confirmed:** top-level and expanded paging exist, but deterministic ordering, watermarking, and common snapshot do not. |
| 5 | Empty/partial output | **Confirmed:** valid empty output is authoritative and can revoke managed roles; an exception before apply instead preserves stale roles. |
| 6 | OneLake limits/propagation | **Corrected:** 250 roles/item default; support escalation to 1,000; 500 users or groups/role; 500 permissions/role; role changes about five minutes; group changes about one hour plus possible additional engine hour. |
| 7 | Scale calculation | **Corrected:** 12,500-role examples are valid projections under stated assumptions, but preflight rejects over-cap rather than generating them. Permission and row/CLS chunks can increase projections. Memory is repeated per-role allocation, not all roles necessarily resident as \(RUC\). |
| 8 | User filtering | **Corrected:** explicit filters exist; assigned ineligible identities block strict export. Nullable eligibility fields remain fail-open. |
| 9 | Unsupported mechanisms | **Confirmed with qualification:** strict mode blocks rather than implements hierarchy, RecordFilter, POAA, unverified POA, dynamic group-team assignments, unknown state, and unsupported composition. |
| 10 | System Administrator CLS | **Confirmed — High undergrant:** bypass is not represented unless administrators are handled or excluded. |

## 12. Fact Checker adjudication

The Fact Checker packet is controlling where specialist reports conflicted.

### Confirmed claims

- External synchronous batch architecture, sequential extraction, in-memory translation, strict validation, role expansion, and authoritative Fabric reconciliation.
- Alternate Fabric access planes are a Critical boundary gap.
- Masking/`Read unmasked` are a Critical semantic gap.
- Partial secured-column metadata can fail open.
- Paging exists but no coherent deterministic source snapshot exists.
- Valid empty output is authoritative; no mass-change guard exists.
- Role amplification is operationally blocking at the stated scale.
- System Administrator column-security bypass is under-mapped.
- Process-global state is unsafe for concurrent runs.
- The dormant false-read table-permission path is unsafe.

### Corrected claims

- Limits and propagation use the values in Sections 7 and 8; group changes can incur an additional engine hour.
- Scale numbers are projections rejected by preflight when over cap, not payloads the connector knowingly publishes.
- CLS memory is per-role peak plus repeated allocation/work, not necessarily all roles simultaneously.
- Account filtering exists; the residual defect is nullable eligibility and strict whole-export failure for assigned rejected identities.

### Rejected claims

1. **Rejected:** direct Basic ownership must correlate every owner team with a separate team-level table entitlement. The connector includes owner/group-team ownership for a directly entitled Basic user (`policyweaver/plugins/dataverse/client.py:1185-1190`), and the documented Dataverse access check combines the user's privilege with ownership through team membership. The test confirms owner teams are included and access teams are not (`tests/test_dataverse_basic_owner_isolation.py:600-620`). Mixed-time membership remains an H1 snapshot risk, not this proposed defect.
2. **Rejected:** expanded relationships are not paged. They are paged and tested.
3. **Rejected:** account-state filtering is absent. It exists, subject to M1.
4. **Rejected:** every secured column is masked. Masking is optional and separate.
5. **Rejected:** an extraction exception itself causes mass revocation. Pre-apply failure leaves current roles; structurally valid empty/partial desired state is the revocation risk.

### Residual uncertainty

- Public documentation confirms masking semantics and OneLake allow/hide behavior, but this review did not establish that every ingestion path stores original unmasked values. Exact parity still cannot be proved, so C2 remains a strict gate.
- No specific OneLake Security GA announcement date was independently verified. As of 2026-08-31, the cited current Learn pages are not preview-labelled; this report does not overstate a particular announcement/date.
- No sufficiently explicit public statement proved that bulk POA extraction is universally impossible. Current code still relies on an external `verified_empty` assertion rather than programmatic proof.
- One 500-role/12,500-user synthetic topology was benchmarked, but no tenant-backed run or benchmark using the customer's redacted entitlement distribution was performed.
- Tenant/item-specific quota escalation and engine behavior remain deployment validation items even when public limits are known.

## 13. Assumptions and open questions

1. What is the redacted distribution of roles per user, users per role, tables per role, depth mix, team overlap, and distinct CLS signatures?
2. Are any secured columns masked, and which consumers have each `Read unmasked` state?
3. Which mapped consumers have workspace roles, item permissions, SQL permissions, or other Fabric access outside DARs?
4. Are POA, POAA, hierarchy security, RecordFilter, access teams, or dynamic Entra group teams in active use?
5. Are System Administrators in scope, and how will their bypass be represented or excluded?
6. Are impersonation, delegation, or application-user flows required for analytical access parity?
7. Is the support-escalated 1,000-role quota confirmed on every target item, and what is the approved response when projection exceeds it?
8. What source-change detection, maximum stale-access interval, revocation budget, approval workflow, and rollback objective does the bank require?
9. Does the destination contain original or independently masked values for every protected column?
10. Which Fabric engines consume the item, and how will the documented propagation windows be measured?

## 14. Prioritized remediation

### P0 — production blockers

1. Extend target-boundary validation to workspace/item/SQL access and administrator exclusions.
2. Extract and enforce masking/`Read unmasked`, or block all uncertain masking.
3. Enforce complete secured-table/column discovery.
4. Design deterministic/versioned extraction with mutation detection and restart.
5. Implement baseline counts, change budgets, approval, before-image, rollback, and stale-access alerting.
6. Map or exclude System Administrators.
7. Produce a redacted scale projection and block topologies over the confirmed quota.

### P1 — security and reliability hardening

1. Replace process-global source/authentication state with per-run dependencies.
2. Fail closed on nullable/disabled eligibility.
3. Fix or remove the alternate `has_read` path.
4. Add an end-to-end deadline, cancellation, terminal run state, and recovery procedure.
5. Add explicit tests for bypass grants, masking states, metadata omissions, concurrent mutation, large deletions, and administrator CLS.

### P2 — scale and maintainability

1. Cache/reuse BU child maps per environment generation.
2. Compute CLS signatures once per role/generation and reuse them across preflight/construction.
3. Turn the 12,500-user/500-role/25-profile harness into a repeatable CI benchmark and add customer-shaped redacted distributions, payload size, and regression thresholds.
4. Clarify connector/plugin terminology, synchronous behavior, and snapshot-callback semantics; add correctly spelled callback aliases.

## 15. Public Microsoft documentation

Accessed 2026-08-31:

- [Data security overview - Microsoft Fabric](https://learn.microsoft.com/en-us/fabric/onelake/security/get-started-security)
- [OneLake security roles, permissions, and scopes](https://learn.microsoft.com/en-us/fabric/onelake/security/data-access-control-model)
- [Create and manage OneLake security roles](https://learn.microsoft.com/en-us/fabric/onelake/security/create-manage-roles)
- [OneLake table, column, and row-level security](https://learn.microsoft.com/en-us/fabric/onelake/security/table-column-row-security)
- [Roles in workspaces in Microsoft Fabric](https://learn.microsoft.com/en-us/fabric/fundamentals/roles-workspaces)
- [Column-level security - Power Platform](https://learn.microsoft.com/en-us/power-platform/admin/field-level-security)
- [Create and manage masking rules - Power Platform](https://learn.microsoft.com/en-us/power-platform/admin/create-manage-masking-rules)
- [Page results using OData from Dataverse Web API](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/webapi/query/page-results)
- [Order rows using OData in Dataverse](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/webapi/query/order-rows)
- [Use change tracking to synchronize external systems](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/use-change-tracking-synchronize-data-external-systems)
- [How access to a record is determined](https://learn.microsoft.com/en-us/power-platform/admin/how-record-access-determined)
- [Teams in Dataverse](https://learn.microsoft.com/en-us/power-platform/admin/manage-teams)
- [Access Teams and Owner Teams for Record Sharing](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/use-access-teams-owner-teams-collaborate-share-information)
- [systemuser EntityType](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/webapi/reference/systemuser?view=dataverse-latest)

The current Learn pages above are not preview-labelled. This review uses their current documented behavior but makes no unsupported claim about a specific GA announcement date.
