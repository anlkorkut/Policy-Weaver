# Dataverse Security Sync Runbook

This runbook is for regulated environments where both overgrant and undergrant are release blockers. Use a dedicated Dataverse sandbox and a dedicated Fabric mirrored item until every gate passes.

## Current Matrix Result

The checked-in `Dataverse_Security_Roles_Consolidated.xlsx` contains:

- 194 role rows and 194 unique exact role names
- 159 unique role IDs
- 60,991 privilege rows
- 19,475 Read grants across 2,044 targets
- no users, user-role assignments, teams, team memberships, business-unit hierarchy, field-profile assignments, POA, or POAA

It is useful for role-definition testing but cannot prove effective access for an estate described as roughly 500 roles and 12,500 users.

## Gate 0: Credentials and Isolation

1. Rotate any client secret that has appeared in a file, terminal output, or chat transcript.
2. Keep `configdataverse.yaml` ignored and untracked.
3. Prefer Key Vault secret names in configuration.
4. Use a Dataverse application user with only the required read privileges.
5. If any assigned Dataverse application user has `applicationid` but no `azureactivedirectoryobjectid`, grant the Policy Weaver app Microsoft Graph application permission `Application.Read.All` and admin consent. Verify a service-principal lookup returns 200; strict apply stops on any unresolved member.
6. Use a dedicated Fabric item with no unmanaged OneLake roles.
7. Set `fabric.delete_default_reader_role: true`.
8. Ensure test personas are Fabric Viewers or have item Read. Admin, Member, and Contributor workspace roles bypass OneLake RLS and CLS.

## Gate 1: Offline Matrix Validation

```powershell
Set-Location C:\Users\anilkorkut\Policy-Weaver
& .\.venv-x64\Scripts\Activate.ps1

python scripts\dataverse_role_matrix_preflight.py `
  --workbook Dataverse_Security_Roles_Consolidated.xlsx `
  --expected-role-count 500 `
  --output reports\dataverse-role-matrix-preflight.json
```

Do not continue on the assumption that this is the complete customer extract. Obtain a source-controlled export of the missing role definitions and a separate, timestamped entitlement inventory.

## Gate 2: Optional Sandbox Role Import

Role import changes Dataverse. Run it only in a sandbox. First build a plan:

```powershell
python scripts\dataverse_role_import.py `
  --config configdataverse.yaml `
  --workbook Dataverse_Security_Roles_Consolidated.xlsx `
  --organization-id <dataverse-organization-guid> `
  --environment-id <power-platform-environment-guid> `
  --max-roles 3 `
  --plan-output reports\dataverse-role-import-canary-plan.json
```

The plan must report zero missing privilege assignments for an exact test. Missing privileges usually mean the target sandbox doesn't contain the customer's managed solutions. Never use `--allow-partial` for parity certification.

After reviewing the canary plan:

```powershell
python scripts\dataverse_role_import.py `
  --config configdataverse.yaml `
  --workbook Dataverse_Security_Roles_Consolidated.xlsx `
  --organization-id <dataverse-organization-guid> `
  --environment-id <power-platform-environment-guid> `
  --max-roles 3 `
  --apply `
  --plan-output reports\dataverse-role-import-canary-plan.json `
  --manifest reports\dataverse-role-import-canary-manifest.json
```

Verify every root and BU-specific role instance:

```powershell
python scripts\dataverse_role_import.py `
  --config configdataverse.yaml `
  --organization-id <dataverse-organization-guid> `
  --environment-id <power-platform-environment-guid> `
  --verify-manifest reports\dataverse-role-import-canary-manifest.json `
  --verify-plan reports\dataverse-role-import-canary-plan.json `
  --verify-all-instances `
  --verify-instances-output reports\dataverse-role-import-canary-verification.json
```

Only repeat without `--max-roles` after the canary has zero missing privileges, depth mismatches, and unexpected privileges. The prior sandbox evidence in [dataverse-role-import-summary.md](../reports/dataverse-role-import-summary.md) was partial because customer solutions were absent, so it is not parity evidence.

## Gate 3: Read-Only Environment Inventory

```powershell
python scripts\dataverse_environment_inventory.py `
  --config configdataverse.yaml `
  --compile-policies `
  --compile-without-cls `
  --output reports\dataverse-environment-inventory.json
```

Review at least:

- active and eligible users, application users, and unresolved Entra IDs
- role instances and user/team role-assignment edges
- owner/access/group team counts and membership edges
- complete active and disabled BU hierarchy
- `isinherited` values for every team-assigned role
- Basic, Local, Deep, Global, Unknown, and RecordFilter counts
- field profiles, permissions, assignments, secured-table metadata, and POAA read grants
- hierarchy-security status and mode
- projected OneLake role/member/permission/predicate counts

## Gate 4: External POA Review

The supported Dataverse Web API has no bulk `PrincipalObjectAccess` collection query. Do not infer that POA is empty from a successful connector run.

Use a Microsoft-supported, customer-approved process to establish whether relevant mirrored records have Read shares from direct sharing, access teams, reassignment, or cascade sharing. For a narrowly scoped validation set, `RetrieveSharedPrincipalsAndAccess` can be called per record. For a large estate, obtain a governed POA inventory or entitlement materialization from the Dataverse owner.

- If relevant POA read access exists, this build cannot claim exact parity. Stop.
- If evidence proves there are no relevant POA read shares, archive the evidence and set `dataverse.poa_read_access_status: verified_empty`.

Also review Dataverse column masking and `CanReadUnmasked` privileges. OneLake column constraints can allow or hide a column, but cannot reproduce masked-value presentation. Live extraction queries active `AttributeMaskingRule` assignments within the selected table scope; zero returned assignments is authoritative evidence that masking is absent for that scope.

- If relevant secured columns use masking, this build cannot claim exact parity. Keep affected roles quarantined.
- Use `dataverse.column_masking_status: verified_absent` only as a fallback for an externally supplied snapshot that lacks masking-assignment state, and only after archived evidence proves masking semantics are absent for the mirrored scope. A live active assignment overrides that setting and remains blocked.

## Gate 5: Offline Scale Test

```powershell
python scripts\dataverse_scale_preflight.py `
  --users 12500 --roles 500 --profiles 25 `
  --roles-per-user 5 --business-units 10 --owner-teams 100 `
  --tables-per-role 10 --role-limit 1000 `
  --output reports\dataverse-scale-preflight.json
```

The current synthetic result exercises all 500 roles:

- direct-role RLS baseline: 500 generated roles, 62,500 memberships, 5,000 table scopes, and 3,330 row constraints
- cross-BU overlapping owner-team role assignments: blocked at a projected minimum of 54,948 roles
- Basic role assigned to 12,500 users: blocked because exact isolation needs 12,500 roles, above the approved 1,000-role quota
- multi-role RLS plus 25-profile CLS: blocked for 12,500 user-table assignments because OneLake doesn't support that composition

Synthetic success measures mapper capacity only. It does not certify customer entitlement parity.

## Gate 6: Strict Compile

Required configuration:

```yaml
fabric:
  policy_mapping: role_based
  delete_default_reader_role: true
constraints:
  columns:
    columnlevelsecurity: true
    fallback: deny
  rows:
    rowlevelsecurity: true
    fallback: deny
dataverse:
  onelake_role_limit: 1000
  row_constraint_chunk_length: 4096
  strict_access_parity: true
  poa_read_access_status: verified_empty
  column_masking_status: verified_absent
```

Run source compilation without a Fabric call:

```powershell
& .\.venv-x64\Scripts\python.exe -m scripts.dataverse_policy_sync `
  --config configdataverse.yaml `
  --output reports\dataverse-policy-strict-compile.json
```

Strict compile stops on POAA, RecordFilter, hierarchy security, role- or field-profile-assigned Entra group teams, unknown depth/inheritance, unresolved identities, unrepresentable row predicates, empty CLS allowlists, unsupported RLS+CLS composition, or quota overflow. Do not work around a blocker by disabling CLS or strict mode.

In-scope application users that have only `applicationid` (no `azureactivedirectoryobjectid`) are resolved through Microsoft Graph and the export is only stamped strict-validated after every discovered app-only identity resolves exactly. Any unresolved app-only identity fails the whole strict run and the export is never validated, so a later apply is rejected. This mirrors partial sync's Graph resolution, except partial audits and skips only the affected principals instead of failing the run. Grant the Policy Weaver app `Application.Read.All` with admin consent before strict runs that assign app-only users.

## Gate 6B: Explicit Partial Sync

Use partial sync only when an intentional under-grant is acceptable. It quarantines the entire source role when any grant in that role is unsafe or unrepresentable. Identity-only failures are quarantined at principal level: an unresolved or ineligible direct user, a missing direct-user snapshot, or a missing or unresolved Owner/Access team member is omitted while resolvable members retain the complete source-role permissions. A truly absent user snapshot is omitted and audited because no business-unit context exists to evaluate. A known user excluded for ineligibility or unresolved Graph identity still whole-role quarantines as `invalid_assignment_context` when its business unit is missing or differs from the role business unit. Dynamic Entra group teams and unsafe privilege, table, masking, ownership, capacity, or RLS+CLS semantics remain whole-role blockers. The JSON report separates skipped roles from skipped principal assignments and never claims exact parity.

Ownership type affects scoped row filters. Global reads on BusinessOwned tables are transferable without a predicate. Local and Deep reads use the mirrored table's `businessunitid`; Basic BusinessOwned reads remain unsupported and fail closed. Scoped reads on BusinessParented or otherwise unsupported ownership types remain quarantined.

Compile first:

```powershell
& .\.venv-x64\Scripts\python.exe -m scripts.dataverse_policy_sync `
  --config configdataverse.yaml `
  --tables-file reports\fabric-lakehouse-table-names.txt `
  --partial-sync `
  --output reports\dataverse-policy-partial-compile.json
```

Stop if the report is unexpected. In particular, review:

- `quarantine.included_role_count` and `skipped_role_count`
- every entry in `quarantine.skipped_roles`
- `quarantine.reason_counts`
- `quarantine.skipped_principal_assignment_count`, `principal_reason_counts`, and every entry in `skipped_principal_assignments`
- `quarantine.constraint_composition_conflicts`, `suppressed_redundant_scoped_grant_count`, and every entry in `suppressed_redundant_scoped_grants`
- `quarantine.environment_limitations`
- `quarantine.graph_validation` and any principal-level `unresolved_graph_service_principal` reasons
- `column_masking_unverified`, `incomplete_cls_metadata`, and `inconsistent_cls_metadata` reasons
- `unrepresentable_row_constraint` and `no_readable_columns` whole-role reasons
- generated memberships, table scopes, row constraints, and column constraints

For a CLS-secured table, OneLake cannot safely combine multiple roles for the same user when any role has RLS. Partial mode can resolve one exact case: if a surviving Global grant already gives that user the same table access, the connector removes only the redundant scoped user-table edge and preserves all unrelated members and tables. Capacity is recalculated after residual roles are formed. Scoped-vs-scoped conflicts, loss of the Global dominator, and partially dominated row-filter chunks remain whole-role quarantines with `unsupported_multi_role_rls_cls`.

Partial mode is an authoritative replacement. Existing Policy Weaver-managed roles that are not in the valid subset will be deleted on apply. Compare the current managed-role count with the generated/projected count and archive the successful dry-run report. If every role is quarantined, or if conversion resolves to no publishable Fabric roles, publication is blocked to prevent an empty replacement.

Application users with only `applicationid` are resolved through Microsoft Graph before the final subset is stamped. Unresolved identities are omitted from direct assignments and Owner/Access team expansion; otherwise resolvable members of the same role remain publishable. Roles with no resolvable members are quarantined as `no_resolvable_members`. If all or most application IDs are unresolved, stop and grant `Application.Read.All` application permission with admin consent before proceeding; otherwise the partial result can be a severe under-grant.

## Gate 7: Fabric Dry Run

The CLI first performs a no-change write-readiness check by replaying the current sanitized role collection with `dryRun=true` and its ETag. This check runs before Dataverse extraction. If Fabric returns `CapacityNotActive`, the report records the capacity ID and `fabric_write_preflight: blocked-capacity-not-active`; no roles are changed. An Azure owner must resume the F SKU capacity in the Azure portal or through `Microsoft.Fabric/capacities/resume/action`, or reassign the workspace to an active compatible capacity. Resuming restarts billing.

```powershell
& .\.venv-x64\Scripts\python.exe -m scripts.dataverse_policy_sync `
  --config configdataverse.yaml `
  --fabric-dry-run `
  --output reports\dataverse-policy-fabric-dry-run.json
```

The script reads all paginated roles, rejects unmanaged roles, and sends the complete candidate collection with `dryRun=true` and `If-Match`. No role is changed.

For a reviewed partial subset:

```powershell
& .\.venv-x64\Scripts\python.exe -m scripts.dataverse_policy_sync `
  --config configdataverse.yaml `
  --tables-file reports\fabric-lakehouse-table-names.txt `
  --partial-sync `
  --fabric-dry-run `
  --confirm-item <exact-fabric-item-id> `
  --output reports\dataverse-policy-partial-dryrun.json
```

## Gate 8: Canary and Full Apply

Apply first to a disposable item with representative synthetic principals. For the dedicated target:

```powershell
& .\.venv-x64\Scripts\python.exe -m scripts.dataverse_policy_sync `
  --config configdataverse.yaml `
  --apply `
  --confirm-item <exact-fabric-item-id> `
  --rollback-output reports\dataverse-policy-rollback.json `
  --output reports\dataverse-policy-apply.json
```

The command reads the prior role collection once, validates it, and persists a sanitized deep copy of the raw PUT-relevant before-image, including `kind`, with that collection's ETag. Preparation is one-shot and bound to the connector, strict/partial mode, workspace, item, acknowledgement, and ETag; those values are checked at apply entry and again immediately before the authoritative PUT. Dry-run and apply use the snapshot's same ETag. If the snapshot cannot be written, apply is blocked. `--output` and `--rollback-output` must resolve to different paths. Ambiguous timeout or connection failures are accepted as success only when a subsequent GET semantically matches the requested collection. This comparison ignores only top-level server-assigned role IDs and Fabric-omitted `members.microsoftEntraMembers[].objectType`; all security-bearing IDs, tenant IDs, role names, scopes, permissions, and constraints remain compared. Identical reruns make no PUT.

Rollback:

```powershell
& .\.venv-x64\Scripts\python.exe -m scripts.dataverse_policy_sync `
  --config configdataverse.yaml `
  --rollback reports\dataverse-policy-rollback.json `
  --confirm-item <exact-fabric-item-id> `
  --output reports\dataverse-policy-rollback-result.json
```

Partial apply requires an additional acknowledgement:

```powershell
& .\.venv-x64\Scripts\python.exe -m scripts.dataverse_policy_sync `
  --config configdataverse.yaml `
  --tables-file reports\fabric-lakehouse-table-names.txt `
  --partial-sync `
  --apply `
  --confirm-partial-sync `
  --confirm-item <exact-fabric-item-id> `
  --rollback-output reports\dataverse-policy-partial-rollback.json `
  --output reports\dataverse-policy-partial-apply.json
```

## Gate 9: Persona-Level Proof

Role counts alone do not prove authorization. Select representative personas covering:

- multiple direct roles with overlapping depths
- direct and owner-team role overlap
- team-only and direct-user Basic inheritance
- users from root, parent, child, sibling, and disabled BUs
- uniform, divergent, and no-read field profiles
- human and application users
- current-state team-owned cases and future-state BU-driven access

For each persona and scoped table:

1. Query Dataverse as that principal and record the primary-key set and readable columns.
2. Query Fabric as the same Entra principal.
3. Compare exact primary-key sets, not only counts.
4. Compare readable column sets.
5. Record false positives as overgrants and false negatives as undergrants.
6. Require zero mismatches before promotion.

POA, POAA, RecordFilter, or hierarchy-security personas must remain blocked until their semantics are implemented in an enforcement layer that can represent them exactly.