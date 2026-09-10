  <p align="center">
  <img src="./assets/policyweaver.png" alt="Policy Weaver icon" width="200"/>
</p>

</p>
<p align="center">
<a href="https://badgen.net/github/license/microsoft/Policy-Weaver" target="_blank">
    <img src="https://badgen.net/github/license/microsoft/Policy-Weaver" alt="License">
</a>
<a href="https://badgen.net/github/releases/microsoft/Policy-Weaver" target="_blank">
    <img src="https://badgen.net/github/releases/microsoft/Policy-Weaver" alt="Test">
</a>
<a href="https://badgen.net/github/contributors/microsoft/Policy-Weaver" target="_blank">
    <img src="https://badgen.net/github/contributors/microsoft/Policy-Weaver" alt="Publish">
</a>
<a href="https://badgen.net/github/commits/microsoft/Policy-Weaver" target="_blank">
    <img src="https://badgen.net/github/commits/microsoft/Policy-Weaver" alt="Commits">
</a>
<a href="https://badgen.net/pypi/v/Policy-Weaver" target="_blank">
    <img src="https://badgen.net/pypi/v/Policy-Weaver" alt="Package version">
</a>
  <a href="https://badgen.net/pypi/dm/policy-weaver" target="_blank">
    <img src="https://badgen.net/pypi/dm/policy-weaver" alt="Monthly Downloads">
</a>
</a>
  <a href="https://badge.socket.dev/pypi/package/policy-weaver?artifact_id=tar-gz" target="_blank">
    <img src="https://badge.socket.dev/pypi/package/policy-weaver?artifact_id=tar-gz" alt="Socket Badge">
</a>
</p>

---

# Policy Weaver: synchronizes data access policies across platforms

A Python-based accelerator designed to automate the synchronization of security policies from different source catalogs with [OneLake Security](https://learn.microsoft.com/en-us/fabric/onelake/security/get-started-data-access-roles) roles. While mirroring is only synchronizing the data, **Policy Weaver** is adding the missing piece which is mirroring data access policies to ensure consistent security across data platforms.


## :rocket: Features
- **Microsoft Fabric Support**: Direct integration with Fabric Mirrored Databases/Catalogs and OneLake Security.
- **Runs anywhere**: It can be run within Fabric Notebook or from anywhere with a Python runtime.
- **Effective Policies**: Resolves effective read privileges automatically, traversing nested groups and roles as required.
- **Pluggable Framework**: Supports Azure Databricks, Snowflake, and Dataverse policies, with more connectors planned.
- **Secure**: Can use Azure Key Vault to securely manage sensitive information like Service Principal credentials and API tokens.


## Table of Contents
- [Installation](#hammer_and_wrench-installation)
- [Getting Started](#rocket-getting-started)
  - [General Prerequisites](#clipboard-general-prerequisites)
  - [Databricks specific setup](#thread-databricks-specific-setup)
  - [Snowflake specific setup](#thread-snowflake-specific-setup)
  - [Dataverse specific setup (Beta)](#thread-dataverse-specific-setup-beta)
- [Config File values](#books-config-file-values)
- [Column Level Security](#books-column-level-security)
- [Row Level Security](#books-row-level-security)
- [Feedback](#raising_hand-feedback)


## :hammer_and_wrench: Installation
Make sure your Python version is greater or equal than 3.11. Then, install the library:
```bash
$ pip install policy-weaver
```

# :rocket: Getting Started

Follow the General Prerequisites and Installation steps below [here](#clipboard-general-prerequisites). Then, depending on your source catalog, follow the specific setup instructions for [Databricks](#thread-databricks-specific-setup), [Snowflake](#thread-snowflake-specific-setup), or [Dataverse](#thread-dataverse-specific-setup-beta).
If you run into any issues, wish for new features or let us know that you like the accelerator, let us know via our feedback form [https://aka.ms/pwfeedback](https://aka.ms/pwfeedback)

## :clipboard: General Prerequisites
Before installing and running this solution, ensure you have:
- **Azure [Service Principal](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal)** with the following [Microsoft Graph API permissions](https://learn.microsoft.com/en-us/graph/permissions-reference) (*This is not mandatory in every case but recommended, please check the specific source catalog requirements and limitations*):
  - `User.Read.All` as application permissions
- [A client secret](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal#option-3-create-a-new-client-secret) for the Service Principal
- Added the Service Principal as [Admin](https://learn.microsoft.com/en-us/fabric/fundamentals/give-access-workspaces) on the Fabric Workspace containing the mirrored database/catalog.
- The Service Principal needs to be able to call public Fabric REST APIs. This is configured in the tenant settings via the following setting [service-principals-can-call-fabric-public-apis]( https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-developer#service-principals-can-call-fabric-public-apis)

> :pushpin: **Note:** Every source catalog has additional pre-requisites



## :thread: Databricks specific setup

### Azure Databricks Configuration
We assume you have an Entra ID integrated Unity Catalog in your Azure Databricks workspace. To set up Entra ID SCIM for Unity Catalog, please follow the steps in [Configure Entra ID SCIM for Unity Catalog](https://learn.microsoft.com/en-us/azure/databricks/admin/users-groups/scim/aad).

:clipboard: Note that we only sync groups, users and service principals on account level, i.e. specifically no legacy "local" workspace groups. If you still use local workspace groups, please migrate them: [Link to Documentation](https://learn.microsoft.com/en-us/azure/databricks/admin/users-groups/workspace-local-groups)

We also assume you already have a mirrored catalog in Microsoft Fabric. If not, please follow the steps in [Create a mirrored catalog in Microsoft Fabric](https://learn.microsoft.com/en-us/fabric/onelake/mirror-azure-databricks-catalog). You need to enable One Lake Security by opening the Item in the Fabric UI and click on "Manage OneLake data access".


<img width="570" height="268" alt="image" src="https://github.com/user-attachments/assets/462e8123-5929-427e-9408-31df95d44a15" />


To allow Policy Weaver to read the Unity Catalog metadata and access policies, you need to assign the following roles to your Azure Service Principal:
1. Go to the Account Admin Console (https://accounts.azuredatabricks.net/) :arrow_right: User Management :arrow_right: Add your Azure Service Principal. 
1. Click on the Service Principal and go to the Roles tab :arrow_right: Assign the role "Account Admin"
3. Go to the "Credentials & Secrets" tab :arrow_right: Generate an OAuth Secret. Save the secret, you will need it in your config.yaml file as the `account_api_token`.

### Update your Configuration file
Download this [config.yaml](./config.yaml) file template and update it based on your environment.

In general, you should fill the config file as described here: [Config File values](#books-config-file-values).

For Databricks specifically, you will need to provide:

- **workspace_url**: https://adb-xxxxxxxxxxx.azuredatabricks.net/
- **account_id**: your databricks account id  (You can find it in the URL when you are in the Account Admin Console: https://accounts.azuredatabricks.net/?account_id=<account_id>)
- **account_api_token**: Depending on the keyvault setting: the keyvault secret name or your databricks secret

### Run the Weaver!
This is all the code you need. Just make sure Policy Weaver can access your YAML configuration file.
```python
#import the PolicyWeaver library
from policyweaver.weaver import WeaverAgent
from policyweaver.plugins.databricks.model import DatabricksSourceMap

#Load config
config = DatabricksSourceMap.from_yaml("path_to_your_config.yaml")

#run the PolicyWeaver
await WeaverAgent.run(config)
```

All done! You can now check your Microsoft Fabric Mirrored Azure Databricks catalog´s new One Lake Security policies.

https://github.com/user-attachments/assets/4bacb45f-c019-4389-a711-974ffb550884


## :thread: Snowflake specific setup

### Snowflake Configuration
We assume you have an Entra ID integrated Snowflake workspace, i.e. users in Snowflake have the same login e-mail as in Entra ID and Fabric, ideally imported through a SCIM process.
We also assume you already have a mirrored snowflake database in Microsoft Fabric. If not, please follow the steps in [Create a mirrored Snowflake Datawarehouse in Microsoft Fabric](https://learn.microsoft.com/en-us/fabric/mirroring/snowflake-tutorial). You need to enable One Lake Security by opening the Item in the Fabric UI and click on "Manage OneLake data access".


<img width="512" height="282" alt="image" src="https://github.com/user-attachments/assets/2bc19234-7fbf-4c42-945d-6e215286e97a" />


For the Snowflake setup the Service Principal is required to have User.Read.All permissions for the Graph API to look up the Entra ID object id for each user.

To allow Policy Weaver to read the Snowflake metadata and access policies, you need to create a Snowflake user and role and assign the following privileges. Follow the following steps:
1. Create a new technical user in Snowflake, e.g. with the name POLICYWEAVER. (Optionally, but recommended: setup key-pair authentication for this user with an encrypted key as described [here](https://docs.snowflake.com/en/user-guide/key-pair-auth))
1. Create a new role e.g. ACCOUNT_USAGE and assign the following privileges to this role:
   - IMPORTED PRIVILEGES on the SNOWFLAKE database
   - USAGE on the WAREHOUSE you want to use to run the queries (e.g. COMPUTE_WH)
   - Assign the ACCOUNT_USAGE role to the POLICYWEAVER user

You can use the following SQL statements. Replace the role, user and warehouse names as required.
```sql
CREATE ROLE "ACCOUNT_USAGE";
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE ACCOUNT_USAGE;
GRANT USAGE ON WAREHOUSE COMPUTE_WH TO ROLE ACCOUNT_USAGE;
GRANT ROLE ACCOUNT_USAGE to USER "POLICYWEAVER";
```

### Update your Configuration file
Download this [config.yaml](./config.yaml) file template and update it based on your environment.

In general, you should fill the config file as described here: [Config File values](#books-config-file-values).

For Snowflake specifically, you will need to provide:

- **account_name**: your snowflake account name (e.g. KWADKA-AK8207) **OR** the secret name in the keyvault if you use keyvault
- **user_name**: the snowflake user name you created for Policy Weaver (e.g. POLICYWEAVER)  **OR** the secret name in the keyvault if you use keyvault
- **private_key_file**: the path to your private key file if you are using key-pair authentication (e.g. ./builtin/rsa_policyweaver_key.p8)
- **password**: the password of the snowflake user if you are using password authentication **OR** the passphrase of your private key if you are using key-pair authentication **OR** the secret name in the keyvault if you use keyvault
- **warehouse**: the snowflake warehouse you want to use to run the queries (e.g. COMPUTE_WH)


### Run the Weaver!
This is all the code you need. Just make sure Policy Weaver can access your YAML configuration file.
```python
#import the PolicyWeaver library
from policyweaver.weaver import WeaverAgent
from policyweaver.plugins.snowflake.model import SnowflakeSourceMap

#Load config
config = SnowflakeSourceMap.from_yaml("path_to_your_config.yaml")

#run the PolicyWeaver
await WeaverAgent.run(config)
```

All done! You can now check your Microsoft Fabric Mirrored Snowflake Warehouse´s new One Lake Security policies.


https://github.com/user-attachments/assets/4de93aa3-e6c2-4c5b-b220-b30f6bfafd2f


## :thread: Dataverse specific setup (Beta)

> :warning: **Beta Notice:** The Dataverse connector is currently in **beta**.Behavior and configuration options may change in future releases. Please provide feedback via [https://aka.ms/pwfeedback](https://aka.ms/pwfeedback).

### Microsoft Dataverse Configuration

We assume you have a Dataverse environment (e.g. Dynamics 365, Power Platform) with security roles, users, and teams configured. 

We also assume you use Dataverse´s Fabric Link to integrate with Microsoft Fabric. You need to enable OneLake Security by opening the Item in the Fabric UI and clicking on "Manage OneLake data access".

### Prerequisites

The Dataverse connector **does not require Microsoft Graph API permissions** (`User.Read.All`) on the Service Principal. Dataverse provides Azure AD object IDs for users and teams directly, so principal resolution happens without Graph lookups in most cases.

However, the Service Principal needs the following:

#### 1. Register an App in Azure Entra ID

If you haven't already created a Service Principal (see [General Prerequisites](#clipboard-general-prerequisites)):
- Go to **Azure Portal** > **Entra ID** > **App registrations** > **New registration**
- Note the **Client ID** and **Tenant ID**
- Under **Certificates & secrets**, create a client secret

#### 2. Create an Application User in Dataverse

This is the most critical step and the one most commonly missed:

1. Go to the [Power Platform Admin Center](https://admin.powerplatform.microsoft.com/) → select your environment
2. Navigate to **Settings** > **Users + permissions** > **Application users**
3. Click **+ New app user**
4. Select the app registration you created in step 1
5. Assign a **Business Unit**
6. Assign one or more **Security Roles** (see step 3)

> :pushpin: **Note:** Unlike Microsoft Graph, Dataverse does **not** require API permissions in the Entra app registration. The Application User + Security Role in Dataverse is what controls access.

#### 3. Assign the Right Security Role

The Service Principal (Application User) needs **Organization-level Read** access on the following Dataverse tables:

| Table | Reason |
|---|---|
| `systemuser` | Fetch users and their Azure AD object IDs |
| `team` | Fetch teams and team memberships |
| `role` | Fetch security roles |
| `roleprivileges` | Fetch privileges per role (including depth) |
| `privilege` | Resolve privilege names and access rights |
| `systemuserroles` | User-to-role assignments |
| `teamroles` | Team-to-role assignments |
| `fieldsecurityprofile` | Field-level security profiles |
| `fieldpermission` | Field-level permissions per profile |

The built-in **System Administrator** role covers all of these. For least-privilege access, create a custom security role with **Organization-level Read** on each table listed above.

#### 4. Verify the Environment URL

Make sure your `environment_url` in the config matches the actual Dataverse environment URL (e.g. `https://org21208c7b.crm.dynamics.com`). The OAuth token scope is derived from this URL.

### What Policy Weaver reads from Dataverse

Policy Weaver fetches the following security metadata from your Dataverse environment:

- **Users**: All active, non-disabled system users with Azure AD object IDs
- **Teams**: All teams (Owner, Access, AAD Security Group, AAD Office Group) with memberships
- **Security Roles**: All security roles and their read privileges per table
- **Privilege Depth**: The scope of each read privilege (Basic/User, Local/Business Unit, Deep/Parent BU, Global/Organization)
- **Field Security Profiles**: Column-level security profiles with read permissions and user/team assignments

### Privilege Depth Mapping

Policy Weaver maps Dataverse privilege depth levels to Fabric row-level security filters:

| Dataverse Depth | Dataverse Name | Fabric Row Filter | Description |
|---|---|---|---|
| User | Basic | `ownerid in ('<principal IDs>')` | Rows owned by the user or their teams |
| Business Unit | Local | `owningbusinessunit = '<role BU>'` | Rows in the role's business unit only |
| Parent: Child Business Units | Deep | `owningbusinessunit in ('<role BU>', '<descendant BUs>')` | Rows in the role's BU and all child BUs |
| Organization | Global | No row filter | All rows visible |
| Unknown / Unrecognized | — | `false` (deny all) | Fail-closed for safety |

> :pushpin: **Note:** Dataverse access is cumulative — the greatest depth prevails. If a user has both a Local and a Global role on the same table, Global wins and no row filter is applied.

### Fabric OneLake Security Role Limits

OneLake Security has a default limit of **250 Data Access Roles** per item. In environments with many Dataverse security roles, users, and business units, Policy Weaver may generate roles that approach or exceed this limit — especially when per-principal splitting is used for Basic-depth or CLS isolation.

If you encounter the role count limit, you can request Microsoft to increase it to **1,000 roles** via a support ticket. Plan your Dataverse security role structure accordingly:
- Roles with **Global** depth generally share a Fabric role across members when CLS and OneLake chunking permit it
- Roles with **Local** or **Deep** depth can split per principal when cumulative personal or team ownership outside the BU scope requires an ownership overlay
- Roles with **Basic** depth split per effective principal for owner isolation
- Divergent field-security access is grouped by effective column allowlist, then split only when a group exceeds 500 members

Each OneLake role can contain at most **500 users or groups** and **500 permissions**. Policy Weaver automatically chunks larger shared Dataverse roles and includes those chunks in its preflight role-count check. For example, 12,500 directly assigned users require at least 25 OneLake roles when they share identical access with no per-principal ownership or CLS split. Although an AAD-backed Dataverse team can reduce member count in permissive legacy mode, strict and partial modes block dynamic group-team role, field-security, and ownership-overlay dependencies because the snapshot cannot prove their effective membership.

Set `dataverse.onelake_role_limit` to the quota approved for the target Fabric item. Policy generation fails before upload when exact Basic/CLS isolation, member chunks, permission chunks, or row-filter chunks exceed that quota.

The current Fabric REST schema does not document a maximum length for `RowConstraint.value`. Policy Weaver nevertheless chunks long Dataverse predicates as an internal safeguard. On July 30, 2026, `dryRun=true` against the test mirror accepted predicates through **4,096 characters** and rejected 4,097 with `PolicyValidationError: Predicate in Row Constraint should not exceed 4096`. This is observed runtime behavior for that target, not a maximum declared by the REST schema. The default internal boundary is **4,096 characters** and can be changed with `dataverse.row_constraint_chunk_length`; validate candidate boundaries with `dryRun=true` for each target before changing it.

Generated Fabric role names are normalized to alphanumeric characters, include a stable hash, preserve the configured suffix, and are capped at 128 characters. The 4,096-character limit applies to row-constraint SQL, not role names.

### Policy Mapping Modes

- **`role_based`** (required): Starts from Dataverse security roles, then safely groups or chunks policies where OneLake limits and effective RLS/CLS entitlements require it.

Dataverse publication has two explicit validation modes:

- **Strict parity** (default): Any unsupported or incomplete security mechanism stops the whole run before Fabric.
- **Partial sync** (`--partial-sync`): Quarantines an entire Dataverse role when any of its grants has RecordFilter/unknown depth, an unrepresentable row predicate, no readable CLS columns, missing ownership metadata, scoped access on an unsupported ownership type, invalid BU/assignment context, dynamic Entra group-team semantics, unsupported multi-role RLS+CLS, or no remaining OneLake role capacity. This includes `dynamic_group_team_ownership` when a generated per-user owner filter depends on an AAD-backed team whose effective membership cannot be proven. Identity-only failures are narrower: unresolved application users, ineligible users, missing direct-user snapshots, and missing Owner/Access team snapshot members are omitted from direct assignments or team expansion after Graph validation. Resolvable peers keep the role's complete permissions; a role left with no resolvable members is quarantined with `no_resolvable_members`. Global reads on BusinessOwned tables need no row predicate, while Local and Deep reads use the mirrored table's `businessunitid`; Basic BusinessOwned reads remain unsupported and fail closed. Exact access parity is explicitly false.

Partial sync also reports environment-wide limitations such as unverified POA, POAA, hierarchy security, or column masking. These mechanisms are additive in Dataverse, so omitting them under-grants access; partial mode never treats their absence as parity evidence. Roles touching a table affected by a dynamic Entra group-assigned field security profile are quarantined rather than using an unverified membership snapshot. The connector reads active Dataverse `AttributeMaskingRule` assignments for the selected table scope: an empty authoritative result proves masking is absent, while roles touching an active masking assignment are quarantined because OneLake column allowlists cannot reproduce masked-value presentation or `CanReadUnmasked` privileges. `dataverse.column_masking_status: verified_absent` remains a fallback only for externally supplied snapshots that do not contain masking-assignment state.

Before publication, both strict and partial modes resolve application users that have only an `applicationid` (no Azure AD object id) through Microsoft Graph, and only for identities assigned within the configured table scope. **Strict parity** fails the entire run when any in-scope app-only identity cannot be resolved: no policies are applied and the export never receives the strict validation stamp, so a downstream apply is rejected. **Partial sync** is narrower: an unresolved application identity omits only that user's direct role assignments and Owner/Access team expansions, while otherwise valid members of the same source role remain publishable. The partial report records these omissions in `skipped_principal_assignment_count`, `principal_reason_counts`, and `skipped_principal_assignments` without including emails or display names. Grant the Policy Weaver application `Application.Read.All` application permission with admin consent to avoid failing (strict) or omitting (partial) valid application users. A Graph permission failure is treated as unresolved and therefore fails the strict run or under-grants in partial mode rather than exposing data.

A missing direct-user snapshot is omitted and audited at principal level because no business-unit context exists to evaluate. That exemption applies only when the user snapshot is truly absent. A known user excluded for ineligibility or unresolved Graph identity still whole-role quarantines as `invalid_assignment_context` when its business unit is missing or differs from the role business unit.

Partial apply is an authoritative replacement of Policy Weaver-managed Fabric roles. A quarantined role is absent from the desired collection and any older managed version is removed. Compare the current managed-role count with `quarantine.projected_onelake_role_count` before applying. The command refuses to publish when every role is quarantined or when policy conversion produces no publishable roles, requires a successful Fabric dry-run, takes a rollback snapshot, and requires both the exact item ID and `--confirm-partial-sync`.

Before any Fabric dry-run or apply, the CLI replays the current sanitized role collection with `dryRun=true` and its collection ETag. This write-readiness check happens before Dataverse extraction, so a suspended Fabric capacity fails quickly without changing roles. A `FabricCapacityNotActiveError` identifies the capacity and records `fabric_write_preflight: blocked-capacity-not-active` in the report. Resume the F SKU capacity through its Azure resource, or have its Azure owner reassign the workspace to an active compatible capacity. Resuming a capacity restarts billing.

```powershell
# 1. Compile and review reports/dataverse-policy-partial-compile.json.
& .\.venv-x64\Scripts\python.exe -m scripts.dataverse_policy_sync `
  --config configdataverse.yaml `
  --tables-file reports\fabric-lakehouse-table-names.txt `
  --partial-sync `
  --output reports\dataverse-policy-partial-compile.json

# 2. Validate the complete replacement payload without changing Fabric.
& .\.venv-x64\Scripts\python.exe -m scripts.dataverse_policy_sync `
  --config configdataverse.yaml `
  --tables-file reports\fabric-lakehouse-table-names.txt `
  --partial-sync `
  --fabric-dry-run `
  --confirm-item <exact-fabric-item-id> `
  --output reports\dataverse-policy-partial-dryrun.json

# 3. Apply only after reviewing the quarantine and dry-run reports.
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

When CLS is enabled, a secured role/table with no readable columns is not serialized as an empty allowlist. Strict Dataverse compilation fails the whole run; partial sync quarantines the entire source role, including otherwise valid sibling-table grants, with `no_readable_columns`.

Likewise, if even one value cannot fit the configured row-constraint predicate budget, strict compilation fails and partial sync quarantines the entire source role with `unrepresentable_row_constraint`. A serializer limitation never becomes a table-only deny or a weakened sibling grant.

Ownership-derived predicates that require multiple row chunks cannot be safely combined with CLS on the same table. Partial sync quarantines the whole source role with `unsupported_multi_role_rls_cls`; strict mode fails compilation. The only partial-mode exception is a scoped user-table grant made redundant by a surviving Global grant for the same user and table. Policy Weaver removes that redundant edge, preserves the role's other members and tables in residual policies, recomputes capacity, and records the result in `constraint_composition_conflicts` and `suppressed_redundant_scoped_grants`. Strict and partial modes also block AAD-backed dynamic team ownership dependencies before publication because their effective membership cannot be proven from the snapshot.

OneLake doesn't support a user reaching the same CLS-secured table through multiple roles when any of those roles contains RLS. This is common in Dataverse environments where access is cumulative across several security roles. Strict mode stops before upload. Partial mode resolves only the provably redundant Global-dominance case above; all scoped-vs-scoped and partially dominated chunked combinations remain whole-role quarantines.

### Update your Configuration file

Download the [config.yaml](./config.yaml) file template and update it based on your environment.

In general, you should fill the config file as described here: [Config File values](#books-config-file-values).

For Dataverse specifically, you will need to provide:

- **environment_url**: Your Dataverse environment URL (e.g. `https://org21208c7b.crm.dynamics.com`)

Set the `type` to `DATAVERSE`.

Here is a minimal example config:

```yaml
keyvault:
  use_key_vault: false
fabric:
  mirror_id: 845-----45567
  mirror_name: dataversemirror
  workspace_id: 9d-----7c
  tenant_id: 349-----e2885
  fabric_role_suffix: PW
  delete_default_reader_role: true
  policy_mapping: role_based
constraints:
  columns:
    columnlevelsecurity: true
    fallback: deny
  rows:
    rowlevelsecurity: true
    fallback: deny
service_principal:
  client_id: your-client-id
  client_secret: your-client-secret
  tenant_id: your-tenant-id
source:
  name: your-dataverse-environment
type: DATAVERSE
dataverse:
  environment_url: https://yourorg.crm.dynamics.com
  # Set this to the Data Access Role quota approved for the Fabric item.
  onelake_role_limit: 1000
  # Policy Weaver safeguard; this is not a documented Fabric service maximum.
  row_constraint_chunk_length: 4096
  # Required before any Fabric operation. Unsupported or incomplete source
  # security mechanisms stop compilation rather than silently under-granting.
  strict_access_parity: true
  # Leave false in YAML; enable explicitly with --partial-sync for each command.
  partial_sync: false
  # Leave unverified until an external POA review proves relevant shares are empty.
  poa_read_access_status: unverified
  # Fallback for externally supplied snapshots without masking-assignment state.
  # Live Dataverse extraction checks AttributeMaskingRule records directly.
  column_masking_status: unverified
```

### Run the Weaver!

This is all the code you need. Just make sure Policy Weaver can access your YAML configuration file.

```python
#import the PolicyWeaver library
from policyweaver.weaver import WeaverAgent
from policyweaver.plugins.dataverse.model import DataverseSourceMap

#Load config
config = DataverseSourceMap.from_yaml("path_to_your_config.yaml")

# Run non-Dataverse connectors. Dataverse publication must use the guarded
# scripts/dataverse_policy_sync.py workflow shown above.
await WeaverAgent.run(config)
```

All done! You can now check your Microsoft Fabric Mirrored Dataverse database's new OneLake Security policies.


## :books: Config File values

Here ´s how the config.yaml should be adjusted to your environment.

- keyvault:
  - use_key_vault: true/false (true if you want to use keyvault to store secrets, false if you want to store secrets directly in the config file)
  - name: your keyvault name (only required if use_key_vault is true)
  - authentication_method: azure_cli / fabric_notebook (only required if use_key_vault is true) :right_arrow: use fabric_notebook if you run it in a fabric notebook, otherwise use azure_cli and login with `az login` before running the weaver

- fabric:
    - mirror_id: the item id of the mirrored catalog/database/warehouse (you can find it in the URL when you open the workload item in the Fabric UI)
    - mirror_name: the name of the item in Fabric
    - workspace_id: your fabric workspace id (you can find it in the URL when you are in the Fabric workspace)
    - tenant_id: your fabric tenant id (you can find it in the URL "help" -> "about Fabric" section of the Fabric UI)
    - fabric_role_suffix: suffix for the fabric roles created by Policy Weaver (default: PW)
    - delete_default_reader_role: true/false (if true, the DefaultReader role created by Fabric will be deleted, if false it will be kept, default: true)
    - policy_mapping: role_based: create one role per role/group, default: role_based
- constraints:
    - columns: (optional, if not set, no column level security will be applied, see below for details [Column Level Security](#books-column-level-security))
      - columnlevelsecurity: true/false (if true, column level security will be applied at best effort. Default: false)
      - fallback: grant/deny (if a not supported column mask is found, the fallback will be applied. Default: deny)
    - rows: (optional, if not set, no row level security will be applied, see below for details [Row Level Security](#books-row-level-security))
      - RLS is always applied for non-Global depths to maintain access parity
      - fallback: grant/deny (if a not supported row mask is found, the fallback will be applied. Default: deny)

- service_principal:
  - client_id: the client id of the service principal mentioned under general prerequisites **OR** the corresponding secret name in the keyvault if you use keyvault
  - client_secret: the client secret of the service principal mentioned under general prerequisites **OR** the corresponding secret name in the keyvault if you use keyvault
  - tenant_id: the tenant id of the service principal mentioned under general prerequisites **OR** the corresponding secret name in the keyvault if you use keyvault

- source:
  - name of the unity catalog or snowflake database
  - schemas: list of schemas to include. If not set, all schemas are included. For each schema you can give a list of tables which should be included. If not set all tables are included (see examples below)

- type: either 'UNITY_CATALOG' for databricks, 'SNOWFLAKE' for snowflake, or 'DATAVERSE' for dataverse

Here is an example config.yaml **NOT** using keyvault:

```yaml
keyvault:
  use_key_vault: false
  name: notapplicable
  authentication_method: notapplicable
fabric:
  mirror_id: 845464654646adfasdf45567
  mirror_name: salescatalog
  workspace_id: 9d556498489465asdf7c
  tenant_id: 3494545asdfs7e2885
  fabric_role_suffix: PW
  delete_default_reader_role: true
  policy_mapping: role_based
constraints:
  columns:
    columnlevelsecurity: true
    fallback: deny
  rows:
    rowlevelsecurity: true
    fallback: deny
service_principal:
  client_id: 89ac5a4sd894as9df4sad89f
  client_secret: 1234556dsad4848129
  tenant_id: 3494545asdfs7e2885
source:
  name: dbxsalescatalog
  schemas: <---- optional, if not provided all schemas will be scanned
  - name: analystschema
    tables: <---- optional, if not provided all tables will be scanned
    - subsubanalysttable
type: UNITY_CATALOG
databricks:
  workspace_url: https://adb-6a5s4df9sd4fasdf.0.azuredatabricks.net/
  account_id: 085a54s65a4sfa6565asdff
  account_api_token: 74adsf84ad8f4a8sd4f8asdf
snowflake:
  account_name: KAIJOIWA-DUAK8207
  user_name: POLICYWEAVER
  private_key_file: rsa_key.p8
  password: ODFJo12io1212
  warehouse: COMPUTE_WH
```

Here is an example config.yaml **using** keyvault. 

:clipboard: Note that in this case, the user running the weaver needs to have access to the keyvault and the secrets.

```yaml
keyvault:
  use_key_vault: true
  name: policyweaver20250912
  authentication_method: fabric_notebook
fabric:
  mirror_id: 845464654646adfasdf45567
  mirror_name: SFDEMODATA
  workspace_id: 9d556498489465asdf7c
  tenant_id: 3494545asdfs7e2885
  fabric_role_suffix: PW
  delete_default_reader_role: true
  policy_mapping: role_based
constraints:
  columns:
    columnlevelsecurity: true
    fallback: deny
  rows:
    rowlevelsecurity: true
    fallback: deny
service_principal:
  client_id: kv-service-principal-client-id
  client_secret: kv-service-principal-client-secret
  tenant_id: kv-service-principal-tenant-id
source:
  name: SFDEMODATA
  schemas: <---- optional, if not provided all schemas will be scanned
  - name: analystschema
    tables: <---- optional, if not provided all tables will be scanned
    - subsubanalysttable
type: SNOWFLAKE
databricks:
  workspace_url: https://adb-1441751476278720.0.azuredatabricks.net/
  account_id: 085f281e-a7ef-4faa-9063-325e1db8e45f
  account_api_token: kv-databricks-account-api-token
snowflake:
  account_name: kv-sfaccountname
  user_name: kv-sfusername
  private_key_file: rsa_key.p8
  password: kv-sfpassword
  warehouse: COMPUTE_WH
```


## :books: Column Level Security

Column level security is an optional feature that can be enabled in the config file. If enabled, Policy Weaver will try to apply column level security at best effort and fallback to the configured fallback if a not supported column mask is found.

:warning: NOTE: Column level security is only enabled if the config `policy_mapping` is set to `role_based`. In the case of table_based mapping there would be an unforeseeable high number of roles created in Fabric. That´s why it can only be used in role_based mapping.

Databricks and Snowflake support column level security by column mask policies. Dataverse supports column level security via field security profiles. OneLake Security currently supports column level security by restricting visible columns in role constraints.

Given the biggest use case for column mask policies is to hide the whole column, this still aligns. However, if you have a column mask policy that is not supported by Policy Weaver, you can configure the fallback to either grant or deny access to this column by default.

Supported column mask policies:
- Databricks:
  - Allow only a specific group to see the real value. I.e. the function looks like `CASE WHEN is_account_group_member('HumanResourceDept') THEN ssn ELSE '<arbitrary_value>' END`
  - Allow everyone except a specific group to see the real value.  I.e. the function looks like `CASE WHEN is_account_group_member('HumanResourceDept') THEN '<arbitrary_value>' ELSE ssn END`
- Snowflake:
  - Allow only a specific role to see the real value. I.e. the function looks like `CASE WHEN CURRENT_ROLE() IN ('HR_ROLE') THEN ssn ELSE '<arbitrary_value>' END`
  - Allow everyone except a specific role to see the real value.  I.e. the function looks like `CASE WHEN CURRENT_ROLE() IN ('HR_ROLE') THEN '<arbitrary_value>' ELSE ssn END`
- Dataverse:
  - Field-level read permissions from Dataverse field security profiles are mapped to Fabric column constraints for role-based policies.

For Dataverse, if a role/table has no readable columns, strict compilation fails the whole run and partial sync quarantines the entire source role. Policy Weaver never keeps that role's sibling-table grants while dropping only the affected table.
:warning: NOTE: Our recommendation is to set the fallback to deny to avoid unintentional data exposure. If you identify a scenaro where there is a data exposure risk, please give us feedback and we´ll try to fix it asap. Note though that this solution is provided as-is without any warranties.

## :books: Row Level Security

Row level security is supported.


:warning: NOTE: Row level security is only enabled if the config `policy_mapping` is set to `role_based`. In the case of table_based mapping there would be an unforeseeable high number of roles created in Fabric. That´s why it can only be used in role_based mapping.


Databricks and Snowflake support various row level security variations. Dataverse uses privilege depth and business unit hierarchy semantics. OneLake Security sets row level security filters not on a table scope but a "table + role"-scope. For many use cases we can map source-side semantics to this "table + role"-scope.


If you have a row access policy that is not supported by Policy Weaver, you can configure the fallback to either grant or deny access to the whole table by default. This also includes unsupported policies like aggregation, join or projection policies in Snowflake.
:warning: NOTE: Our recommendation is to set the fallback to deny to avoid unintentional data exposure. If you identify a scenario where there is a data exposure risk, please give us feedback and we´ll try to fix it asap. Note though that this solution is provided as-is without any warranties.


Supported row access policies:
- Databricks:
  - Specify a filter for a specific group and a default for the rest in the form of: `IF(IS_ACCOUNT_GROUP_MEMBER('admin'), true, region='US');` 
  - Based on group membership allow access to certain rows via a CASE statement in the form of: `CASE WHEN IS_ACCOUNT_GROUP_MEMBER('subanalystgroup') THEN true WHEN IS_ACCOUNT_GROUP_MEMBER('analystgroup') THEN Id = 'T001' ELSE false END`


- Snowflake:
  - Allow only specific groups to see the values in the form of: `current_role() in ('SENSITIVE')`
  - Based on group membership allow access to certain rows via a CASE statement in the form of: `CASE WHEN current_role() in ('SENSITIVE') THEN true  WHEN current_role() in ('COUNTRY') THEN Id = 'T001' ELSE false END`

- Dataverse (role-based mapping):
  - `Global` depth: no row filter is applied.
  - `Deep` depth: rows are filtered to the role business unit and descendant business units.
  - `Local` depth: rows are filtered to the role business unit.
  - `Basic` depth: rows are filtered to records owned by principals in the role.


If you see demand for more (simple) row access policies which are not supported, please give us feedback and we´ll try to add them.


Dataverse serializer or predicate-budget failures are handled before role publication: strict mode fails compilation, while partial mode quarantines the entire source role rather than omitting one table and publishing its siblings.


## :raising_hand: Feedback

If you run into any issues, wish for new features or let us know that you like the accelerator, let us know via our feedback form [https://aka.ms/pwfeedback](https://aka.ms/pwfeedback)


## :raising_hand: Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## :scroll: License

This project is licensed under the MIT License - see the LICENSE file for details.

## :shield: Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
