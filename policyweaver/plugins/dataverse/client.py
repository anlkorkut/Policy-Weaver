import hashlib
import json
import os
import weakref
from collections import Counter
from typing import List, Dict, Tuple, Set
from urllib.parse import urlsplit

from policyweaver.models.export import (
    PermissionObject,
    RolePolicyExport,
    RolePolicy,
    PermissionScope,
    ColumnConstraint,
    RowConstraint,
)
from policyweaver.models.config import ConstraintsConfig, RowConstraintsConfig
from policyweaver.plugins.dataverse.model import (
    DataverseSourceMap,
    DataverseEnvironment,
    DataverseTablePermission,
)
from policyweaver.core.enum import (
    IamType,
    PermissionType,
    PermissionState,
    PolicyWeaverConnectorType,
)
from policyweaver.core.common import PolicyWeaverCore
from policyweaver.plugins.dataverse.api import DataverseAPIClient


_STRICT_VALIDATED_EXPORTS: dict[int, tuple[weakref.ReferenceType, str, str]] = {}


class _UnrepresentableRowConstraintError(ValueError):
    def __init__(self, schema_name: str, table_name: str) -> None:
        self.table_name = table_name
        super().__init__(
            f"Dataverse row constraint for {schema_name}.{table_name} cannot fit "
            "the configured predicate budget. No policies were generated or applied."
        )


def _digest_value(value) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(exclude_none=True, exclude_unset=True)
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _strict_config_digest(config: DataverseSourceMap) -> str:
    service_principal = getattr(config, "service_principal", None)
    fabric = getattr(config, "fabric", None)
    return _digest_value(
        {
            "type": config.type,
            "source": config.source,
            "fabric": {
                "tenant_id": getattr(fabric, "tenant_id", None),
                "workspace_id": getattr(fabric, "workspace_id", None),
                "mirror_id": getattr(fabric, "mirror_id", None),
                "fabric_role_suffix": getattr(fabric, "fabric_role_suffix", None),
                "delete_default_reader_role": getattr(
                    fabric, "delete_default_reader_role", None
                ),
                "policy_mapping": getattr(fabric, "policy_mapping", None),
            },
            "constraints": config.constraints,
            "mapped_items": config.mapped_items,
            "dataverse": config.dataverse,
            "service_principal_identity": {
                "tenant_id": getattr(service_principal, "tenant_id", None),
                "client_id": getattr(service_principal, "client_id", None),
            },
        }
    )


def is_dataverse_export_validated(
    export: RolePolicyExport, config: DataverseSourceMap
) -> bool:
    record = _STRICT_VALIDATED_EXPORTS.get(id(export))
    if not record:
        return False
    export_reference, export_digest, config_digest = record
    return (
        export_reference() is export
        and export_digest == _digest_value(export)
        and config_digest == _strict_config_digest(config)
    )


def is_strict_dataverse_export_validated(
    export: RolePolicyExport, config: DataverseSourceMap
) -> bool:
    return bool(
        config.dataverse.strict_access_parity
        and not config.dataverse.partial_sync
        and is_dataverse_export_validated(export, config)
    )


def _mark_strict_dataverse_export_validated(
    export: RolePolicyExport, config: DataverseSourceMap
) -> None:
    export_id = id(export)

    def remove_record(reference: weakref.ReferenceType) -> None:
        record = _STRICT_VALIDATED_EXPORTS.get(export_id)
        if record and record[0] is reference:
            _STRICT_VALIDATED_EXPORTS.pop(export_id, None)

    export_reference = weakref.ref(export, remove_record)
    _STRICT_VALIDATED_EXPORTS[export_id] = (
        export_reference,
        _digest_value(export),
        _strict_config_digest(config),
    )


class DataversePolicyWeaver(PolicyWeaverCore):
    """
    Dataverse Policy Weaver for Microsoft Dynamics 365 / Dataverse.
    This class extends the PolicyWeaverCore to implement the mapping of policies
    from Dataverse security model to the Policy Weaver framework.

    Dataverse security model includes:
    - Security Roles: Table-level CRUD privileges assigned to users/teams.
    - Field-Level Security: Column-level read restrictions via profiles.
    - Teams: Group users together, can have AAD-backed groups with Entra object IDs.
    """

    DEFAULT_ROW_CONSTRAINT_CHUNK_LENGTH = 4096
    FABRIC_ROLE_MEMBER_MAX = 500
    FABRIC_ROLE_PERMISSION_MAX = 500

    def __init__(self, config: DataverseSourceMap) -> None:
        super().__init__(PolicyWeaverConnectorType.DATAVERSE, config)
        self.__config_validation(config)
        self.__enforce_row_level_security__(config)
        self.config = config

        os.environ["DATAVERSE_ENVIRONMENT_URL"] = config.dataverse.environment_url

        self.api_client = DataverseAPIClient()
        self.environment: DataverseEnvironment = None
        self.partial_sync_report: Dict = {}
        self._partial_unresolved_application_ids: Set[str] = set()
        self._partial_excluded_user_ids: Set[str] = set()
        self._partial_checked_application_count = 0
        self._strict_unresolved_application_ids: Set[str] = set()
        self._strict_checked_application_count = 0

    def __config_validation(self, config: DataverseSourceMap) -> None:
        """Validate the Dataverse plugin configuration."""
        if not config.dataverse:
            raise ValueError(
                "DataverseSourceMap configuration is required for DataversePolicyWeaver."
            )

        if not config.dataverse.environment_url:
            raise ValueError(
                "Dataverse environment_url is required in the configuration."
            )

        if not config.dataverse.environment_url.startswith("https://"):
            raise ValueError("Dataverse environment_url must start with 'https://'.")

        parsed_url = urlsplit(config.dataverse.environment_url)
        if not parsed_url.hostname:
            raise ValueError("Dataverse environment_url must contain a valid hostname.")
        if parsed_url.username or parsed_url.password:
            raise ValueError(
                "Dataverse environment_url must not contain embedded credentials."
            )
        if parsed_url.path not in {"", "/"} or parsed_url.query or parsed_url.fragment:
            raise ValueError(
                "Dataverse environment_url must contain the environment origin only."
            )

        if config.dataverse.poa_read_access_status not in {
            "unverified",
            "verified_empty",
        }:
            raise ValueError(
                "dataverse.poa_read_access_status must be 'unverified' or "
                "'verified_empty'."
            )

        if config.dataverse.column_masking_status not in {
            "unverified",
            "verified_absent",
        }:
            raise ValueError(
                "dataverse.column_masking_status must be 'unverified' or "
                "'verified_absent'."
            )

        if config.dataverse.strict_access_parity and config.dataverse.partial_sync:
            raise ValueError(
                "dataverse.strict_access_parity and dataverse.partial_sync cannot "
                "both be true."
            )

    def __enforce_row_level_security__(self, config: DataverseSourceMap) -> None:
        """Keep the shared Fabric serializer from dropping Dataverse row filters."""
        if config.constraints is None:
            config.constraints = ConstraintsConfig()
        if config.constraints.rows is None:
            config.constraints.rows = RowConstraintsConfig()
        if not config.constraints.rows.rowlevelsecurity:
            self.logger.warning(
                "Dataverse row-level security is mandatory for access parity. "
                "Overriding constraints.rows.rowlevelsecurity to true."
            )
            config.constraints.rows.rowlevelsecurity = True

    def map_policy(self, policy_mapping: str = "role_based") -> RolePolicyExport:
        """
        Map Dataverse security policies to a role-based RolePolicyExport.

        Only 'role_based' mode is supported.  table_based mode cannot express
        row-level or column-level constraints and would over-grant access for
        non-Global privilege depths.

        Args:
            policy_mapping (str): Must be 'role_based'.
        Returns:
            RolePolicyExport: The mapped policies.
        """
        if policy_mapping != "role_based":
            raise ValueError(
                "Dataverse connector requires policy_mapping='role_based'. "
                "table_based mode cannot express row-level or column-level "
                "constraints and would over-grant access for non-Global "
                "privilege depths."
            )

        self.logger.info(f"Dataverse Policy Export for {self.config.source.name}...")

        self.environment = self.api_client.get_environment_security_map(
            self.config.source
        )
        if self.config.dataverse.partial_sync:
            self.partial_sync_report = {}
        self.__validate_security_coverage__()

        if (
            not self.environment.table_permissions
            and not self.environment.role_privileges
        ):
            self.logger.warning(
                "No table-level read permissions found in Dataverse environment."
            )

        export = self.__build_role_based_export__()
        if self.config.dataverse.strict_access_parity:
            # App-only service principals (application_id without an Azure AD object
            # id) require exact Microsoft Graph verification before publication. When
            # any are assigned in scope, leave this export unstamped so the CLI must
            # finalize through rebuild_strict_export_after_graph_validation; a direct
            # apply of the provisional export stays rejected by the strict gate.
            if not self.get_strict_application_ids_to_validate():
                _mark_strict_dataverse_export_validated(export, self.config)
        return export

    def get_partial_sync_report(self) -> Dict:
        return dict(getattr(self, "partial_sync_report", {}) or {})

    def __configured_table_scope__(self) -> Set[str]:
        config = getattr(self, "config", None)
        source = getattr(config, "source", None)
        return {
            str(table).strip().casefold()
            for schema in getattr(source, "schemas", None) or []
            for table in getattr(schema, "tables", None) or []
            if table and str(table).strip()
        }

    def __table_permissions_in_scope__(
        self,
    ) -> List[DataverseTablePermission]:
        environment = getattr(self, "environment", None)
        configured_tables = self.__configured_table_scope__()
        return [
            permission
            for permission in getattr(environment, "table_permissions", None) or []
            if getattr(permission, "table_name", None)
            and (
                not configured_tables
                or permission.table_name.casefold() in configured_tables
            )
        ]

    def __readable_table_permissions_in_scope__(
        self,
    ) -> List[DataverseTablePermission]:
        return [
            permission
            for permission in self.__table_permissions_in_scope__()
            if getattr(permission, "has_read", False)
        ]

    def __readable_scope_role_ids__(self) -> Set[str]:
        """Role IDs that grant a readable privilege inside the configured scope."""
        environment = getattr(self, "environment", None)
        configured_tables = self.__configured_table_scope__()
        return {
            privilege.role_id
            for privilege in getattr(environment, "role_privileges", None) or []
            if getattr(privilege, "role_id", None)
            and getattr(privilege, "entity_name", None)
            and getattr(privilege, "can_read", False)
            and (
                not configured_tables
                or privilege.entity_name.casefold() in configured_tables
            )
        }

    def __source_role_assignments__(
        self,
    ) -> Set[Tuple[str, IamType, str | None]]:
        environment = getattr(self, "environment", None)
        assignments = {
            (principal_id, principal_type, role_id)
            for principal_type, role_assignments in (
                (
                    IamType.USER,
                    getattr(environment, "user_role_assignments", None) or {},
                ),
                (
                    IamType.GROUP,
                    getattr(environment, "team_role_assignments", None) or {},
                ),
            )
            for principal_id, role_ids in role_assignments.items()
            if principal_id
            for role_id in role_ids or []
        }
        assignments.update(
            (permission.principal_id, permission.principal_type, permission.role_id)
            for permission in self.__readable_table_permissions_in_scope__()
            if getattr(permission, "principal_id", None)
            and getattr(permission, "principal_type", None)
            in {IamType.USER, IamType.GROUP}
        )
        return assignments

    def __scoped_source_role_assignments__(
        self,
    ) -> Set[Tuple[str, IamType, str | None]]:
        """Principal/role edges that actually drive scoped readable policies.

        Unlike __source_role_assignments__ (which stays deliberately broad so strict
        coverage validation remains fail-closed), this mirrors __build_role_map__
        source precedence so out-of-scope assignments never reach Microsoft Graph
        discovery. When in-scope table permissions are the active source they are
        authoritative and the assignment map is ignored; otherwise only assignment
        edges whose role has a readable in-scope privilege are included.
        """
        environment = getattr(self, "environment", None)
        if self.__table_permissions_in_scope__():
            return {
                (permission.principal_id, permission.principal_type, permission.role_id)
                for permission in self.__readable_table_permissions_in_scope__()
                if getattr(permission, "principal_id", None)
                and getattr(permission, "principal_type", None)
                in {IamType.USER, IamType.GROUP}
            }
        readable_role_ids = self.__readable_scope_role_ids__()
        return {
            (principal_id, principal_type, role_id)
            for principal_type, role_assignments in (
                (
                    IamType.USER,
                    getattr(environment, "user_role_assignments", None) or {},
                ),
                (
                    IamType.GROUP,
                    getattr(environment, "team_role_assignments", None) or {},
                ),
            )
            for principal_id, role_ids in role_assignments.items()
            if principal_id
            for role_id in role_ids or []
            if role_id in readable_role_ids
        }

    def __scoped_application_ids_to_validate__(self) -> Set[str]:
        """App-only service-principal IDs assigned within the configured scope.

        Discovery is scope-aware through __scoped_source_role_assignments__: only
        in-scope readable assignments and their Owner/Access team members
        contribute. An app-only identity is one with an applicationid but no Azure
        AD object id, which is exactly what must be proven through Microsoft Graph.
        """
        environment = getattr(self, "environment", None)
        source_assignments = self.__scoped_source_role_assignments__()
        assigned_user_ids = {
            principal_id
            for principal_id, principal_type, _ in source_assignments
            if principal_type == IamType.USER
        }
        assigned_team_ids = {
            principal_id
            for principal_id, principal_type, _ in source_assignments
            if principal_type == IamType.GROUP
        }
        for team in getattr(environment, "teams", None) or []:
            if team.id in assigned_team_ids:
                assigned_user_ids.update(team.member_ids or [])
        return {
            user.application_id
            for user in getattr(environment, "users", None) or []
            if user.id in assigned_user_ids
            and user.application_id
            and not user.azure_ad_object_id
        }

    def get_partial_application_ids_to_validate(self) -> Set[str]:
        dataverse = getattr(getattr(self, "config", None), "dataverse", None)
        if not getattr(dataverse, "partial_sync", False):
            return set()
        return self.__scoped_application_ids_to_validate__()

    def get_strict_application_ids_to_validate(self) -> Set[str]:
        dataverse = getattr(getattr(self, "config", None), "dataverse", None)
        if not getattr(dataverse, "strict_access_parity", False) or getattr(
            dataverse, "partial_sync", False
        ):
            return set()
        return self.__scoped_application_ids_to_validate__()

    def rebuild_partial_export_after_graph_validation(
        self,
        checked_application_ids: Set[str],
        unresolved_application_ids: Set[str],
    ) -> RolePolicyExport:
        if not self.config.dataverse.partial_sync:
            raise ValueError("Graph quarantine rebuild requires partial sync mode.")
        if not unresolved_application_ids.issubset(checked_application_ids):
            raise ValueError(
                "Unresolved application IDs must be a subset of checked IDs."
            )
        expected_application_ids = self.get_partial_application_ids_to_validate()
        if checked_application_ids != expected_application_ids:
            raise ValueError(
                "Graph validation must check exactly every discovered application ID."
            )
        self._partial_checked_application_count = len(checked_application_ids)
        self._partial_unresolved_application_ids = set(unresolved_application_ids)
        self.partial_sync_report = {}
        export = self.__build_role_based_export__()
        _mark_strict_dataverse_export_validated(export, self.config)
        return export

    def rebuild_strict_export_after_graph_validation(
        self,
        checked_application_ids: Set[str],
        unresolved_application_ids: Set[str],
    ) -> RolePolicyExport:
        """Finalize a strict export only after exact Graph verification.

        Analogous to rebuild_partial_export_after_graph_validation but fail-closed:
        strict security coverage must already have passed (via map_policy or a direct
        __validate_security_coverage__ call), the checked set must equal every
        discovered in-scope app-only identity, the unresolved set must be a subset,
        and any unresolved identity aborts the rebuild through
        __validate_resolvable_principals__ so no validated export is produced. Only a
        fully verified rebuild receives the strict validation stamp. This method
        never sets the coverage marker itself, so it cannot promote a client that
        never proved strict coverage.
        """
        if (
            not self.config.dataverse.strict_access_parity
            or self.config.dataverse.partial_sync
        ):
            raise ValueError(
                "Strict Graph finalization requires strict access parity mode."
            )
        # Fail-closed: the checked/unresolved-set validation below only runs once
        # strict security coverage has proven the snapshot is representable. A
        # manually constructed client that never ran __validate_security_coverage__
        # must not reach that validation or receive the strict stamp.
        if not getattr(self, "_strict_security_coverage_validated", False):
            raise ValueError(
                "Strict security coverage validation must complete before Graph "
                "finalization. Run map_policy (or __validate_security_coverage__) so "
                "strict coverage passes first; finalization never sets this marker."
            )
        if not unresolved_application_ids.issubset(checked_application_ids):
            raise ValueError(
                "Unresolved application IDs must be a subset of checked IDs."
            )
        expected_application_ids = self.get_strict_application_ids_to_validate()
        if checked_application_ids != expected_application_ids:
            raise ValueError(
                "Graph validation must check exactly every discovered application ID."
            )
        self._strict_checked_application_count = len(checked_application_ids)
        self._strict_unresolved_application_ids = set(unresolved_application_ids)
        export = self.__build_role_based_export__()
        _mark_strict_dataverse_export_validated(export, self.config)
        return export

    def __validate_security_coverage__(self) -> None:
        self._strict_security_coverage_validated = False
        source_role_assignments = self.__source_role_assignments__()
        readable_table_permissions = self.__readable_table_permissions_in_scope__()
        record_filter_count = sum(
            bool(privilege.record_filter_id)
            for privilege in self.environment.role_privileges or []
            if privilege.can_read
        )
        poaa_count = sum(
            bool(access.read_access)
            for access in self.environment.principal_object_attribute_accesses or []
        )
        dynamic_group_team_ids = {
            team.id
            for team in self.environment.teams or []
            if team.id and team.team_type in {2, 3}
        }
        group_team_count = sum(
            principal_type == IamType.GROUP and principal_id in dynamic_group_team_ids
            for principal_id, principal_type, _ in source_role_assignments
        )
        group_team_fsp_count = sum(
            team.team_type in {2, 3}
            and any(
                team.id in (profile.team_ids or [])
                for profile in self.environment.field_security_profiles or []
            )
            for team in self.environment.teams or []
        )
        unknown_depth_grants = {
            (
                privilege.role_id,
                privilege.entity_name.casefold(),
                (privilege.depth or "Unknown").title(),
            )
            for privilege in self.environment.role_privileges or []
            if privilege.can_read
            and privilege.entity_name
            and (privilege.depth or "Unknown").title()
            not in DataverseAPIClient.DEPTH_RANK
        }
        unknown_depth_grants.update(
            (
                permission.role_id or permission.role_name or "",
                permission.table_name.casefold(),
                (permission.depth or "Unknown").title(),
            )
            for permission in readable_table_permissions
            if (permission.depth or "Unknown").title()
            not in DataverseAPIClient.DEPTH_RANK
        )
        unknown_depth_count = len(unknown_depth_grants)
        team_role_ids = {
            role_id
            for _, principal_type, role_id in source_role_assignments
            if principal_type == IamType.GROUP
        }
        inheritance_by_role_id = {
            role.id: role.is_inherited
            for role in self.environment.security_roles or []
            if role.id
        }
        unknown_inheritance_count = sum(
            inheritance_by_role_id.get(role_id) not in {0, 1}
            for role_id in team_role_ids
        )
        if not self.config.dataverse.strict_access_parity:
            self.logger.warning(
                "Dataverse strict access parity is disabled. POA record shares "
                "cannot be bulk-extracted through the supported Web API; %d POAA "
                "field shares, %d RecordFilter read privileges, hierarchy security "
                "enabled=%s, %d dynamic Entra group-team role assignments, %d "
                "dynamic Entra group-team field-security assignments, %d unknown "
                "read depths, and %d unknown team-role inheritance modes can remain "
                "under-granted in Fabric.",
                poaa_count,
                record_filter_count,
                self.environment.hierarchy_security_enabled,
                group_team_count,
                group_team_fsp_count,
                unknown_depth_count,
                unknown_inheritance_count,
            )
            self.logger.warning(
                "Dataverse permissive mapping cannot prove dynamic Entra "
                "group-team ownership membership when those teams contribute "
                "to generated ownership-overlay filters."
            )
            return

        column_security = bool(
            self.config.constraints
            and self.config.constraints.columns
            and self.config.constraints.columns.columnlevelsecurity
        )
        if not column_security:
            raise ValueError(
                "Dataverse strict access parity requires column-level security."
            )
        if self.environment.hierarchy_security_enabled:
            model = (
                "position"
                if self.environment.hierarchy_security_uses_position
                else "manager"
            )
            raise ValueError(
                f"Dataverse {model} hierarchy security is enabled at depth "
                f"{self.environment.hierarchy_security_depth}; those additive row "
                f"entitlements are not translated to OneLake. No policies were applied."
            )
        if group_team_count:
            raise ValueError(
                f"Dataverse strict access parity found {group_team_count:,} "
                f"role-assigned Entra group-team records. Their dynamic, filtered "
                f"membership cannot be proven from the current Dataverse snapshot. "
                f"No policies were applied."
            )
        if group_team_fsp_count:
            raise ValueError(
                f"Dataverse strict access parity found {group_team_fsp_count:,} "
                f"Microsoft Entra group-team field security assignments. Their "
                f"dynamic, filtered membership cannot be proven from the current "
                f"snapshot. No policies were applied."
            )
        if record_filter_count:
            raise ValueError(
                f"Dataverse strict access parity cannot translate "
                f"{record_filter_count:,} RecordFilter-backed read privileges "
                f"to OneLake predicates. No policies were applied."
            )
        if unknown_depth_count:
            raise ValueError(
                f"Dataverse strict access parity found {unknown_depth_count:,} "
                f"read privileges with unknown privilege depth. No policies were applied."
            )
        if unknown_inheritance_count:
            raise ValueError(
                f"Dataverse strict access parity found {unknown_inheritance_count:,} "
                f"team-assigned roles with an unknown inheritance mode. "
                f"No policies were applied."
            )

        configured_tables = {
            str(table).strip().lower()
            for schema in self.config.source.schemas or []
            for table in schema.tables or []
            if table
        }
        readable_privileges = [
            privilege
            for privilege in self.environment.role_privileges or []
            if privilege.can_read
            and privilege.entity_name
            and (
                not configured_tables
                or privilege.entity_name.lower() in configured_tables
            )
        ]
        readable_tables = {
            privilege.entity_name.lower() for privilege in readable_privileges
        }
        readable_tables.update(
            permission.table_name.lower()
            for permission in readable_table_permissions
            if not configured_tables
            or permission.table_name.lower() in configured_tables
        )
        metadata_by_table = {
            metadata.logical_name.lower(): metadata
            for metadata in self.environment.table_metadata or []
            if metadata.logical_name
        }
        masking_rules = self.environment.attribute_masking_rules
        active_masking_tables = {
            rule.entity_name.lower() for rule in masking_rules or [] if rule.entity_name
        }
        masking_blocked_tables = readable_tables.intersection(active_masking_tables)
        if (
            masking_rules is None
            and self.config.dataverse.column_masking_status != "verified_absent"
        ):
            masking_blocked_tables.update(
                table_name
                for table_name in readable_tables
                if table_name in metadata_by_table
                and metadata_by_table[table_name].has_secured_columns
            )
        if masking_blocked_tables:
            raise ValueError(
                f"Dataverse strict access parity found "
                f"{len(masking_blocked_tables):,} readable tables with active or "
                f"unverified column masking semantics that cannot be reproduced. "
                f"No policies were applied."
            )
        incomplete_ownership = {
            table_name
            for table_name in readable_tables
            if table_name not in metadata_by_table
            or not metadata_by_table[table_name].ownership_type
        }
        if incomplete_ownership:
            raise ValueError(
                f"Dataverse strict access parity is missing ownership metadata for "
                f"{len(incomplete_ownership):,} readable tables. No policies were applied."
            )

        unsupported_scoped_ownership = [
            (table_name, depth)
            for table_name, depth in [
                *(
                    (privilege.entity_name.lower(), privilege.depth)
                    for privilege in readable_privileges
                ),
                *(
                    (permission.table_name.lower(), permission.depth)
                    for permission in readable_table_permissions
                    if not configured_tables
                    or permission.table_name.lower() in configured_tables
                ),
            ]
            if metadata_by_table[table_name].ownership_type
            not in {"UserOwned", "OrganizationOwned", "BusinessOwned"}
            and (depth or "Unknown").title() != "Global"
            or (
                metadata_by_table[table_name].ownership_type == "BusinessOwned"
                and (depth or "Unknown").title() == "Basic"
            )
        ]
        if unsupported_scoped_ownership:
            raise ValueError(
                f"Dataverse strict access parity cannot translate "
                f"{len(unsupported_scoped_ownership):,} scoped read grants on "
                f"BusinessOwned, BusinessParented, or unsupported ownership "
                f"tables. Global grants remain ownership-independent. "
                f"No policies were applied."
            )

        fsp_columns_by_table: Dict[str, Set[str]] = {}
        for profile in self.environment.field_security_profiles or []:
            for permission in profile.permissions or []:
                if permission.entity_name and permission.attribute_logical_name:
                    fsp_columns_by_table.setdefault(
                        permission.entity_name.lower(), set()
                    ).add(permission.attribute_logical_name.lower())
        inconsistent_cls_tables = set()
        for table_name in readable_tables:
            metadata = metadata_by_table[table_name]
            metadata_secured_columns = {
                column.logical_name.lower()
                for column in metadata.columns or []
                if column.logical_name and column.is_secured
            }
            fsp_columns = fsp_columns_by_table.get(table_name, set())
            if bool(metadata.has_secured_columns) != bool(
                metadata_secured_columns
            ) or not fsp_columns.issubset(metadata_secured_columns):
                inconsistent_cls_tables.add(table_name)
        if inconsistent_cls_tables:
            raise ValueError(
                f"Dataverse strict access parity found contradictory field-security "
                f"metadata for {len(inconsistent_cls_tables):,} readable tables. "
                f"No policies were applied."
            )

        invalid_organization_depths = [
            depth
            for table_name, depth in [
                *(
                    (privilege.entity_name.lower(), privilege.depth)
                    for privilege in readable_privileges
                ),
                *(
                    (permission.table_name.lower(), permission.depth)
                    for permission in readable_table_permissions
                    if not configured_tables
                    or permission.table_name.lower() in configured_tables
                ),
            ]
            if metadata_by_table[table_name].ownership_type == "OrganizationOwned"
            and (depth or "Unknown").title() != "Global"
        ]
        if invalid_organization_depths:
            raise ValueError(
                f"Dataverse strict access parity found "
                f"{len(invalid_organization_depths):,} non-Global read grants on "
                f"OrganizationOwned tables. No policies were applied."
            )

        extracted_role_ids = {
            role.id for role in self.environment.security_roles or [] if role.id
        }
        assigned_role_ids = {
            role_id
            for assignments in (
                self.environment.user_role_assignments or {},
                self.environment.team_role_assignments or {},
            )
            for role_ids in assignments.values()
            for role_id in role_ids or []
        }
        missing_assigned_roles = assigned_role_ids.difference(extracted_role_ids)
        if missing_assigned_roles:
            raise ValueError(
                f"Dataverse strict access parity found "
                f"{len(missing_assigned_roles):,} assigned role references missing "
                f"from the role extraction. No policies were applied."
            )

        role_by_id = {
            role.id: role for role in self.environment.security_roles or [] if role.id
        }
        assignment_context_errors = 0
        for principal_id, principal_type, role_id in source_role_assignments:
            principal = (
                self.environment.lookup_user_by_id(principal_id)
                if principal_type == IamType.USER
                else self.environment.lookup_team_by_id(principal_id)
            )
            role = role_by_id.get(role_id)
            assignment_context_errors += int(
                not principal
                or not role
                or not principal.business_unit_id
                or not role.business_unit_id
                or principal.business_unit_id != role.business_unit_id
            )
        if assignment_context_errors:
            raise ValueError(
                f"Dataverse strict access parity found {assignment_context_errors:,} "
                f"invalid role assignment context records with a missing principal, "
                f"missing BU, or cross-BU role instance. No policies were applied."
            )

        self.__validate_business_unit_topology__()
        if poaa_count:
            raise ValueError(
                f"Dataverse strict access parity cannot translate {poaa_count:,} "
                f"POAA record-specific field read grants to OneLake's table-wide "
                f"CLS allowlists. No policies were applied."
            )
        if self.config.dataverse.poa_read_access_status != "verified_empty":
            raise ValueError(
                "Dataverse POA read-share coverage is unverified because the "
                "supported Web API has no bulk PrincipalObjectAccess query. Set "
                "dataverse.poa_read_access_status='verified_empty' only after an "
                "external POA review proves there are no relevant read shares. "
                "No policies were applied."
            )
        self._strict_security_coverage_validated = True

    def __validate_business_unit_topology__(self) -> None:
        business_units = self.environment.business_units or []
        business_unit_ids = [unit.id for unit in business_units if unit.id]
        known_ids = set(business_unit_ids)
        invalid = len(business_unit_ids) != len(business_units) or len(
            known_ids
        ) != len(business_unit_ids)

        parent_by_id = {
            unit.id: unit.parent_business_unit_id for unit in business_units if unit.id
        }
        invalid = invalid or any(
            parent_id and parent_id not in known_ids
            for parent_id in parent_by_id.values()
        )

        for business_unit_id in known_ids:
            path = set()
            current_id = business_unit_id
            while current_id:
                if current_id in path:
                    invalid = True
                    break
                path.add(current_id)
                current_id = parent_by_id.get(current_id)

        referenced_business_unit_ids = {
            item.business_unit_id
            for collection in (
                self.environment.users or [],
                self.environment.teams or [],
                self.environment.security_roles or [],
            )
            for item in collection
            if item.business_unit_id
        }
        invalid = invalid or bool(referenced_business_unit_ids.difference(known_ids))

        role_by_id = {
            role.id: role for role in self.environment.security_roles or [] if role.id
        }
        invalid = invalid or any(
            not role_by_id.get(privilege.role_id)
            or not role_by_id[privilege.role_id].business_unit_id
            or role_by_id[privilege.role_id].business_unit_id not in known_ids
            for privilege in self.environment.role_privileges or []
            if privilege.can_read
            and (privilege.depth or "Unknown").title() in {"Local", "Deep"}
        )

        if invalid:
            raise ValueError(
                "Dataverse business unit hierarchy is incomplete, cyclic, or "
                "inconsistent with extracted users, teams, roles, or scoped read "
                "privileges. No policies were applied."
            )

    def __constraint_composition_conflicts__(
        self, role_map: Dict[Tuple[str, str], Dict], column_security: bool
    ) -> List[Tuple[str, str, Dict[str, set]]]:
        if not column_security:
            return []

        access_by_user_table: Dict[Tuple[str, str], Dict[str, set]] = {}
        for role_key, data in role_map.items():
            depth_by_table: Dict[str, str] = {}
            for permission in data["perms"]:
                table_name = permission.table_name
                candidate_depth = (permission.depth or "Unknown").title()
                current_depth = depth_by_table.get(table_name)
                if current_depth is None or self.__get_depth_rank__(
                    candidate_depth
                ) >= self.__get_depth_rank__(current_depth):
                    depth_by_table[table_name] = candidate_depth

            cls_tables = {
                constraint.table_name
                for constraint in self.__get_column_constraints_for_principals__(
                    data["principals"],
                    data["tables"],
                    self.config.source.name,
                    self.__get_schema_name__(),
                )
            }
            for user_id in self.__get_effective_user_ids__(data["principals"]):
                for table_name in cls_tables:
                    entry = access_by_user_table.setdefault(
                        (user_id, table_name),
                        {"roles": set(), "rls_roles": set()},
                    )
                    entry["roles"].add(role_key)
                    if depth_by_table.get(table_name, "Unknown") != "Global":
                        entry["rls_roles"].add(role_key)

        return [
            (user_id, table_name, entry)
            for (user_id, table_name), entry in access_by_user_table.items()
            if len(entry["roles"]) > 1 and entry["rls_roles"]
        ]

    def __role_capacity_requirement__(
        self, data: Dict, column_security: bool
    ) -> Tuple[int, str]:
        split_for_basic = self.__role_has_basic_effective_depth__(data["perms"])
        split_for_ownership = bool(
            not split_for_basic and self.__role_requires_ownership_split__(data)
        )
        split_for_cls = bool(
            not split_for_basic
            and not split_for_ownership
            and column_security
            and self.__principals_have_divergent_cls__(
                data["principals"], data["tables"]
            )
        )
        data["split_for_basic"] = split_for_basic
        data["split_for_ownership"] = split_for_ownership
        data["split_for_cls"] = split_for_cls

        if split_for_basic or split_for_ownership:
            role_count = 0
            seen_identity_keys: Set[str] = set()
            for user_id in sorted(self.__get_effective_user_ids__(data["principals"])):
                user = self.environment.lookup_user_by_id(user_id)
                permission_object = self.__permission_object_for_user__(user)
                if not permission_object:
                    continue
                identity_key = self.__permission_object_identity_key__(
                    permission_object
                )
                if identity_key in seen_identity_keys:
                    continue
                seen_identity_keys.add(identity_key)
                role_count += self.__row_and_permission_role_factor__(
                    data,
                    ownership_overrides=self.__ownership_overrides_for_user__(
                        data, user_id
                    ),
                )
            reason = "Basic depth" if split_for_basic else "ownership overlays"
        elif split_for_cls:
            role_count = self.__count_cls_role_chunks__(
                data["principals"], data["tables"]
            ) * self.__row_and_permission_role_factor__(data)
            reason = "divergent CLS groups"
        else:
            member_count = self.__count_resolvable_role_members__(data["principals"])
            member_role_count = (
                member_count + self.FABRIC_ROLE_MEMBER_MAX - 1
            ) // self.FABRIC_ROLE_MEMBER_MAX
            role_count = member_role_count * self.__row_and_permission_role_factor__(
                data
            )
            reason = "shared member chunks"

        return role_count, reason

    def __row_and_permission_role_factor__(
        self,
        data: Dict,
        ownership_overrides: Dict[str, Set[str]] = None,
    ) -> int:
        row_constraints = self.__get_row_constraints_for_role__(
            data["perms"],
            self.config.source.name,
            self.__get_schema_name__(),
            ownership_overrides=ownership_overrides,
        )
        row_counts_by_table = Counter(
            constraint.table_name for constraint in row_constraints
        )
        chunked_tables = {
            table_name for table_name, count in row_counts_by_table.items() if count > 1
        }
        base_table_count = len(set(data["tables"]).difference(chunked_tables))
        base_permission_chunks = (
            (base_table_count + self.FABRIC_ROLE_PERMISSION_MAX - 1)
            // self.FABRIC_ROLE_PERMISSION_MAX
            if base_table_count
            else 0
        )
        row_chunks = sum(
            row_counts_by_table[table_name] for table_name in chunked_tables
        )
        return max(1, base_permission_chunks + row_chunks)

    @staticmethod
    def __permission_role_id__(
        permission: DataverseTablePermission,
    ) -> str | None:
        role_id = permission.role_id
        if not role_id:
            return None
        normalized_role_id = role_id.strip()
        return normalized_role_id or None

    def __partial_role_report_id__(self, role_key: Tuple[str, str], data: Dict) -> str:
        role_id = next(
            (
                normalized_role_id
                for permission in data["perms"]
                if (normalized_role_id := self.__permission_role_id__(permission))
            ),
            None,
        )
        if role_id:
            return role_id

        role_label = str(role_key[0] or data.get("role_name") or "UnknownRole")
        role_label = role_label.strip() or "UnknownRole"
        business_unit_id = str(
            role_key[1] or data.get("role_business_unit_id") or "no-business-unit"
        )
        return f"missing-role-id:{role_label}:{business_unit_id}"

    def __partial_identity_failure_reason__(
        self, user_id: str, team_member: bool = False
    ) -> str | None:
        user = self.environment.lookup_user_by_id(user_id)
        if not user:
            return (
                "missing_team_member_snapshot"
                if team_member
                else "missing_assigned_user_snapshot"
            )
        unresolved_application_ids = set(
            getattr(self, "_partial_unresolved_application_ids", set()) or set()
        )
        if user.application_id and user.application_id in unresolved_application_ids:
            return "unresolved_graph_service_principal"
        if not self.__permission_object_for_user__(user):
            return "ineligible_user"
        return None

    def __filter_partial_identity_failures__(
        self, role_map: Dict[Tuple[str, str], Dict]
    ) -> List[Dict]:
        excluded_user_ids: Set[str] = set()
        skipped_assignments: List[Dict] = []

        for role_key, data in sorted(role_map.items(), key=lambda item: str(item[0])):
            role_id = self.__partial_role_report_id__(role_key, data)
            filtered_principals = set()
            for principal_id, principal_type in sorted(
                data["principals"],
                key=lambda item: (str(item[1]), str(item[0])),
            ):
                if principal_type == IamType.USER:
                    reason = self.__partial_identity_failure_reason__(principal_id)
                    if reason:
                        excluded_user_ids.add(principal_id)
                        skipped_assignments.append(
                            {
                                "assignment_context": "direct_role",
                                "principal_id": principal_id,
                                "principal_type": str(principal_type),
                                "reason": reason,
                                "role_id": role_id,
                                "role_name": data["role_name"],
                            }
                        )
                        continue

                filtered_principals.add((principal_id, principal_type))
                if principal_type != IamType.GROUP:
                    continue
                team = self.environment.lookup_team_by_id(principal_id)
                if not team or team.team_type not in {0, 1}:
                    continue
                for member_id in sorted(set(team.member_ids or [])):
                    reason = self.__partial_identity_failure_reason__(
                        member_id, team_member=True
                    )
                    if not reason:
                        continue
                    excluded_user_ids.add(member_id)
                    skipped_assignments.append(
                        {
                            "assignment_context": "team_member",
                            "principal_id": principal_id,
                            "principal_type": str(principal_type),
                            "reason": reason,
                            "role_id": role_id,
                            "role_name": data["role_name"],
                            "team_member_id": member_id,
                            "team_type": team.team_type,
                        }
                    )

            data["principals"] = filtered_principals

        self._partial_excluded_user_ids = excluded_user_ids
        return sorted(
            skipped_assignments,
            key=lambda item: (
                item["role_id"],
                item["role_name"] or "",
                item["assignment_context"],
                item["principal_type"],
                item["principal_id"],
                item.get("team_member_id", ""),
                item["reason"],
            ),
        )

    def __is_partial_excluded_user_id__(self, user_id: str) -> bool:
        config = getattr(self, "config", None)
        dataverse = getattr(config, "dataverse", None)
        return bool(
            getattr(dataverse, "partial_sync", False)
            and user_id in (getattr(self, "_partial_excluded_user_ids", set()) or set())
        )

    def __is_partial_absent_user_snapshot__(self, user_id: str) -> bool:
        return bool(
            self.__is_partial_excluded_user_id__(user_id)
            and self.environment.lookup_user_by_id(user_id) is None
        )

    def __quarantine_partial_role_map__(
        self, role_map: Dict[Tuple[str, str], Dict], column_security: bool
    ) -> Dict[Tuple[str, str], Dict]:
        source_principals_by_role = {
            role_key: set(data["principals"]) for role_key, data in role_map.items()
        }
        skipped_principal_assignments = self.__filter_partial_identity_failures__(
            role_map
        )

        quarantined: Dict[Tuple[str, str], Dict[str, set]] = {}

        def quarantine(
            role_key: Tuple[str, str], reason: str, table_name: str = None
        ) -> None:
            entry = quarantined.setdefault(
                role_key, {"reasons": set(), "tables": set()}
            )
            entry["reasons"].add(reason)
            if table_name:
                entry["tables"].add(table_name)

        for role_key, data in role_map.items():
            if self.__count_resolvable_role_members__(data["principals"]) == 0:
                quarantine(role_key, "no_resolvable_members")

        role_by_id = {
            role.id: role for role in self.environment.security_roles or [] if role.id
        }

        def normalized_role_identity(role_key: Tuple[str, str], data: Dict) -> str:
            return self.__partial_role_report_id__(role_key, data)

        role_keys_by_id: Dict[str, Set[Tuple[str, str]]] = {}
        for role_key, data in role_map.items():
            role_id = normalized_role_identity(role_key, data)
            role_keys_by_id.setdefault(role_id, set()).add(role_key)

        def quarantine_role_id(
            role_id: str, reason: str, table_name: str = None
        ) -> None:
            for role_key in role_keys_by_id.get(role_id, set()):
                quarantine(role_key, reason, table_name)

        environment_limitations: List[Dict] = []

        def limitation(code: str, count: int = None) -> None:
            item: Dict = {"code": code}
            if count is not None:
                item["count"] = count
            environment_limitations.append(item)

        poaa_count = sum(
            bool(access.read_access)
            for access in self.environment.principal_object_attribute_accesses or []
        )
        if poaa_count:
            limitation("poaa_field_shares_not_mapped", poaa_count)
        if self.config.dataverse.poa_read_access_status != "verified_empty":
            limitation("poa_record_shares_unverified")
        if self.environment.hierarchy_security_enabled:
            limitation("hierarchy_security_not_mapped")
        masking_rules = self.environment.attribute_masking_rules
        masking_tables = {
            rule.entity_name.casefold()
            for rule in masking_rules or []
            if rule.entity_name
        }
        masking_unverified = (
            masking_rules is None
            and self.config.dataverse.column_masking_status != "verified_absent"
        )
        if masking_unverified:
            limitation("column_masking_unverified")
        elif masking_rules:
            limitation("column_masking_not_mapped", len(masking_rules))

        group_fsp_count = sum(
            team.team_type in {2, 3}
            and any(
                team.id in (profile.team_ids or [])
                for profile in self.environment.field_security_profiles or []
            )
            for team in self.environment.teams or []
        )
        if group_fsp_count:
            limitation("dynamic_group_field_security_not_mapped", group_fsp_count)

        group_teams_by_id = {
            team.id: team
            for team in self.environment.teams or []
            if team.id and team.team_type in {2, 3}
        }
        dynamic_group_fsp_tables = {
            permission.entity_name
            for profile in self.environment.field_security_profiles or []
            if any(team_id in group_teams_by_id for team_id in profile.team_ids or [])
            for permission in profile.permissions or []
            if permission.can_read == 4 and permission.entity_name
        }

        for privilege in self.environment.role_privileges or []:
            if not privilege.can_read:
                continue
            if privilege.record_filter_id:
                quarantine_role_id(
                    privilege.role_id,
                    "record_filter_not_supported",
                    privilege.entity_name,
                )
            if (
                privilege.entity_name
                and (privilege.depth or "Unknown").title()
                not in DataverseAPIClient.DEPTH_RANK
            ):
                quarantine_role_id(
                    privilege.role_id,
                    "unknown_privilege_depth",
                    privilege.entity_name,
                )

        for team in self.environment.teams or []:
            assigned_role_ids = (self.environment.team_role_assignments or {}).get(
                team.id, []
            )
            if team.team_type in {2, 3}:
                for role_id in assigned_role_ids:
                    quarantine_role_id(role_id, "dynamic_group_team_role")

        for role_key, data in role_map.items():
            has_group_principal = any(
                principal_type == IamType.GROUP
                for _, principal_type in source_principals_by_role[role_key]
            )
            missing_group_role_id = any(
                permission.principal_type == IamType.GROUP
                and self.__permission_role_id__(permission) is None
                for permission in data["perms"]
            )
            if has_group_principal:
                role = role_by_id.get(normalized_role_identity(role_key, data))
                if missing_group_role_id or not role or role.is_inherited not in {0, 1}:
                    quarantine(role_key, "unknown_team_role_inheritance")

            missing_role_id = any(
                self.__permission_role_id__(permission) is None
                for permission in data["perms"]
            )
            if missing_role_id and not missing_group_role_id:
                quarantine(role_key, "invalid_assignment_context")

        unresolved_application_ids = set(
            getattr(self, "_partial_unresolved_application_ids", set()) or set()
        )

        missing_assigned_role_count = 0
        for assignments, principal_type, principal_lookup in (
            (
                self.environment.user_role_assignments or {},
                IamType.USER,
                self.environment.lookup_user_by_id,
            ),
            (
                self.environment.team_role_assignments or {},
                IamType.GROUP,
                self.environment.lookup_team_by_id,
            ),
        ):
            for principal_id, role_ids in assignments.items():
                principal = principal_lookup(principal_id)
                for role_id in role_ids or []:
                    role = role_by_id.get(role_id)
                    if not role:
                        missing_assigned_role_count += 1
                        continue
                    if principal_type == IamType.USER and (
                        self.__is_partial_absent_user_snapshot__(principal_id)
                    ):
                        continue
                    if (
                        not principal
                        or not principal.business_unit_id
                        or not role.business_unit_id
                        or principal.business_unit_id != role.business_unit_id
                    ):
                        quarantine_role_id(role_id, "invalid_assignment_context")
        if missing_assigned_role_count:
            limitation("missing_assigned_role_references", missing_assigned_role_count)

        for role_key, data in role_map.items():
            role_business_unit_id = data.get("role_business_unit_id")
            for principal_id, principal_type in source_principals_by_role[role_key]:
                if principal_type == IamType.USER:
                    if self.__is_partial_absent_user_snapshot__(principal_id):
                        continue
                    principal = self.environment.lookup_user_by_id(principal_id)
                elif principal_type == IamType.GROUP:
                    principal = self.environment.lookup_team_by_id(principal_id)
                    if principal and principal.team_type in {2, 3}:
                        quarantine(role_key, "dynamic_group_team_role")
                else:
                    continue

                if (
                    not principal
                    or not principal.business_unit_id
                    or not role_business_unit_id
                    or principal.business_unit_id != role_business_unit_id
                ):
                    quarantine(role_key, "invalid_assignment_context")

        metadata_by_table = {
            metadata.logical_name.lower(): metadata
            for metadata in self.environment.table_metadata or []
            if metadata.logical_name
        }
        fsp_columns_by_table: Dict[str, Set[str]] = {}
        for profile in self.environment.field_security_profiles or []:
            for permission in profile.permissions or []:
                if permission.entity_name and permission.attribute_logical_name:
                    fsp_columns_by_table.setdefault(
                        permission.entity_name.lower(), set()
                    ).add(permission.attribute_logical_name.lower())
        try:
            self.__validate_business_unit_topology__()
            invalid_business_unit_topology = False
        except ValueError:
            invalid_business_unit_topology = True
            limitation("invalid_business_unit_topology")

        for role_key, data in role_map.items():
            for table_name in set(data["tables"]).intersection(
                dynamic_group_fsp_tables
            ):
                quarantine(
                    role_key,
                    "dynamic_group_field_security",
                    table_name,
                )
            for permission in data["perms"]:
                table_name = (permission.table_name or "").lower()
                depth = (permission.depth or "Unknown").title()
                metadata = metadata_by_table.get(table_name)
                if depth not in DataverseAPIClient.DEPTH_RANK:
                    quarantine(role_key, "unknown_privilege_depth", table_name)
                if not metadata or not metadata.ownership_type:
                    quarantine(role_key, "missing_ownership_metadata", table_name)
                elif (
                    metadata.ownership_type
                    not in {
                        "UserOwned",
                        "OrganizationOwned",
                        "BusinessOwned",
                    }
                    and depth != "Global"
                    or (metadata.ownership_type == "BusinessOwned" and depth == "Basic")
                ):
                    quarantine(role_key, "unsupported_table_ownership", table_name)
                elif (
                    metadata.ownership_type == "OrganizationOwned" and depth != "Global"
                ):
                    quarantine(role_key, "scoped_organization_owned_grant", table_name)
                if table_name.casefold() in masking_tables or (
                    metadata and metadata.has_secured_columns and masking_unverified
                ):
                    quarantine(
                        role_key,
                        "column_masking_unverified"
                        if masking_unverified
                        else "column_masking_not_supported",
                        table_name,
                    )
                if metadata and metadata.has_secured_columns and not metadata.columns:
                    quarantine(role_key, "incomplete_cls_metadata", table_name)
                fsp_columns = fsp_columns_by_table.get(table_name, set())
                if metadata:
                    metadata_secured_columns = {
                        column.logical_name.lower()
                        for column in metadata.columns or []
                        if column.logical_name and column.is_secured
                    }
                    if bool(metadata.has_secured_columns) != bool(
                        metadata_secured_columns
                    ) or not fsp_columns.issubset(metadata_secured_columns):
                        quarantine(role_key, "inconsistent_cls_metadata", table_name)
                if depth in {"Local", "Deep"} and not data.get("role_business_unit_id"):
                    quarantine(role_key, "missing_role_business_unit", table_name)
                if invalid_business_unit_topology and depth == "Deep":
                    quarantine(
                        role_key, "invalid_deep_business_unit_topology", table_name
                    )

            for principal_id, principal_type in data["principals"]:
                if principal_type == IamType.USER:
                    continue
                if principal_type != IamType.GROUP:
                    quarantine(role_key, "unsupported_principal_type")
                    continue
                team = self.environment.lookup_team_by_id(principal_id)
                if not team:
                    quarantine(role_key, "unresolvable_team_membership")
                    continue
                if team.team_type in {0, 1}:
                    continue
                if not team.member_ids:
                    quarantine(role_key, "unresolvable_team_membership")
                    continue
                if any(
                    not self.__permission_object_for_user__(
                        self.environment.lookup_user_by_id(member_id)
                    )
                    for member_id in team.member_ids
                ):
                    quarantine(role_key, "unresolvable_team_member")

            if column_security:
                for table_name in self.__empty_cls_allowlist_tables__(data):
                    quarantine(role_key, "no_readable_columns", table_name)

        for role_key, data in role_map.items():
            if role_key in quarantined:
                continue
            for table_name in self.__dynamic_owner_team_ids_by_override_table__(data):
                quarantine(
                    role_key,
                    "dynamic_group_team_ownership",
                    table_name,
                )

        candidates = {
            role_key: data
            for role_key, data in role_map.items()
            if role_key not in quarantined
        }
        for role_key, data in candidates.items():
            try:
                self.__role_capacity_requirement__(data, column_security)
            except _UnrepresentableRowConstraintError as error:
                quarantine(
                    role_key,
                    "unrepresentable_row_constraint",
                    error.table_name,
                )

        candidates = {
            role_key: data
            for role_key, data in role_map.items()
            if role_key not in quarantined
        }
        constraint_composition_conflicts = []

        def conflict_role_details(
            role_data: Dict[Tuple[str, str], Dict],
            role_keys: Set[Tuple[str, str]],
            table_name: str,
        ) -> List[Dict]:
            return [
                {
                    "role_id": self.__partial_role_report_id__(
                        role_key, role_data[role_key]
                    ),
                    "role_name": role_data[role_key]["role_name"],
                    "depth": self.__effective_depths_by_table__(
                        role_data[role_key]["perms"]
                    ).get(table_name, "Unknown"),
                }
                for role_key in sorted(role_keys, key=str)
            ]

        role_limit = self.config.dataverse.onelake_role_limit
        if not role_limit or role_limit < 1:
            raise ValueError("dataverse.onelake_role_limit must be a positive integer.")

        for data in role_map.values():
            data.pop("partial_suppressed_tables_by_user", None)

        selected = dict(candidates)
        selected_role_count = 0
        final_global_conflicts = []
        while True:
            source_conflicts = self.__constraint_composition_conflicts__(
                selected, column_security
            )
            scoped_conflicts = [
                (user_id, table_name, conflict)
                for user_id, table_name, conflict in source_conflicts
                if not conflict["roles"].difference(conflict["rls_roles"])
            ]
            if scoped_conflicts:
                for user_id, table_name, conflict in scoped_conflicts:
                    constraint_composition_conflicts.append(
                        {
                            "principal_id": user_id,
                            "table_name": table_name,
                            "resolution": "quarantined",
                            "roles": conflict_role_details(
                                selected, conflict["roles"], table_name
                            ),
                        }
                    )
                    for role_key in conflict["roles"]:
                        quarantine(
                            role_key,
                            "unsupported_multi_role_rls_cls",
                            table_name,
                        )
                selected = {
                    role_key: data
                    for role_key, data in selected.items()
                    if role_key not in quarantined
                }
                continue

            suppression_plan: Dict[Tuple[str, str], Dict[str, Set[str]]] = {}
            global_conflicts = []
            for user_id, table_name, conflict in source_conflicts:
                global_role_keys = conflict["roles"].difference(conflict["rls_roles"])
                global_conflicts.append(
                    (user_id, table_name, conflict, global_role_keys)
                )
                for role_key in conflict["rls_roles"]:
                    suppression_plan.setdefault(role_key, {}).setdefault(
                        user_id, set()
                    ).add(table_name)

            for data in role_map.values():
                data.pop("partial_suppressed_tables_by_user", None)
            for role_key, suppressions_by_user in suppression_plan.items():
                selected[role_key]["partial_suppressed_tables_by_user"] = {
                    user_id: set(table_names)
                    for user_id, table_names in suppressions_by_user.items()
                }

            generated_policies: List[RolePolicy] = []
            generated_policy_role_keys: List[Tuple[str, str]] = []
            generated_role_counts: Dict[Tuple[str, str], int] = {}
            for role_key, data in selected.items():
                role_policies = self.__build_policies_for_role_data__(
                    data,
                    self.config.source.name,
                    self.__get_schema_name__(),
                    column_security,
                )
                generated_role_counts[role_key] = self.__projected_onelake_role_count__(
                    role_policies
                )
                generated_policies.extend(role_policies)
                generated_policy_role_keys.extend([role_key] * len(role_policies))

            generated_conflicts = self.__generated_constraint_composition_conflicts__(
                generated_policies
            )
            if generated_conflicts:
                for _, table_name, policy_indexes in generated_conflicts:
                    for role_key in {
                        generated_policy_role_keys[index] for index in policy_indexes
                    }:
                        quarantine(
                            role_key,
                            "unsupported_multi_role_rls_cls",
                            table_name,
                        )
                selected = {
                    role_key: data
                    for role_key, data in selected.items()
                    if role_key not in quarantined
                }
                continue

            selected_role_count = sum(generated_role_counts.values())
            if selected_role_count <= role_limit:
                final_global_conflicts = global_conflicts
                break

            role_key_to_remove = max(
                selected,
                key=lambda role_key: (
                    generated_role_counts[role_key],
                    (selected[role_key]["role_name"] or "").casefold(),
                    str(role_key),
                ),
            )
            quarantine(role_key_to_remove, "onelake_role_capacity")
            selected.pop(role_key_to_remove)

        redundant_scoped_grant_suppressions = []
        for user_id, table_name, conflict, global_role_keys in final_global_conflicts:
            if not global_role_keys:
                constraint_composition_conflicts.append(
                    {
                        "principal_id": user_id,
                        "table_name": table_name,
                        "resolution": "quarantined",
                        "roles": conflict_role_details(
                            selected, conflict["roles"], table_name
                        ),
                    }
                )
                continue

            dominant_roles = conflict_role_details(
                selected, global_role_keys, table_name
            )
            constraint_composition_conflicts.append(
                {
                    "principal_id": user_id,
                    "table_name": table_name,
                    "resolution": "suppressed_redundant_scoped_grants",
                    "roles": conflict_role_details(
                        selected, conflict["roles"], table_name
                    ),
                }
            )
            for role_key in sorted(conflict["rls_roles"], key=str):
                data = selected[role_key]
                data.setdefault("partial_suppressed_tables_by_user", {}).setdefault(
                    user_id, set()
                ).add(table_name)
                redundant_scoped_grant_suppressions.append(
                    {
                        "principal_id": user_id,
                        "table_name": table_name,
                        "suppressed_role": conflict_role_details(
                            selected, {role_key}, table_name
                        )[0],
                        "dominant_global_roles": dominant_roles,
                    }
                )

        skipped_roles = []
        for role_key, details in sorted(
            quarantined.items(), key=lambda item: str(item[0])
        ):
            data = role_map[role_key]
            role_id = self.__partial_role_report_id__(role_key, data)
            skipped_roles.append(
                {
                    "role_id": role_id,
                    "role_name": data["role_name"],
                    "business_unit_id": data["role_business_unit_id"],
                    "reasons": sorted(details["reasons"]),
                    "tables": sorted(details["tables"]),
                }
            )

        reason_counts = Counter(
            reason for details in quarantined.values() for reason in details["reasons"]
        )
        principal_reason_counts = Counter(
            assignment["reason"] for assignment in skipped_principal_assignments
        )
        self.partial_sync_report = {
            "enabled": True,
            "exact_access_parity": False,
            "source_role_count": len(role_map),
            "included_role_count": len(selected),
            "projected_onelake_role_count": selected_role_count,
            "skipped_role_count": len(skipped_roles),
            "reason_counts": dict(sorted(reason_counts.items())),
            "skipped_principal_assignment_count": len(skipped_principal_assignments),
            "principal_reason_counts": dict(sorted(principal_reason_counts.items())),
            "skipped_principal_assignments": skipped_principal_assignments,
            "suppressed_redundant_scoped_grant_count": len(
                redundant_scoped_grant_suppressions
            ),
            "suppressed_redundant_scoped_grants": sorted(
                redundant_scoped_grant_suppressions,
                key=lambda item: (
                    item["principal_id"],
                    item["table_name"],
                    item["suppressed_role"]["role_id"],
                ),
            ),
            "constraint_composition_conflicts": sorted(
                constraint_composition_conflicts,
                key=lambda item: (
                    item["principal_id"],
                    item["table_name"],
                    item["resolution"],
                ),
            ),
            "environment_limitations": sorted(
                environment_limitations, key=lambda item: item["code"]
            ),
            "graph_validation": {
                "application_ids_checked": getattr(
                    self, "_partial_checked_application_count", 0
                ),
                "unresolved_application_ids": len(unresolved_application_ids),
            },
            "skipped_roles": skipped_roles,
        }
        self.logger.warning(
            "Dataverse partial sync quarantined %d of %d source roles and "
            "skipped %d principal assignments. Exact access parity is not claimed.",
            len(skipped_roles),
            len(role_map),
            len(skipped_principal_assignments),
        )
        return selected

    def __apply_partial_table_suppressions__(
        self, data: Dict, policies: List[RolePolicy]
    ) -> List[RolePolicy]:
        suppressions_by_user = data.get("partial_suppressed_tables_by_user", {})
        if not self.config.dataverse.partial_sync or not suppressions_by_user:
            return policies

        suppressions_by_identity: Dict[str, Set[str]] = {}
        for user_id, table_names in suppressions_by_user.items():
            user = self.environment.lookup_user_by_id(user_id)
            permission_object = self.__permission_object_for_user__(user)
            if not permission_object:
                continue
            identity_key = self.__permission_object_identity_key__(permission_object)
            suppressions_by_identity.setdefault(identity_key, set()).update(table_names)

        adjusted_policies: List[RolePolicy] = []
        for policy in policies:
            policy_tables = {
                scope.table for scope in policy.permissionscopes or [] if scope.table
            }
            retained_members = []
            residual_members: Dict[frozenset, List[PermissionObject]] = {}
            for permission_object in policy.permissionobjects or []:
                identity_key = self.__permission_object_identity_key__(
                    permission_object
                )
                suppressed_tables = policy_tables.intersection(
                    suppressions_by_identity.get(identity_key, set())
                )
                if not suppressed_tables:
                    retained_members.append(permission_object)
                    continue
                remaining_tables = frozenset(
                    policy_tables.difference(suppressed_tables)
                )
                if remaining_tables:
                    residual_members.setdefault(remaining_tables, []).append(
                        permission_object
                    )

            if not residual_members:
                if retained_members:
                    if len(retained_members) == len(policy.permissionobjects or []):
                        adjusted_policies.append(policy)
                    else:
                        adjusted_policies.append(
                            RolePolicy(
                                name=policy.name,
                                permissionobjects=retained_members,
                                permissionscopes=policy.permissionscopes,
                                columnconstraints=policy.columnconstraints,
                                rowconstraints=policy.rowconstraints,
                            )
                        )
                continue

            if retained_members:
                adjusted_policies.append(
                    RolePolicy(
                        name=policy.name,
                        permissionobjects=retained_members,
                        permissionscopes=policy.permissionscopes,
                        columnconstraints=policy.columnconstraints,
                        rowconstraints=policy.rowconstraints,
                    )
                )

            for remaining_tables, permission_objects in sorted(
                residual_members.items(), key=lambda item: tuple(sorted(item[0]))
            ):
                filtered_scopes = [
                    scope
                    for scope in policy.permissionscopes or []
                    if scope.table in remaining_tables
                ]
                filtered_columns = [
                    constraint
                    for constraint in policy.columnconstraints or []
                    if constraint.table_name in remaining_tables
                ]
                filtered_rows = [
                    constraint
                    for constraint in policy.rowconstraints or []
                    if constraint.table_name in remaining_tables
                ]
                if not retained_members and len(residual_members) == 1:
                    residual_name = policy.name
                else:
                    residual_key = "|".join(
                        [
                            policy.name or "",
                            *sorted(remaining_tables),
                            *sorted(
                                self.__permission_object_identity_key__(item)
                                for item in permission_objects
                            ),
                        ]
                    )
                    residual_digest = hashlib.sha256(
                        residual_key.encode("utf-8")
                    ).hexdigest()[:12]
                    residual_name = f"{policy.name}_Residual{residual_digest}"
                adjusted_policies.append(
                    RolePolicy(
                        name=residual_name,
                        permissionobjects=permission_objects,
                        permissionscopes=filtered_scopes,
                        columnconstraints=filtered_columns or None,
                        rowconstraints=filtered_rows or None,
                    )
                )

        return self.__coalesce_equivalent_role_policies__(adjusted_policies)

    @staticmethod
    def __role_policy_entitlement_key__(
        policy: RolePolicy,
    ) -> Tuple[Tuple, Tuple, Tuple]:
        permission_scopes = tuple(
            sorted(
                (
                    str(scope.catalog or ""),
                    str(scope.catalog_schema or ""),
                    str(scope.table or ""),
                    str(scope.name or ""),
                    str(scope.state or ""),
                )
                for scope in policy.permissionscopes or []
            )
        )
        column_constraints = tuple(
            sorted(
                (
                    str(constraint.catalog_name or ""),
                    str(constraint.schema_name or ""),
                    str(constraint.table_name or ""),
                    tuple(
                        sorted(
                            str(action) for action in constraint.column_actions or []
                        )
                    ),
                    str(constraint.column_effect or ""),
                    tuple(sorted(constraint.column_names or [])),
                )
                for constraint in policy.columnconstraints or []
            )
        )
        row_constraints = tuple(
            sorted(
                (
                    str(constraint.catalog_name or ""),
                    str(constraint.schema_name or ""),
                    str(constraint.table_name or ""),
                    str(constraint.filter_condition or ""),
                )
                for constraint in policy.rowconstraints or []
            )
        )
        return permission_scopes, column_constraints, row_constraints

    def __coalesce_equivalent_role_policies__(
        self, policies: List[RolePolicy]
    ) -> List[RolePolicy]:
        policies_by_entitlement: Dict[Tuple[Tuple, Tuple, Tuple], List[RolePolicy]] = {}
        for policy in policies:
            entitlement_key = self.__role_policy_entitlement_key__(policy)
            policies_by_entitlement.setdefault(entitlement_key, []).append(policy)

        coalesced_policies: List[RolePolicy] = []
        for equivalent_policies in policies_by_entitlement.values():
            representative = equivalent_policies[0]
            permission_objects_by_identity: Dict[str, PermissionObject] = {}
            for policy in equivalent_policies:
                for permission_object in policy.permissionobjects or []:
                    identity_key = self.__permission_object_identity_key__(
                        permission_object
                    )
                    if not identity_key:
                        identity_key = permission_object.model_dump_json(
                            exclude_none=True
                        )
                    permission_objects_by_identity.setdefault(
                        identity_key, permission_object
                    )

            merged_policy = RolePolicy(
                name=representative.name,
                permissionobjects=list(permission_objects_by_identity.values()),
                permissionscopes=representative.permissionscopes,
                columnconstraints=representative.columnconstraints,
                rowconstraints=representative.rowconstraints,
            )
            coalesced_policies.extend(
                self.__split_policy_for_member_limit__(merged_policy)
            )

        if len(coalesced_policies) < len(policies):
            self.logger.info(
                "Coalesced %d post-suppression policies into %d exact "
                "entitlement roles.",
                len(policies),
                len(coalesced_policies),
            )
        return coalesced_policies

    def __build_policies_for_role_data__(
        self,
        data: Dict,
        catalog_name: str,
        schema_name: str,
        column_security: bool,
    ) -> List[RolePolicy]:
        if data["split_for_basic"] or data["split_for_ownership"]:
            policies = self.__build_per_principal_roles__(
                data, catalog_name, schema_name, column_security
            )
            return self.__apply_partial_table_suppressions__(data, policies)

        if data["split_for_cls"]:
            policies = self.__build_per_principal_cls_roles__(
                data, catalog_name, schema_name
            )
            return self.__apply_partial_table_suppressions__(data, policies)

        permission_objects = []
        seen_entra_ids = set()
        for principal_id, principal_type in data["principals"]:
            resolved = self.__resolve_shared_permission_object__(
                principal_id, principal_type
            )
            for permission_object in resolved:
                entra_key = (
                    permission_object.entra_object_id
                    or permission_object.id
                    or permission_object.app_id
                )
                if entra_key and entra_key not in seen_entra_ids:
                    seen_entra_ids.add(entra_key)
                    permission_objects.append(permission_object)

        if not permission_objects:
            return []

        permission_scopes = [
            PermissionScope(
                catalog=catalog_name,
                catalog_schema=schema_name,
                table=table_name,
                name=PermissionType.SELECT,
                state=PermissionState.GRANT,
            )
            for table_name in data["tables"]
        ]
        column_constraints = (
            self.__get_column_constraints_for_principals__(
                data["principals"], data["tables"], catalog_name, schema_name
            )
            if column_security
            else []
        )
        row_constraints = self.__get_row_constraints_for_role__(
            data["perms"], catalog_name, schema_name
        )

        role_name = data["role_name"]
        if data["role_business_unit_id"]:
            bu_label = self.__get_role_business_unit_label__(
                data["role_business_unit_id"]
            )
            role_name = f"{role_name}_{bu_label}"

        role_policy = RolePolicy(
            name=role_name,
            permissionobjects=permission_objects,
            permissionscopes=permission_scopes,
            columnconstraints=column_constraints if column_constraints else None,
            rowconstraints=row_constraints if row_constraints else None,
        )
        policies = [
            member_split_policy
            for row_split_policy in self.__split_policy_for_row_constraint_limit__(
                role_policy
            )
            for member_split_policy in self.__split_policy_for_member_limit__(
                row_split_policy
            )
        ]
        return self.__apply_partial_table_suppressions__(data, policies)

    def __projected_onelake_role_count__(self, policies: List[RolePolicy]) -> int:
        return sum(
            max(
                1,
                (
                    len(policy.permissionscopes or [])
                    + self.FABRIC_ROLE_PERMISSION_MAX
                    - 1
                )
                // self.FABRIC_ROLE_PERMISSION_MAX,
            )
            for policy in policies
        )

    def __build_role_based_export__(self) -> RolePolicyExport:
        """
        Build a role-based RolePolicyExport.
        Groups permissions by security role, where each role policy contains:
        - The principals (users/teams) assigned to that role
        - The table-level permission scopes (read)
        - Column constraints from field-level security
        - Row constraints from BU depth (when enabled)
        """
        if not (
            self.config.constraints
            and self.config.constraints.columns
            and self.config.constraints.columns.columnlevelsecurity
        ):
            self.logger.warning("Column level security is not enabled in the config.")
            column_security = False
        else:
            self.logger.info("Column level security is enabled in the config.")
            column_security = True

        if self.config.dataverse.partial_sync and not column_security:
            raise ValueError(
                "Dataverse partial sync requires column-level security so valid "
                "roles cannot expose secured columns."
            )

        self.logger.info(
            "Row level security is active and mandatory for the Dataverse connector."
        )

        catalog_name = self.config.source.name
        schema_name = self.__get_schema_name__()
        role_map = self.__build_role_map__()
        if self.config.dataverse.partial_sync:
            role_map = self.__quarantine_partial_role_map__(role_map, column_security)
        elif self.config.dataverse.strict_access_parity:
            if self.__strict_dynamic_owner_team_validation_enabled__() and any(
                self.__dynamic_owner_team_ids_by_override_table__(data)
                for data in role_map.values()
            ):
                raise ValueError(
                    "Dataverse strict access parity cannot prove dynamic Entra "
                    "group-team ownership membership used by generated ownership "
                    "overrides. No policies were applied."
                )
            self.__validate_role_cls_representability__(role_map, column_security)
        self.__validate_resolvable_principals__(role_map)
        if not self.config.dataverse.partial_sync:
            self.__preflight_role_capacity__(role_map, column_security)
        self.__preflight_constraint_composition__(role_map, column_security)

        policies = [
            policy
            for data in role_map.values()
            for policy in self.__build_policies_for_role_data__(
                data,
                catalog_name,
                schema_name,
                column_security,
            )
        ]

        if not policies:
            self.logger.warning(
                "No role-based policies generated from Dataverse permissions."
            )
            return RolePolicyExport(
                source=self.config.source,
                type=PolicyWeaverConnectorType.DATAVERSE,
                policies=[],
            )

        self.__validate_generated_constraint_composition__(policies)

        role_limit = self.config.dataverse.onelake_role_limit
        projected_fabric_role_count = self.__projected_onelake_role_count__(policies)
        if projected_fabric_role_count > role_limit:
            raise ValueError(
                f"Dataverse mapping requires {projected_fabric_role_count:,} "
                f"OneLake roles after member, permission, and row-filter chunking, "
                f"exceeding the configured dataverse.onelake_role_limit of "
                f"{role_limit:,}. No policies were applied."
            )
        if self.config.dataverse.partial_sync:
            self.partial_sync_report["projected_onelake_role_count"] = (
                projected_fabric_role_count
            )

        export = RolePolicyExport(
            source=self.config.source,
            type=PolicyWeaverConnectorType.DATAVERSE,
            policies=policies,
        )

        self.logger.info(
            f"Generated {len(policies)} role-based policies from Dataverse "
            f"({projected_fabric_role_count} projected OneLake roles)."
        )
        return export

    def __validate_resolvable_principals__(
        self, role_map: Dict[Tuple[str, str], Dict]
    ) -> None:
        if not self.config.dataverse.strict_access_parity:
            return

        strict_unresolved = set(
            getattr(self, "_strict_unresolved_application_ids", set()) or set()
        )

        def __app_only_unverified__(user) -> bool:
            application_id = getattr(user, "application_id", None)
            return bool(
                application_id
                and not getattr(user, "azure_ad_object_id", None)
                and application_id in strict_unresolved
            )

        unresolved: Set[str] = set()
        for data in role_map.values():
            for principal_id, principal_type in data["principals"]:
                if principal_type == IamType.USER:
                    user = self.environment.lookup_user_by_id(principal_id)
                    if not self.__permission_object_for_user__(
                        user
                    ) or __app_only_unverified__(user):
                        unresolved.add(f"user:{principal_id}")
                    continue

                if principal_type != IamType.GROUP:
                    unresolved.add(f"principal:{principal_id}")
                    continue
                team = self.environment.lookup_team_by_id(principal_id)
                if not team:
                    unresolved.add(f"team:{principal_id}")
                    continue
                member_ids = team.member_ids or []
                if team.team_type in {0, 1} and not member_ids:
                    unresolved.add(f"team:{principal_id}")
                    continue
                for member_id in member_ids:
                    user = self.environment.lookup_user_by_id(member_id)
                    if not self.__permission_object_for_user__(
                        user
                    ) or __app_only_unverified__(user):
                        unresolved.add(f"team-member:{member_id}")

        if unresolved:
            raise ValueError(
                f"Dataverse strict access parity found {len(unresolved):,} "
                f"assigned principals with unresolvable Entra identities. "
                f"No policies were applied."
            )

    def __empty_cls_allowlist_tables__(self, data: Dict) -> Set[str]:
        empty_tables: Set[str] = set()
        catalog_name = self.config.source.name
        schema_name = self.__get_schema_name__()
        for user_id in self.__get_effective_user_ids__(data["principals"]):
            constraints = self.__get_column_constraints_for_principals__(
                {(user_id, IamType.USER)},
                data["tables"],
                catalog_name,
                schema_name,
            )
            empty_tables.update(
                constraint.table_name
                for constraint in constraints
                if not constraint.column_names
            )
        return empty_tables

    def __validate_role_cls_representability__(
        self,
        role_map: Dict[Tuple[str, str], Dict],
        column_security: bool,
    ) -> None:
        if not column_security:
            return
        failures = [
            (data["role_name"], table_name)
            for data in role_map.values()
            for table_name in sorted(self.__empty_cls_allowlist_tables__(data))
        ]
        if not failures:
            return
        examples = ", ".join(
            f"{role_name}:{table_name}" for role_name, table_name in failures[:5]
        )
        raise ValueError(
            f"Dataverse strict access parity found {len(failures):,} role-table "
            f"grants with no readable columns ({examples}). An empty CLS allowlist "
            "cannot be serialized without weakening the source role. No policies "
            "were generated or applied."
        )

    def __preflight_constraint_composition__(
        self, role_map: Dict[Tuple[str, str], Dict], column_security: bool
    ) -> None:
        """Reject source role combinations OneLake cannot evaluate with RLS and CLS."""
        conflicts = self.__constraint_composition_conflicts__(role_map, column_security)
        if self.config.dataverse.partial_sync:
            conflicts = [
                (user_id, table_name, conflict)
                for user_id, table_name, conflict in conflicts
                if not all(
                    table_name
                    in role_map[role_key]
                    .get("partial_suppressed_tables_by_user", {})
                    .get(user_id, set())
                    for role_key in conflict["rls_roles"]
                )
            ]
        if not conflicts:
            return

        example_tables = sorted({table_name for _, table_name, _ in conflicts})[:5]
        raise ValueError(
            f"OneLake cannot evaluate the generated RLS/CLS composition for "
            f"{len(conflicts):,} user-table assignments. A CLS-secured table "
            f"cannot be reached through multiple OneLake roles when any role "
            f"has RLS. Example tables: {', '.join(example_tables)}. Consolidate "
            f"the Dataverse roles into effective per-user entitlement roles or "
            f"disable CLS only if the resulting secured-column exposure is "
            f"explicitly accepted. No policies were generated or applied."
        )

    def __generated_constraint_composition_conflicts__(
        self, policies: List[RolePolicy]
    ) -> List[Tuple[str, str, Set[int]]]:
        access_by_member_table: Dict[Tuple[str, str], Dict[str, set]] = {}
        for policy_index, policy in enumerate(policies):
            cls_tables = {
                constraint.table_name
                for constraint in policy.columnconstraints or []
                if constraint.column_names
            }
            rls_tables = {
                constraint.table_name
                for constraint in policy.rowconstraints or []
                if constraint.filter_condition
                and constraint.filter_condition.lower() not in {"false", "denyall"}
            }
            constrained_tables = cls_tables.union(rls_tables)
            if not constrained_tables:
                continue

            for permission_object in policy.permissionobjects or []:
                member_id = (
                    permission_object.entra_object_id
                    or permission_object.id
                    or permission_object.app_id
                )
                if not member_id:
                    continue
                for table_name in constrained_tables:
                    entry = access_by_member_table.setdefault(
                        (member_id, table_name),
                        {"policies": set(), "cls": set(), "rls": set()},
                    )
                    entry["policies"].add(policy_index)
                    if table_name in cls_tables:
                        entry["cls"].add(policy_index)
                    if table_name in rls_tables:
                        entry["rls"].add(policy_index)

        return [
            (member_id, table_name, entry["policies"])
            for key, entry in access_by_member_table.items()
            for member_id, table_name in [key]
            if len(entry["policies"]) > 1 and entry["cls"] and entry["rls"]
        ]

    def __validate_generated_constraint_composition__(
        self, policies: List[RolePolicy]
    ) -> None:
        conflicts = self.__generated_constraint_composition_conflicts__(policies)
        if conflicts:
            tables = sorted({table_name for _, table_name, _ in conflicts})[:5]
            raise ValueError(
                f"Generated policy chunking creates an unsupported OneLake "
                f"RLS/CLS multi-role combination for {len(conflicts):,} "
                f"member-table assignments. Example tables: {', '.join(tables)}. "
                f"No policies were applied."
            )

    def __preflight_role_capacity__(
        self, role_map: Dict[Tuple[str, str], Dict], column_security: bool
    ) -> None:
        """Fail before per-user expansion when exact mapping cannot fit OneLake."""
        role_limit = self.config.dataverse.onelake_role_limit
        if not role_limit or role_limit < 1:
            raise ValueError("dataverse.onelake_role_limit must be a positive integer.")

        minimum_role_count = 0
        contributors: List[Tuple[int, str, str]] = []
        for data in role_map.values():
            role_count, reason = self.__role_capacity_requirement__(
                data, column_security
            )

            minimum_role_count += role_count
            if role_count > 1:
                contributors.append((role_count, data["role_name"], reason))

        if minimum_role_count > role_limit:
            largest = ", ".join(
                f"{name} ({reason}: {count:,})"
                for count, name, reason in sorted(contributors, reverse=True)[:5]
            )
            contributor_message = f" Largest expansions: {largest}." if largest else ""
            raise ValueError(
                f"Exact Dataverse mapping requires at least "
                f"{minimum_role_count:,} OneLake roles, exceeding the configured "
                f"dataverse.onelake_role_limit of {role_limit:,}."
                f"{contributor_message} Basic-depth owner isolation and divergent "
                f"field-security profiles cannot be safely combined into shared "
                f"roles. No policies were generated or applied."
            )

        if minimum_role_count >= int(role_limit * 0.8):
            self.logger.warning(
                "Dataverse mapping requires at least %d of %d configured OneLake "
                "roles before row-filter chunking.",
                minimum_role_count,
                role_limit,
            )

    def __count_resolvable_users__(self, principals: set) -> int:
        identity_keys: Set[str] = set()
        for principal_id, principal_type in principals:
            if principal_type == IamType.USER:
                if self.__is_partial_excluded_user_id__(principal_id):
                    continue
                user = self.environment.lookup_user_by_id(principal_id)
                permission_object = self.__permission_object_for_user__(user)
                if permission_object:
                    identity_keys.add(
                        self.__permission_object_identity_key__(permission_object)
                    )
                continue

            if principal_type != IamType.GROUP:
                continue
            team = self.environment.lookup_team_by_id(principal_id)
            if not team:
                continue
            for member_id in team.member_ids or []:
                if self.__is_partial_excluded_user_id__(member_id):
                    continue
                user = self.environment.lookup_user_by_id(member_id)
                permission_object = self.__permission_object_for_user__(user)
                if permission_object:
                    identity_keys.add(
                        self.__permission_object_identity_key__(permission_object)
                    )

        return len(identity_keys)

    def __count_resolvable_role_members__(self, principals: set) -> int:
        identity_keys: Set[str] = set()
        for principal_id, principal_type in principals:
            if principal_type == IamType.USER:
                if self.__is_partial_excluded_user_id__(principal_id):
                    continue
                user = self.environment.lookup_user_by_id(principal_id)
                permission_object = self.__permission_object_for_user__(user)
                if permission_object:
                    identity_keys.add(
                        self.__permission_object_identity_key__(permission_object)
                    )
                continue

            if principal_type != IamType.GROUP:
                continue
            team = self.environment.lookup_team_by_id(principal_id)
            if not team:
                continue
            if team.team_type in {2, 3} and team.azure_ad_object_id:
                identity_keys.add(team.azure_ad_object_id)
                continue
            for member_id in team.member_ids or []:
                if self.__is_partial_excluded_user_id__(member_id):
                    continue
                user = self.environment.lookup_user_by_id(member_id)
                permission_object = self.__permission_object_for_user__(user)
                if permission_object:
                    identity_keys.add(
                        self.__permission_object_identity_key__(permission_object)
                    )

        return len(identity_keys)

    def __count_cls_role_chunks__(self, principals: set, tables: set) -> int:
        entra_ids_by_grants: Dict[frozenset, Set[str]] = {}
        for user_id, grants in self.__get_cls_grants_by_user__(
            principals, tables
        ).items():
            user = self.environment.lookup_user_by_id(user_id)
            permission_object = self.__permission_object_for_user__(user)
            if not permission_object:
                continue
            entra_ids_by_grants.setdefault(grants, set()).add(
                self.__permission_object_identity_key__(permission_object)
            )

        return sum(
            (len(entra_ids) + self.FABRIC_ROLE_MEMBER_MAX - 1)
            // self.FABRIC_ROLE_MEMBER_MAX
            for entra_ids in entra_ids_by_grants.values()
        )

    def __build_role_map__(self) -> Dict[Tuple[str, str], Dict]:
        """Build role policy inputs without expanding every principal/table pair."""
        readable_table_permissions = self.__readable_table_permissions_in_scope__()
        if self.__table_permissions_in_scope__():
            role_map: Dict[Tuple[str, str], Dict] = {}
            for permission in readable_table_permissions:
                role_name = permission.role_name or "UnknownRole"
                role_id = self.__permission_role_id__(permission)
                role_key = (
                    role_id or role_name,
                    permission.role_business_unit_id or "",
                )
                if role_key not in role_map:
                    role_map[role_key] = {
                        "role_name": role_name,
                        "role_business_unit_id": permission.role_business_unit_id,
                        "principals": set(),
                        "tables": set(),
                        "perms": [],
                    }
                role_map[role_key]["principals"].add(
                    (permission.principal_id, permission.principal_type)
                )
                role_map[role_key]["tables"].add(permission.table_name)
                role_map[role_key]["perms"].append(permission)
            return role_map

        configured_tables = self.__configured_table_scope__()
        role_by_id = {
            role.id: role for role in self.environment.security_roles or [] if role.id
        }
        entities_by_role: Dict[str, Dict[str, str]] = {}
        for privilege in self.environment.role_privileges or []:
            if (
                not privilege.role_id
                or not privilege.entity_name
                or not privilege.can_read
            ):
                continue
            entity_name = privilege.entity_name.lower()
            if configured_tables and entity_name not in configured_tables:
                continue

            candidate_depth = (privilege.depth or "Unknown").title()
            role_entities = entities_by_role.setdefault(privilege.role_id, {})
            current_depth = role_entities.get(entity_name)
            if current_depth is None or self.__get_depth_rank__(
                candidate_depth
            ) >= self.__get_depth_rank__(current_depth):
                role_entities[entity_name] = candidate_depth

        principals_by_role: Dict[str, Set[Tuple[str, IamType]]] = {}
        for user_id, role_ids in (self.environment.user_role_assignments or {}).items():
            for role_id in set(role_ids or []):
                principals_by_role.setdefault(role_id, set()).add(
                    (user_id, IamType.USER)
                )
        for team_id, role_ids in (self.environment.team_role_assignments or {}).items():
            for role_id in set(role_ids or []):
                principals_by_role.setdefault(role_id, set()).add(
                    (team_id, IamType.GROUP)
                )

        role_map = {}
        for role_id, entities in entities_by_role.items():
            principals = principals_by_role.get(role_id, set())
            if not principals:
                continue

            role = role_by_id.get(role_id)
            role_name = role.name if role and role.name else "UnknownRole"
            role_business_unit_id = role.business_unit_id if role else None
            role_key = (role_id, role_business_unit_id or "")
            compact_permissions = [
                DataverseTablePermission(
                    table_name=table_name,
                    has_read=True,
                    depth=depth,
                    role_id=role_id,
                    role_name=role_name,
                    role_business_unit_id=role_business_unit_id,
                )
                for table_name, depth in entities.items()
            ]
            role_map[role_key] = {
                "role_name": role_name,
                "role_business_unit_id": role_business_unit_id,
                "principals": principals,
                "tables": set(entities),
                "perms": compact_permissions,
            }

        self.logger.debug(
            "Built compact Dataverse role map with %d roles, %d role-table entries, "
            "and %d role-principal assignments.",
            len(role_map),
            sum(len(data["perms"]) for data in role_map.values()),
            sum(len(data["principals"]) for data in role_map.values()),
        )
        return role_map

    def __role_has_basic_effective_depth__(
        self, perms: List[DataverseTablePermission]
    ) -> bool:
        """Return True if any table in `perms` has Basic as its effective (highest-rank) depth."""
        table_to_perms: Dict[str, List[DataverseTablePermission]] = {}
        for perm in perms:
            table_to_perms.setdefault(perm.table_name, []).append(perm)
        for table_perms in table_to_perms.values():
            ranked = sorted(
                table_perms,
                key=lambda p: self.__get_depth_rank__(p.depth),
                reverse=True,
            )
            if (ranked[0].depth or "Unknown").title() == "Basic":
                return True
        return False

    def __effective_depths_by_table__(
        self, perms: List[DataverseTablePermission]
    ) -> Dict[str, str]:
        depths: Dict[str, str] = {}
        for permission in perms:
            candidate = (permission.depth or "Unknown").title()
            current = depths.get(permission.table_name)
            if current is None or self.__get_depth_rank__(
                candidate
            ) >= self.__get_depth_rank__(current):
                depths[permission.table_name] = candidate
        return depths

    def __get_role_inheritance_mode__(self, data: Dict) -> int:
        role_id = next(
            (permission.role_id for permission in data["perms"] if permission.role_id),
            None,
        )
        role = next(
            (
                candidate
                for candidate in self.environment.security_roles or []
                if candidate.id == role_id
            ),
            None,
        )
        if not role:
            return 0
        if role.is_inherited in {0, 1}:
            return role.is_inherited

        config = getattr(self, "config", None)
        dataverse = getattr(config, "dataverse", None)
        strict_access_parity = getattr(dataverse, "strict_access_parity", None)
        configured_fields = getattr(dataverse, "model_fields_set", None)
        if configured_fields is None:
            configured_fields = getattr(dataverse, "__fields_set__", None)
        # Legacy direct-builder callers can predate the parity flag. Public strict
        # mapping rejects unknown inheritance before ownership mapping starts.
        if (
            strict_access_parity is True
            and configured_fields is not None
            and "strict_access_parity" not in configured_fields
        ):
            strict_access_parity = False
        if (
            dataverse is not None
            and strict_access_parity is False
            and getattr(dataverse, "partial_sync", None) is False
        ):
            return 1
        return 0

    def __owner_team_ids_for_user__(self, user_id: str) -> Set[str]:
        return {
            team.id
            for team in self.environment.get_user_teams(user_id)
            if team.id and team.team_type in {0, 2, 3}
        }

    def __assigned_owner_team_ids_for_user__(
        self, data: Dict, user_id: str
    ) -> Set[str]:
        assigned_team_ids = {
            principal_id
            for principal_id, principal_type in data["principals"]
            if principal_type == IamType.GROUP
        }
        return {
            team.id
            for team in self.environment.get_user_teams(user_id)
            if team.id in assigned_team_ids and team.team_type in {0, 2, 3}
        }

    def __ownership_scope_for_user__(self, data: Dict, user_id: str) -> Set[str]:
        direct_assignment = (user_id, IamType.USER) in data["principals"]
        assigned_team_ids = self.__assigned_owner_team_ids_for_user__(data, user_id)
        inheritance_mode = self.__get_role_inheritance_mode__(data)

        ownership_scope = set(assigned_team_ids)
        if direct_assignment or (assigned_team_ids and inheritance_mode == 1):
            ownership_scope.add(user_id)
            ownership_scope.update(self.__owner_team_ids_for_user__(user_id))
        return ownership_scope

    def __user_needs_nonbasic_ownership_overlay__(
        self, data: Dict, user_id: str, depth: str
    ) -> bool:
        direct_assignment = (user_id, IamType.USER) in data["principals"]
        assigned_team_ids = self.__assigned_owner_team_ids_for_user__(data, user_id)
        if not direct_assignment and not (
            assigned_team_ids and self.__get_role_inheritance_mode__(data) == 1
        ):
            return False

        role_business_unit_id = data["role_business_unit_id"]
        if depth == "Local":
            covered_business_units = {role_business_unit_id}
        elif depth == "Deep":
            covered_business_units = set(
                self.__get_descendant_business_unit_ids__(role_business_unit_id)
            )
        else:
            return False

        user = self.environment.lookup_user_by_id(user_id)
        owner_business_unit_ids = {user.business_unit_id if user else None}
        for team_id in self.__owner_team_ids_for_user__(user_id):
            team = self.environment.lookup_team_by_id(team_id)
            owner_business_unit_ids.add(team.business_unit_id if team else None)
        return not owner_business_unit_ids.issubset(covered_business_units)

    def __supports_ownerid_overlays__(self, table_name: str) -> bool:
        metadata = self.environment.lookup_table_metadata(table_name)
        return metadata is None or metadata.ownership_type == "UserOwned"

    def __ownership_overrides_for_user__(
        self, data: Dict, user_id: str
    ) -> Dict[str, Set[str]]:
        ownership_scope = self.__ownership_scope_for_user__(data, user_id)
        overrides: Dict[str, Set[str]] = {}
        for table_name, depth in self.__effective_depths_by_table__(
            data["perms"]
        ).items():
            if not self.__supports_ownerid_overlays__(table_name):
                continue
            if depth == "Basic":
                overrides[table_name] = ownership_scope
            elif self.__user_needs_nonbasic_ownership_overlay__(data, user_id, depth):
                overrides[table_name] = ownership_scope
        return overrides

    def __dynamic_owner_team_ids_by_override_table__(
        self, data: Dict
    ) -> Dict[str, Set[str]]:
        dynamic_owner_team_ids = {
            team.id
            for team in self.environment.teams or []
            if team.id and team.team_type in {2, 3}
        }
        dependencies: Dict[str, Set[str]] = {}
        for user_id in sorted(self.__get_effective_user_ids__(data["principals"])):
            for table_name, owner_ids in self.__ownership_overrides_for_user__(
                data, user_id
            ).items():
                used_team_ids = owner_ids.intersection(dynamic_owner_team_ids)
                if used_team_ids:
                    dependencies.setdefault(table_name, set()).update(used_team_ids)
        return dependencies

    def __strict_dynamic_owner_team_validation_enabled__(self) -> bool:
        dataverse = self.config.dataverse
        if not dataverse.strict_access_parity:
            return False
        configured_fields = getattr(dataverse, "model_fields_set", None)
        if configured_fields is None:
            configured_fields = getattr(dataverse, "__fields_set__", None)
        return bool(
            getattr(self, "_strict_security_coverage_validated", False)
            or configured_fields is None
            or "strict_access_parity" in configured_fields
        )

    def __role_requires_ownership_split__(self, data: Dict) -> bool:
        user_owned_depths = {
            depth
            for table_name, depth in self.__effective_depths_by_table__(
                data["perms"]
            ).items()
            if depth in {"Local", "Deep"}
            and self.__supports_ownerid_overlays__(table_name)
        }
        if not user_owned_depths:
            return False
        return any(
            self.__user_needs_nonbasic_ownership_overlay__(data, user_id, depth)
            for user_id in self.__get_effective_user_ids__(data["principals"])
            for depth in user_owned_depths
        )

    def __build_per_principal_roles__(
        self,
        data: Dict,
        catalog_name: str,
        schema_name: str,
        column_security: bool,
    ) -> List[RolePolicy]:
        """
        Split a role into per-principal Fabric roles for Basic-depth owner isolation.

        Basic depth means "see rows you own".  Fabric Data Access Roles apply the
        same row filter to every member, so a shared role with
        ownerid in ('A','B') would let both A and B see each other's rows.
        This method creates one Fabric role per resolved identity so each user's
        filter contains only their own ownership scope (their Dataverse user ID
        plus the IDs of teams they belong to within this role).

        AAD-backed teams are expanded to individual members because the Fabric
        group-level filter cannot vary per member.
        """
        role_name = data["role_name"]
        bu_id = data["role_business_unit_id"]
        bu_label = self.__get_role_business_unit_label__(bu_id) if bu_id else ""

        # (ownership overrides by table, PermissionObject, CLS principals, user ID)
        per_user_entries: List[
            Tuple[Dict[str, Set[str]], PermissionObject, set, str]
        ] = []
        seen_identity_keys: Set[str] = set()

        for user_id in sorted(self.__get_effective_user_ids__(data["principals"])):
            resolved = self.__resolve_permission_object__(user_id, IamType.USER)
            for permission_object in resolved:
                entra_key = (
                    permission_object.entra_object_id
                    or permission_object.id
                    or permission_object.app_id
                )
                if not entra_key or entra_key in seen_identity_keys:
                    continue
                seen_identity_keys.add(entra_key)
                per_user_entries.append(
                    (
                        self.__ownership_overrides_for_user__(data, user_id),
                        permission_object,
                        {(user_id, IamType.USER)},
                        user_id,
                    )
                )

        if not per_user_entries:
            return []

        self.logger.info(
            f"Splitting role '{role_name}' into {len(per_user_entries)} per-principal "
            f"roles for Basic-depth owner isolation."
        )

        permission_scopes = [
            PermissionScope(
                catalog=catalog_name,
                catalog_schema=schema_name,
                table=table_name,
                name=PermissionType.SELECT,
                state=PermissionState.GRANT,
            )
            for table_name in data["tables"]
        ]

        policies: List[RolePolicy] = []
        for ownership_overrides, po, cls_principals, user_id in per_user_entries:
            column_constraints = (
                self.__get_column_constraints_for_principals__(
                    cls_principals, data["tables"], catalog_name, schema_name
                )
                if column_security
                else []
            )

            row_constraints = self.__get_row_constraints_for_role__(
                data["perms"],
                catalog_name,
                schema_name,
                ownership_overrides=ownership_overrides,
            )

            principal_digest = hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:12]
            principal_label = f"Principal{principal_digest}"
            if bu_label:
                name_ctx = f"{role_name}_{bu_label}_{principal_label}"
            else:
                name_ctx = f"{role_name}_{principal_label}"

            role_policy = RolePolicy(
                name=name_ctx,
                permissionobjects=[po],
                permissionscopes=permission_scopes,
                columnconstraints=column_constraints if column_constraints else None,
                rowconstraints=row_constraints if row_constraints else None,
            )
            policies.extend(self.__split_policy_for_row_constraint_limit__(role_policy))

        return policies

    def __principals_have_divergent_cls__(
        self, principals: set, tables: set = None
    ) -> bool:
        """Return True if the effective users behind `principals` have different
        field security profile coverage.

        GROUP principals are expanded to their member user IDs so that:
        - AAD-backed team IDs (which never appear in profile coverage) are
          resolved to the actual users who will receive the Fabric role.
        - A single AAD-backed group whose members have divergent FSPs is
          correctly detected (OneLake applies one role policy to all group
          members, so per-member CLS differences require splitting).
        """
        grants_by_user = self.__get_cls_grants_by_user__(principals, tables)
        if len(grants_by_user) < 2:
            return False
        return len(set(grants_by_user.values())) > 1

    def __get_effective_user_ids__(self, principals: set) -> Set[str]:
        effective_user_ids: Set[str] = set()
        for pid, ptype in principals:
            if ptype == IamType.USER:
                if not self.__is_partial_excluded_user_id__(pid):
                    effective_user_ids.add(pid)
            elif ptype == IamType.GROUP:
                team = self.environment.lookup_team_by_id(pid)
                if team and team.member_ids:
                    effective_user_ids.update(
                        member_id
                        for member_id in team.member_ids
                        if not self.__is_partial_excluded_user_id__(member_id)
                    )
        return effective_user_ids

    def __get_cls_grants_by_user__(
        self, principals: set, tables: set = None
    ) -> Dict[str, frozenset]:
        effective_user_ids = self.__get_effective_user_ids__(principals)
        unsecured_grants = {
            (table_name, column.logical_name)
            for table_name in tables or []
            if (metadata := self.environment.lookup_table_metadata(table_name))
            for column in metadata.columns or []
            if column.logical_name and not column.is_secured
        }
        grants_by_user: Dict[str, Set[Tuple[str, str]]] = {
            user_id: set(unsecured_grants) for user_id in effective_user_ids
        }
        for profile in self.environment.field_security_profiles:
            covered = set(profile.user_ids or [])
            for team_id in profile.team_ids or []:
                covered.add(team_id)
                team = self.environment.lookup_team_by_id(team_id)
                if team:
                    covered.update(team.member_ids or [])
            covered_users = effective_user_ids.intersection(covered)
            if not covered_users:
                continue

            grants = {
                (permission.entity_name, permission.attribute_logical_name)
                for permission in profile.permissions or []
                if permission.can_read == 4
                and permission.entity_name
                and permission.attribute_logical_name
                and (not tables or permission.entity_name in tables)
            }
            for user_id in covered_users:
                grants_by_user[user_id].update(grants)

        return {
            user_id: frozenset(grants) for user_id, grants in grants_by_user.items()
        }

    def __build_per_principal_cls_roles__(
        self,
        data: Dict,
        catalog_name: str,
        schema_name: str,
    ) -> List[RolePolicy]:
        """
        Split a non-Basic role into effective CLS entitlement groups.

        When principals in the same Dataverse role have different field security
        grants, a shared Fabric role would grant the union of all column
        permissions to every member. Users with identical effective grants can
        safely share a role; divergent grants remain isolated.
        """
        role_name = data["role_name"]
        bu_id = data["role_business_unit_id"]
        bu_label = self.__get_role_business_unit_label__(bu_id) if bu_id else ""

        # Row constraints are BU-depth-based and identical for all principals
        row_constraints = self.__get_row_constraints_for_role__(
            data["perms"], catalog_name, schema_name
        )

        permission_scopes = [
            PermissionScope(
                catalog=catalog_name,
                catalog_schema=schema_name,
                table=table_name,
                name=PermissionType.SELECT,
                state=PermissionState.GRANT,
            )
            for table_name in data["tables"]
        ]

        users_by_grants: Dict[frozenset, List] = {}
        seen_identity_keys: Set[str] = set()
        for user_id, grants in sorted(
            self.__get_cls_grants_by_user__(data["principals"], data["tables"]).items()
        ):
            user = self.environment.lookup_user_by_id(user_id)
            permission_object = self.__permission_object_for_user__(user)
            if not permission_object:
                continue
            identity_key = self.__permission_object_identity_key__(permission_object)
            if identity_key in seen_identity_keys:
                continue
            seen_identity_keys.add(identity_key)
            users_by_grants.setdefault(grants, []).append(user)

        policies: List[RolePolicy] = []
        for group_index, (_, users) in enumerate(
            sorted(users_by_grants.items(), key=lambda item: repr(sorted(item[0]))),
            start=1,
        ):
            representative_user = users[0]
            column_constraints = self.__get_column_constraints_for_principals__(
                {(representative_user.id, IamType.USER)},
                data["tables"],
                catalog_name,
                schema_name,
            )
            permission_objects = [
                permission_object
                for user in users
                if (permission_object := self.__permission_object_for_user__(user))
            ]
            name = (
                f"{role_name}_{bu_label}_CLS{group_index}"
                if bu_label
                else f"{role_name}_CLS{group_index}"
            )
            role_policy = RolePolicy(
                name=name,
                permissionobjects=permission_objects,
                permissionscopes=permission_scopes,
                columnconstraints=column_constraints if column_constraints else None,
                rowconstraints=row_constraints if row_constraints else None,
            )
            for row_split_policy in self.__split_policy_for_row_constraint_limit__(
                role_policy
            ):
                policies.extend(
                    self.__split_policy_for_member_limit__(row_split_policy)
                )

        if policies:
            self.logger.info(
                f"Splitting role '{role_name}' into {len(policies)} effective "
                f"column-entitlement roles for CLS isolation."
            )

        return policies

    def __get_role_business_unit_label__(self, role_business_unit_id: str) -> str:
        """Return a readable BU label for role naming, with stable fallback."""
        if not role_business_unit_id:
            return ""

        bu = self.environment.lookup_business_unit_by_id(role_business_unit_id)
        if bu and bu.name:
            return bu.name

        return role_business_unit_id[:8]

    def __get_depth_rank__(self, depth: str) -> int:
        rank_map = DataverseAPIClient.DEPTH_RANK
        return rank_map.get((depth or "Unknown").title(), 0)

    def __get_descendant_business_unit_ids__(self, business_unit_id: str) -> List[str]:
        if not business_unit_id:
            return []

        children_map: Dict[str, List[str]] = {}
        for bu in self.environment.business_units:
            if not bu.parent_business_unit_id:
                continue
            if bu.parent_business_unit_id not in children_map:
                children_map[bu.parent_business_unit_id] = []
            children_map[bu.parent_business_unit_id].append(bu.id)

        descendants: Set[str] = set()
        stack = [business_unit_id]
        while stack:
            current = stack.pop()
            if current in descendants:
                continue
            descendants.add(current)
            stack.extend(children_map.get(current, []))

        return list(descendants)

    def __target_table_name__(self, schema_name: str, table_name: str) -> str:
        config = getattr(self, "config", None)
        source_name = getattr(getattr(config, "source", None), "name", None)
        for mapped_item in getattr(config, "mapped_items", None) or []:
            if (
                mapped_item.catalog == source_name
                and mapped_item.catalog_schema == schema_name
                and mapped_item.table == table_name
            ):
                return mapped_item.mirror_table_name or table_name
        return table_name

    def __row_constraint_value_prefix__(self, schema_name: str, table_name: str) -> str:
        return f"SELECT * FROM {self.__target_table_name__(schema_name, table_name)} WHERE "

    def __row_filter_condition_budget__(self, schema_name: str, table_name: str) -> int:
        prefix = self.__row_constraint_value_prefix__(schema_name, table_name)
        config = getattr(self, "config", None)
        dataverse_config = getattr(config, "dataverse", None)
        chunk_length = (
            self.DEFAULT_ROW_CONSTRAINT_CHUNK_LENGTH
            if dataverse_config is None
            else dataverse_config.row_constraint_chunk_length
        )
        if not chunk_length or chunk_length < 1:
            raise ValueError(
                "dataverse.row_constraint_chunk_length must be a positive integer."
            )
        return chunk_length - len(prefix)

    def __build_in_filter_conditions__(
        self,
        column_name: str,
        values: Set[str],
        schema_name: str,
        table_name: str,
    ) -> List[str]:
        sorted_values = sorted(value for value in values if value)
        if not sorted_values:
            return ["false"]

        budget = self.__row_filter_condition_budget__(schema_name, table_name)
        condition_prefix = f"{column_name} in ("
        condition_suffix = ")"

        conditions: List[str] = []
        current_values: List[str] = []

        def _condition_length(items: List[str]) -> int:
            quoted_values = [f"'{item}'" for item in items]
            return (
                len(condition_prefix)
                + len(",".join(quoted_values))
                + len(condition_suffix)
            )

        def _condition(items: List[str]) -> str:
            escaped = "','".join(items)
            return f"{condition_prefix}'{escaped}'{condition_suffix}"

        for value in sorted_values:
            candidate_values = [*current_values, value]
            if _condition_length(candidate_values) <= budget:
                current_values = candidate_values
                continue

            if not current_values:
                raise _UnrepresentableRowConstraintError(schema_name, table_name)

            conditions.append(_condition(current_values))
            current_values = [value]

            if _condition_length(current_values) > budget:
                raise _UnrepresentableRowConstraintError(schema_name, table_name)

        if current_values:
            conditions.append(_condition(current_values))

        if len(conditions) > 1:
            chunk_length = self.config.dataverse.row_constraint_chunk_length
            self.logger.info(
                f"Split {schema_name}.{table_name} {column_name} row filter into "
                f"{len(conditions)} chunks using Policy Weaver's configured "
                f"{chunk_length}-character row-constraint chunk length."
            )

        return conditions

    def __build_row_filter_conditions__(
        self,
        effective_depth: str,
        role_business_unit_id: str,
        principal_ids: Set[str],
        schema_name: str,
        table_name: str,
        business_unit_column_name: str = "owningbusinessunit",
    ) -> List[str]:
        depth = (effective_depth or "Unknown").title()

        if depth == "Global":
            return []

        if depth == "Deep":
            descendants = set(
                self.__get_descendant_business_unit_ids__(role_business_unit_id)
            )
            return self.__build_in_filter_conditions__(
                column_name=business_unit_column_name,
                values=descendants,
                schema_name=schema_name,
                table_name=table_name,
            )

        if depth == "Local":
            if not role_business_unit_id:
                return ["false"]
            condition = f"{business_unit_column_name} = '{role_business_unit_id}'"
            if len(condition) > self.__row_filter_condition_budget__(
                schema_name, table_name
            ):
                raise _UnrepresentableRowConstraintError(schema_name, table_name)
            return [condition]

        if depth == "Basic":
            return self.__build_in_filter_conditions__(
                column_name="ownerid",
                values=principal_ids,
                schema_name=schema_name,
                table_name=table_name,
            )

        self.logger.warning(
            f"Unrecognized effective depth '{effective_depth}' for role BU "
            f"'{role_business_unit_id}'. Denying all rows (fail-closed)."
        )
        return ["false"]

    def __get_row_constraints_for_role__(
        self,
        perms: List[DataverseTablePermission],
        catalog_name: str,
        schema_name: str,
        ownership_overrides: Dict[str, Set[str]] = None,
    ) -> List[RowConstraint]:
        """
        Build BU-aware row constraints by mapping Dataverse read depth to Fabric row filters:
        - Global: no filter
        - Deep: owningbusinessunit in role BU and descendants
        - Local: owningbusinessunit equals role BU
        - Basic: ownerid equals one of the role principals

        Per-table ownership overrides isolate Basic access and add cumulative
        personal/team ownership to Local or Deep BU filters when required.
        """
        constraints: List[RowConstraint] = []
        table_to_perms: Dict[str, List[DataverseTablePermission]] = {}

        for perm in perms:
            table_to_perms.setdefault(perm.table_name, []).append(perm)

        for table_name, table_perms in table_to_perms.items():
            ranked = sorted(
                table_perms,
                key=lambda p: self.__get_depth_rank__(p.depth),
                reverse=True,
            )
            effective_depth = (ranked[0].depth or "Unknown").title()
            role_business_unit_id = ranked[0].role_business_unit_id
            metadata = self.environment.lookup_table_metadata(table_name)
            ownership_type = metadata.ownership_type if metadata else None

            table_ownership = (ownership_overrides or {}).get(table_name)
            if table_ownership is not None and effective_depth == "Basic":
                principal_ids = table_ownership
            else:
                principal_ids = {p.principal_id for p in table_perms if p.principal_id}

            if ownership_type == "BusinessOwned" and effective_depth == "Basic":
                filter_conditions = ["false"]
            else:
                filter_conditions = self.__build_row_filter_conditions__(
                    effective_depth=effective_depth,
                    role_business_unit_id=role_business_unit_id,
                    principal_ids=principal_ids,
                    schema_name=schema_name,
                    table_name=table_name,
                    business_unit_column_name=(
                        "businessunitid"
                        if ownership_type == "BusinessOwned"
                        else "owningbusinessunit"
                    ),
                )

            if (
                self.__supports_ownerid_overlays__(table_name)
                and table_ownership
                and effective_depth in {"Local", "Deep"}
            ):
                ownership_conditions = self.__build_in_filter_conditions__(
                    column_name="ownerid",
                    values=table_ownership,
                    schema_name=schema_name,
                    table_name=table_name,
                )
                if len(filter_conditions) == 1 and len(ownership_conditions) == 1:
                    combined = (
                        f"({filter_conditions[0]}) or ({ownership_conditions[0]})"
                    )
                    if len(combined) <= self.__row_filter_condition_budget__(
                        schema_name, table_name
                    ):
                        filter_conditions = [combined]
                    else:
                        filter_conditions.extend(ownership_conditions)
                else:
                    filter_conditions.extend(ownership_conditions)

            for filter_condition in filter_conditions:
                if not filter_condition:
                    continue

                constraints.append(
                    RowConstraint(
                        catalog_name=catalog_name,
                        schema_name=schema_name,
                        table_name=table_name,
                        filter_condition=filter_condition,
                    )
                )

        return constraints

    @staticmethod
    def __permission_scope_key__(scope: PermissionScope) -> Tuple[str, str, str]:
        return (scope.catalog, scope.catalog_schema, scope.table)

    @staticmethod
    def __column_constraint_key__(constraint: ColumnConstraint) -> Tuple[str, str, str]:
        return (
            constraint.catalog_name,
            constraint.schema_name,
            constraint.table_name,
        )

    @staticmethod
    def __row_constraint_key__(constraint: RowConstraint) -> Tuple[str, str, str]:
        return (
            constraint.catalog_name,
            constraint.schema_name,
            constraint.table_name,
        )

    def __split_policy_for_row_constraint_limit__(
        self, policy: RolePolicy
    ) -> List[RolePolicy]:
        if not policy.rowconstraints:
            return [policy]

        rows_by_table: Dict[Tuple[str, str, str], List[RowConstraint]] = {}
        for row_constraint in policy.rowconstraints:
            rows_by_table.setdefault(
                self.__row_constraint_key__(row_constraint), []
            ).append(row_constraint)

        chunked_table_keys = {
            table_key
            for table_key, row_constraints in rows_by_table.items()
            if len(row_constraints) > 1
        }
        if not chunked_table_keys:
            return [policy]

        permission_scopes = policy.permissionscopes or []
        column_constraints = policy.columnconstraints or []
        row_constraints = policy.rowconstraints or []

        split_policies: List[RolePolicy] = []
        base_scopes = [
            scope
            for scope in permission_scopes
            if self.__permission_scope_key__(scope) not in chunked_table_keys
        ]
        if base_scopes:
            base_rows = [
                constraint
                for constraint in row_constraints
                if self.__row_constraint_key__(constraint) not in chunked_table_keys
            ]
            base_columns = [
                constraint
                for constraint in column_constraints
                if self.__column_constraint_key__(constraint) not in chunked_table_keys
            ]
            split_policies.append(
                RolePolicy(
                    name=policy.name,
                    permissionobjects=policy.permissionobjects,
                    permissionscopes=base_scopes,
                    columnconstraints=base_columns if base_columns else None,
                    rowconstraints=base_rows if base_rows else None,
                )
            )

        for table_key in sorted(chunked_table_keys):
            table_scopes = [
                scope
                for scope in permission_scopes
                if self.__permission_scope_key__(scope) == table_key
            ]
            if not table_scopes:
                table_scopes = [
                    PermissionScope(
                        catalog=table_key[0],
                        catalog_schema=table_key[1],
                        table=table_key[2],
                        name=PermissionType.SELECT,
                        state=PermissionState.GRANT,
                    )
                ]

            table_columns = [
                constraint
                for constraint in column_constraints
                if self.__column_constraint_key__(constraint) == table_key
            ]
            for chunk_index, row_constraint in enumerate(
                rows_by_table[table_key], start=1
            ):
                split_policies.append(
                    RolePolicy(
                        name=f"{policy.name}_{table_key[2]}_RLS{chunk_index}",
                        permissionobjects=policy.permissionobjects,
                        permissionscopes=table_scopes,
                        columnconstraints=table_columns if table_columns else None,
                        rowconstraints=[row_constraint],
                    )
                )

        self.logger.info(
            f"Split policy '{policy.name}' into {len(split_policies)} policies "
            f"because one or more row predicates exceed Policy Weaver's configured "
            f"{self.config.dataverse.row_constraint_chunk_length}-character chunk length."
        )
        return split_policies

    def __split_policy_for_member_limit__(self, policy: RolePolicy) -> List[RolePolicy]:
        permission_objects = sorted(
            policy.permissionobjects or [],
            key=lambda permission_object: (
                permission_object.entra_object_id
                or permission_object.id
                or permission_object.email
                or ""
            ),
        )
        if len(permission_objects) <= self.FABRIC_ROLE_MEMBER_MAX:
            return [policy]

        split_policies = []
        for chunk_index, start in enumerate(
            range(0, len(permission_objects), self.FABRIC_ROLE_MEMBER_MAX), start=1
        ):
            member_chunk = permission_objects[
                start : start + self.FABRIC_ROLE_MEMBER_MAX
            ]
            split_policies.append(
                RolePolicy(
                    name=f"{policy.name}_Members{chunk_index}",
                    permissionobjects=member_chunk,
                    permissionscopes=policy.permissionscopes,
                    columnconstraints=policy.columnconstraints,
                    rowconstraints=policy.rowconstraints,
                )
            )

        self.logger.info(
            "Split policy '%s' into %d roles to stay within OneLake's %d-member limit.",
            policy.name,
            len(split_policies),
            self.FABRIC_ROLE_MEMBER_MAX,
        )
        return split_policies

    def __get_schema_name__(self) -> str:
        """Get the schema name from config, defaulting to 'dbo'."""
        if self.config.source.schemas and len(self.config.source.schemas) > 0:
            return self.config.source.schemas[0].name
        return "dbo"

    def __resolve_permission_object__(
        self, principal_id: str, principal_type: IamType
    ) -> List[PermissionObject]:
        """
        Resolve a Dataverse principal to PermissionObject(s) with Entra identity.
        Returns a list to support expanding owner/access teams to individual users.
        """
        if principal_type == IamType.USER:
            if self.__is_partial_excluded_user_id__(principal_id):
                return []
            user = self.environment.lookup_user_by_id(principal_id)
            if not user:
                self.logger.debug("Assigned Dataverse user not found in the snapshot.")
                return []

            permission_object = self.__permission_object_for_user__(user)
            return [permission_object] if permission_object else []

        elif principal_type == IamType.GROUP:
            team = self.environment.lookup_team_by_id(principal_id)
            if not team:
                self.logger.debug("Assigned Dataverse team not found in the snapshot.")
                return []

            expanded = []
            for member_id in team.member_ids or []:
                if self.__is_partial_excluded_user_id__(member_id):
                    continue
                user = self.environment.lookup_user_by_id(member_id)
                if not user:
                    continue
                permission_object = self.__permission_object_for_user__(user)
                if permission_object:
                    expanded.append(permission_object)
            if not expanded:
                self.logger.warning(
                    f"Team {team.name} ({principal_id}) produced no resolvable "
                    f"Entra identities among its Dataverse members."
                )
            return expanded

        return []

    @staticmethod
    def __permission_object_for_user__(user) -> PermissionObject:
        if not user or user.is_disabled or user.azure_state not in {None, 0}:
            return None
        is_application = bool(user.application_id)
        if not is_application:
            if not user.azure_ad_object_id:
                return None
            if user.access_mode in {1, 3, 5}:
                return None
            if user.is_licensed is False and user.access_mode != 4:
                return None
        principal_type = IamType.SERVICE_PRINCIPAL if is_application else IamType.USER
        return PermissionObject(
            id=user.azure_ad_object_id,
            email=user.email if principal_type == IamType.USER else None,
            app_id=user.application_id,
            type=principal_type,
            entra_object_id=user.azure_ad_object_id,
        )

    @staticmethod
    def __permission_object_identity_key__(
        permission_object: PermissionObject,
    ) -> str:
        return (
            permission_object.entra_object_id
            or permission_object.id
            or permission_object.app_id
        )

    def __resolve_shared_permission_object__(
        self, principal_id: str, principal_type: IamType
    ) -> List[PermissionObject]:
        if principal_type == IamType.GROUP:
            team = self.environment.lookup_team_by_id(principal_id)
            if team and team.team_type in {2, 3} and team.azure_ad_object_id:
                return [
                    PermissionObject(
                        id=team.azure_ad_object_id,
                        type=IamType.GROUP,
                        entra_object_id=team.azure_ad_object_id,
                    )
                ]
        return self.__resolve_permission_object__(principal_id, principal_type)

    def __get_column_constraints_for_principals__(
        self,
        principals: set,
        tables: set,
        catalog_name: str,
        schema_name: str,
    ) -> List[ColumnConstraint]:
        """
        Build column constraints from field-level security profiles.
        For each principal in this role, check which field security profiles they belong to,
        and which columns they can read.
        """
        constraints = []
        principal_ids: Set[str] = set()
        for pid, ptype in principals:
            if ptype == IamType.USER:
                if not self.__is_partial_excluded_user_id__(pid):
                    principal_ids.add(pid)
            elif ptype == IamType.GROUP:
                team = self.environment.lookup_team_by_id(pid)
                if team:
                    effective_member_ids = {
                        member_id
                        for member_id in team.member_ids or []
                        if not self.__is_partial_excluded_user_id__(member_id)
                    }
                    if effective_member_ids:
                        principal_ids.update(effective_member_ids)
                    elif team.team_type not in {0, 1}:
                        principal_ids.add(pid)
                else:
                    principal_ids.add(pid)

        secured_columns_by_table: Dict[str, Set[str]] = {}
        allowed_columns_by_table: Dict[str, Set[str]] = {}
        for table_name in tables:
            metadata = self.environment.lookup_table_metadata(table_name)
            if metadata:
                secured_columns = {
                    column.logical_name
                    for column in metadata.columns or []
                    if column.logical_name and column.is_secured
                }
                if metadata.has_secured_columns or secured_columns:
                    secured_columns_by_table[table_name] = secured_columns
                    allowed_columns_by_table[table_name] = {
                        column.logical_name
                        for column in metadata.columns or []
                        if column.logical_name and not column.is_secured
                    }
                continue

            fallback_columns = {
                permission.attribute_logical_name
                for profile in self.environment.field_security_profiles
                for permission in profile.permissions or []
                if permission.entity_name == table_name
                and permission.attribute_logical_name
            }
            if fallback_columns:
                secured_columns_by_table[table_name] = fallback_columns
                allowed_columns_by_table[table_name] = set()
        for profile in self.environment.field_security_profiles:
            profile_principals = set(profile.user_ids or [])
            for team_id in profile.team_ids or []:
                profile_principals.add(team_id)
                team = self.environment.lookup_team_by_id(team_id)
                if team:
                    profile_principals.update(team.member_ids or [])

            if not principal_ids.intersection(profile_principals):
                continue

            for perm in profile.permissions or []:
                if perm.entity_name in tables and perm.can_read == 4:  # 4 = Allowed
                    if perm.attribute_logical_name:
                        allowed_columns_by_table.setdefault(
                            perm.entity_name, set()
                        ).add(perm.attribute_logical_name)

        for table_name, columns in allowed_columns_by_table.items():
            constraints.append(
                ColumnConstraint(
                    column_actions=[PermissionType.SELECT],
                    column_effect=PermissionState.GRANT,
                    column_names=sorted(columns),
                    table_name=table_name,
                    schema_name=schema_name,
                    catalog_name=catalog_name,
                )
            )

        return constraints
