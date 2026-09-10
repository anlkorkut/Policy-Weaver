from pydantic import TypeAdapter
from requests.exceptions import HTTPError, RequestException
from typing import Callable, List, Dict
from copy import deepcopy
from dataclasses import dataclass

import hashlib
import json
import re
import logging

from policyweaver.core.exception import (
    FabricCapacityNotActiveError,
    PolicyWeaverError,
)
from policyweaver.core.auth import ServicePrincipal
from policyweaver.core.conf import Configuration
from policyweaver.core.api.fabric import FabricAPI
from policyweaver.core.api.microsoftgraph import MicrosoftGraphClient
from policyweaver.plugins.databricks.client import DatabricksPolicyWeaver
from policyweaver.plugins.snowflake.client import SnowflakePolicyWeaver
from policyweaver.plugins.dataverse.client import (
    DataversePolicyWeaver,
    is_dataverse_export_validated,
)
from policyweaver.models.fabric import (
    DataAccessPolicy,
    PolicyDecisionRule,
    PolicyEffectType,
    PolicyPermissionScope,
    PolicyAttributeType,
    PolicyMembers,
    EntraMember,
    FabricMemberObjectType,
    FabricPolicyAccessType,
    ColumnConstraint,
    Constraints,
    RowConstraint,
)
from policyweaver.models.export import (
    PolicyExport,
    RolePolicyExport,
    RolePolicy,
    PermissionObject,
)
from policyweaver.models.config import SourceMap
from policyweaver.core.enum import (
    PolicyWeaverConnectorType,
    PermissionType,
    PermissionState,
    IamType,
)


@dataclass(frozen=True)
class _PreparedRoleApplyContext:
    connector: PolicyWeaverConnectorType
    mode: str
    workspace_id: str
    item_id: str
    partial_sync_acknowledged: bool
    etag: str


class WeaverAgent:
    """
    WeaverAgen class for applying policies to Microsoft Fabric.
    This class is responsible for synchronizing policies from a source (e.g., Databricks
    Unity Catalog) to Microsoft Fabric by creating or updating data access policies.
    It uses the Fabric API to manage data access policies and the Microsoft Graph API
    to resolve user identities.
    Example usage:
        config = SourceMap(...)
        weaver = Weaver(config)
        await weaver.apply(policy_export)
    """

    __FABRIC_POLICY_ROLE_SUFFIX = "PolicyWeaver"
    __FABRIC_DEFAULT_READER_ROLE = "DefaultReader"
    __FABRIC_ROLE_NAME_MAX_LENGTH = 128
    __FABRIC_ROLE_NAME_HASH_LENGTH = 12

    @property
    def FabricPolicyRoleSuffix(self) -> str:
        """
        Get the Fabric policy role suffix from the configuration.
        If the suffix is not set in the configuration, it defaults to "PolicyWeaver".
        Returns:
            str: The Fabric policy role suffix.
        """
        if self.config and self.config.fabric and self.config.fabric.fabric_role_suffix:
            return self.config.fabric.fabric_role_suffix
        else:
            return self.__FABRIC_POLICY_ROLE_SUFFIX

    @staticmethod
    async def run(
        config: SourceMap,
        source_snapshot_hndlr: callable = None,
        fabric_snaphot_hndlr: callable = None,
        unmapped_policy_hndlr: callable = None,
    ) -> None:
        """
        Run the Policy Weaver synchronization process.
        This method initializes the environment, sets up the service principal,
        and applies policies based on the provided configuration.
        Args:
            config (SourceMap): The configuration for the Policy Weaver, including service principal credentials and source
            type.
        """
        if config.type == PolicyWeaverConnectorType.DATAVERSE:
            raise PolicyWeaverError(
                "Dataverse publication must use scripts/dataverse_policy_sync.py "
                "so dry-run, exact-item confirmation, rollback, and explicit "
                "validation acknowledgements cannot be bypassed."
            )
        Configuration.configure_environment(config)
        logger = logging.getLogger("POLICY_WEAVER")
        logger.info("Policy Weaver Sync started...")

        ServicePrincipal.initialize(
            tenant_id=config.service_principal.tenant_id,
            client_id=config.service_principal.client_id,
            client_secret=config.service_principal.client_secret,
        )

        weaver = WeaverAgent(config)

        if source_snapshot_hndlr:
            weaver.set_source_snaphot_handler(source_snapshot_hndlr)

        if fabric_snaphot_hndlr:
            weaver.set_fabric_snapshot_handler(fabric_snaphot_hndlr)

        if unmapped_policy_hndlr:
            weaver.set_unmapped_policy_handler(unmapped_policy_hndlr)

        match config.type:
            case PolicyWeaverConnectorType.UNITY_CATALOG:
                src = DatabricksPolicyWeaver(config)
            case PolicyWeaverConnectorType.SNOWFLAKE:
                src = SnowflakePolicyWeaver(config)
            case PolicyWeaverConnectorType.DATAVERSE:
                src = DataversePolicyWeaver(config)
            case _:
                pass

        logger.info(f"Running Policy Export for {config.type}: {config.source.name}...")
        policy_mapping = config.fabric.policy_mapping

        policy_export = src.map_policy(policy_mapping)

        if policy_export:
            weaver.source_snapshot_handler(policy_export)
            if policy_mapping == "role_based":
                await weaver.apply_role(policy_export)
            else:
                await weaver.apply(policy_export)
            logger.info("Policy Weaver Sync complete!")
        else:
            logger.info("No policies found to apply. Exiting...")

    def __init__(self, config: SourceMap) -> None:
        """
        Initialize the Weaver with the provided configuration.
        This method sets up the logger, Fabric API client, and Microsoft Graph client.
        Args:
            config (SourceMap): The configuration for the Policy Weaver, including service principal credentials and source type.
        """
        self.config = config
        self.logger = logging.getLogger("POLICY_WEAVER")
        self.fabric_api = FabricAPI(config.fabric.workspace_id, self.config.type)
        self.graph_client = MicrosoftGraphClient()

        self._source_snapshot_handler = None
        self._fabric_snapshot_handler = None
        self._unmapped_policy_handler = None
        self.__graph_map = dict()
        self.used_role_names = []
        self._prepared_role_context = None
        self._current_fabric_policies_raw = None
        self._current_fabric_policies_etag = None

    async def apply(self, policy_export: PolicyExport) -> None:
        """
        Apply the policies to Microsoft Fabric based on the provided policy export.
        This method retrieves the current access policies, builds new data access policies
        based on the policy export, and applies them to the Fabric workspace.
        Args:
            policy_export (PolicyExport): The exported policies from the source, containing permissions and objects.
        """

        if self.config.type == PolicyWeaverConnectorType.DATAVERSE:
            raise PolicyWeaverError(
                "Dataverse policies must use role_based mapping through "
                "scripts/dataverse_policy_sync.py."
            )

        if not self.config.fabric.tenant_id:
            self.config.fabric.tenant_id = ServicePrincipal.TenantId

        self.logger.info(f"Tenant ID: {self.config.fabric.tenant_id}...")
        self.logger.info(f"Workspace ID: {self.config.fabric.workspace_id}...")
        self.logger.info(f"Mirror ID: {self.config.fabric.mirror_id}...")
        self.logger.info(f"Mirror Name: {self.config.fabric.mirror_name}...")

        if not self.config.fabric.workspace_name:
            self.config.fabric.workspace_name = self.fabric_api.get_workspace_name()

        self.logger.info(
            f"Applying Fabric Policies to {self.config.fabric.workspace_name}..."
        )
        self.__get_current_access_policy__()
        await self.__apply_policies__(policy_export)

    async def apply_role(
        self,
        policy_export: RolePolicyExport,
        dry_run_only: bool = False,
        partial_sync_acknowledged: bool = False,
    ) -> None:
        """
        Apply the policies to Microsoft Fabric based on the provided policy export.
        This method retrieves the current access policies, builds new data access policies
        based on the policy export, and applies them to the Fabric workspace.
        Args:
            policy_export (PolicyExport): The exported policies from the source, containing permissions and objects.
        """

        prepared_context = None
        if not dry_run_only:
            prepared_context = getattr(self, "_prepared_role_context", None)
            if prepared_context is not None:
                self._prepared_role_context = None
                self.__validate_prepared_role_apply_context__(
                    prepared_context, partial_sync_acknowledged
                )

        if self.config.type == PolicyWeaverConnectorType.DATAVERSE:
            strict_mode = getattr(self.config.dataverse, "strict_access_parity", False)
            partial_mode = getattr(self.config.dataverse, "partial_sync", False)
            if not strict_mode and not partial_mode:
                raise PolicyWeaverError(
                    "Dataverse Fabric operations require either "
                    "dataverse.strict_access_parity=true or an explicitly "
                    "confirmed partial sync."
                )
            if partial_mode and not policy_export.policies:
                raise PolicyWeaverError(
                    "Dataverse partial sync produced no valid policies. Refusing "
                    "to remove all managed Fabric roles."
                )
        self.__validate_strict_dataverse_export__(policy_export)

        if (
            self.config.type == PolicyWeaverConnectorType.DATAVERSE
            and not dry_run_only
            and prepared_context is None
        ):
            raise PolicyWeaverError(
                "Dataverse apply requires prepare_role_apply() so the rollback "
                "snapshot and authoritative PUT use the same target ETag."
            )

        if not self.config.fabric.tenant_id:
            self.config.fabric.tenant_id = ServicePrincipal.TenantId

        self.logger.info(f"Tenant ID: {self.config.fabric.tenant_id}...")
        self.logger.info(f"Workspace ID: {self.config.fabric.workspace_id}...")
        self.logger.info(f"Mirror ID: {self.config.fabric.mirror_id}...")
        self.logger.info(f"Mirror Name: {self.config.fabric.mirror_name}...")

        if not self.config.fabric.workspace_name:
            self.config.fabric.workspace_name = self.fabric_api.get_workspace_name()

        self.logger.info(
            f"Applying Fabric Policies to {self.config.fabric.workspace_name}..."
        )
        if prepared_context is None:
            self.__get_current_access_policy__()
        self.__validate_dataverse_target_access_boundary__()
        await self.__apply_role_policies__(
            policy_export,
            dry_run_only=dry_run_only,
            prepared_context=prepared_context,
            partial_sync_acknowledged=partial_sync_acknowledged,
        )

    def prepare_role_apply(
        self,
        confirm_item: str,
        rollback_snapshot_handler: Callable[[List[dict], str], None] | None = None,
        partial_sync_acknowledged: bool = False,
    ) -> tuple[List[dict], str]:
        self._prepared_role_context = None
        if self.config.type != PolicyWeaverConnectorType.DATAVERSE:
            raise PolicyWeaverError(
                "Role apply preparation is only supported for Dataverse."
            )
        if confirm_item != self.config.fabric.mirror_id:
            raise PolicyWeaverError(
                "Prepared apply item must exactly match fabric.mirror_id."
            )
        if rollback_snapshot_handler is None:
            raise PolicyWeaverError(
                "Dataverse apply requires a rollback snapshot handler."
            )
        if (
            self.config.type == PolicyWeaverConnectorType.DATAVERSE
            and getattr(self.config.dataverse, "partial_sync", False)
            and not partial_sync_acknowledged
        ):
            raise PolicyWeaverError(
                "Partial Dataverse apply requires explicit under-grant acknowledgement."
            )

        self.__validate_fabric_workspace_target__()
        self.__get_current_access_policy__()
        etag = self._current_fabric_policies_etag
        if not etag:
            raise PolicyWeaverError(
                "Fabric did not return an ETag for the Data Access Role collection."
            )
        before_image = [
            self.__sanitize_fabric_role_for_put__(role)
            for role in self._current_fabric_policies_raw or []
        ]
        prepared_context = self.__build_prepared_role_apply_context__(
            partial_sync_acknowledged, etag
        )
        rollback_snapshot_handler(deepcopy(before_image), etag)
        self._prepared_role_context = prepared_context
        return deepcopy(before_image), etag

    def validate_role_target_write_ready(self) -> None:
        """Verify the Dataverse target can accept role writes without changing it."""
        if self.config.type != PolicyWeaverConnectorType.DATAVERSE:
            raise PolicyWeaverError(
                "Role target write readiness is only supported for Dataverse."
            )

        self.__validate_fabric_workspace_target__()
        self.__get_current_access_policy__()
        self.__validate_dataverse_target_access_boundary__()
        etag = self._current_fabric_policies_etag
        if not etag:
            raise PolicyWeaverError(
                "Fabric did not return an ETag for the Data Access Role collection."
            )
        payload = json.dumps(
            {
                "value": [
                    self.__sanitize_fabric_role_for_put__(role)
                    for role in self._current_fabric_policies_raw or []
                ]
            }
        )
        self.fabric_api.put_data_access_policy(
            self.config.fabric.mirror_id,
            payload,
            dry_run=True,
            if_match=etag,
        )
        self.logger.info("Fabric Data Access Role write-readiness preflight succeeded.")

    def __dataverse_role_apply_mode__(self) -> str:
        strict_mode = bool(
            getattr(self.config.dataverse, "strict_access_parity", False)
        )
        partial_mode = bool(getattr(self.config.dataverse, "partial_sync", False))
        if strict_mode == partial_mode:
            raise PolicyWeaverError(
                "Dataverse role apply requires exactly one of strict or partial mode."
            )
        return "strict" if strict_mode else "partial"

    def __build_prepared_role_apply_context__(
        self, partial_sync_acknowledged: bool, etag: str
    ) -> _PreparedRoleApplyContext:
        self.__validate_fabric_workspace_target__()
        return _PreparedRoleApplyContext(
            connector=self.config.type,
            mode=self.__dataverse_role_apply_mode__(),
            workspace_id=self.config.fabric.workspace_id,
            item_id=self.config.fabric.mirror_id,
            partial_sync_acknowledged=partial_sync_acknowledged,
            etag=etag,
        )

    def __validate_fabric_workspace_target__(self) -> None:
        fabric_workspace_id = getattr(self.fabric_api, "workspace_id", None)
        if (
            fabric_workspace_id is not None
            and fabric_workspace_id != self.config.fabric.workspace_id
        ):
            raise PolicyWeaverError(
                "Fabric target context is invalid: client workspace no longer "
                "matches fabric.workspace_id. No policies were applied."
            )

    def __validate_prepared_role_apply_context__(
        self,
        prepared_context: _PreparedRoleApplyContext,
        partial_sync_acknowledged: bool,
    ) -> None:
        if self.config.type != PolicyWeaverConnectorType.DATAVERSE:
            raise PolicyWeaverError(
                "Prepared Dataverse apply context no longer matches the connector."
            )
        current_context = self.__build_prepared_role_apply_context__(
            partial_sync_acknowledged, prepared_context.etag
        )
        if current_context != prepared_context:
            raise PolicyWeaverError(
                "Prepared Dataverse apply context no longer matches the current "
                "mode, target, or acknowledgement. No policies were applied."
            )
        if self.fabric_api.data_access_roles_etag != prepared_context.etag:
            raise PolicyWeaverError(
                "Prepared Fabric role ETag changed before apply. No policies were applied."
            )

    @staticmethod
    def __sanitize_fabric_role_for_put__(role: dict) -> dict:
        allowed_fields = {"id", "name", "kind", "decisionRules", "members"}
        return {
            key: deepcopy(value) for key, value in role.items() if key in allowed_fields
        }

    def __validate_strict_dataverse_export__(
        self, policy_export: RolePolicyExport
    ) -> None:
        if (
            self.config.type == PolicyWeaverConnectorType.DATAVERSE
            and (
                getattr(self.config.dataverse, "strict_access_parity", False)
                or getattr(self.config.dataverse, "partial_sync", False)
            )
            and not is_dataverse_export_validated(policy_export, self.config)
        ):
            raise PolicyWeaverError(
                "Dataverse Fabric operations require an unchanged export produced "
                "by DataversePolicyWeaver.map_policy after strict source validation "
                "or explicit partial quarantine for the current policy and target "
                "configuration."
            )

    def split_off_new_role_policy(
        policy: RolePolicy, part_number: int, min: int, max: int
    ) -> RolePolicy:
        """Split a RolePolicy into a new RolePolicy with a subset of permission scopes.
        This method creates a new RolePolicy object that contains a subset of the permission scopes
        from the original policy, based on the specified minimum and maximum indices.
        Args:
            policy (RolePolicy): The original RolePolicy object to split.
            part_number (int): The part number for naming the new policy.
            min (int): The starting index of the permission scopes to include in the new policy.
            max (int): The ending index of the permission scopes to include in the new policy.
        Returns:
            RolePolicy: A new RolePolicy object containing the specified subset of permission scopes.
        """
        if max > len(policy.permissionscopes):
            max = len(policy.permissionscopes)

        new_policy = RolePolicy(
            name=f"{policy.name}Part{part_number}",
            permissionscopes=policy.permissionscopes[min:max],
            permissionobjects=policy.permissionobjects,
            columnconstraints=policy.columnconstraints,
            rowconstraints=policy.rowconstraints,
        )
        return new_policy

    def split_permission_scopes(policy: RolePolicy) -> List[RolePolicy]:
        """
        Split a RolePolicy with multiple permission scopes into multiple RolePolicy objects, each with a single permission scope.
        This method is used to handle policies that have multiple permissions by creating separate policies for each permission scope.
        Args:
            policy (RolePolicy): The original RolePolicy object containing multiple permission scopes.
        Returns:
            List[RolePolicy]: A list of RolePolicy objects, each containing a single permission scope.
        """

        if len(policy.permissionscopes) <= 500:
            return [policy]  # No need to split if within limits

        # iterate by 500
        policies = []
        for i, j in enumerate(range(0, len(policy.permissionscopes), 500)):
            new_policy = WeaverAgent.split_off_new_role_policy(
                policy, i + 1, j, j + 500
            )
            policies.append(new_policy)

        return policies

    @staticmethod
    def __normalize_semantic_value__(value):
        if isinstance(value, dict):
            return {
                key: WeaverAgent.__normalize_semantic_value__(item)
                for key, item in sorted(value.items())
            }
        if isinstance(value, list):
            normalized = [
                WeaverAgent.__normalize_semantic_value__(item) for item in value
            ]
            return sorted(
                normalized,
                key=lambda item: json.dumps(
                    item, sort_keys=True, separators=(",", ":")
                ),
            )
        return value

    @staticmethod
    def __canonical_role_collection__(roles: List[DataAccessPolicy]) -> List[str]:
        canonical_roles = []
        for role in roles:
            value = {
                key: item
                for key, item in role.model_dump(
                    exclude_none=True, exclude_unset=True
                ).items()
                if key != "id"
            }
            # Fabric requires objectType on PUT but omits it from Data Access
            # Role GET responses. Object and tenant IDs remain authoritative.
            for member in (value.get("members") or {}).get("microsoftEntraMembers", []):
                member.pop("objectType", None)
            canonical_roles.append(
                json.dumps(
                    WeaverAgent.__normalize_semantic_value__(value),
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        return sorted(canonical_roles)

    @staticmethod
    def __canonical_role_policy__(policy: RolePolicy) -> str:
        return json.dumps(
            WeaverAgent.__normalize_semantic_value__(
                policy.model_dump(exclude_none=True, exclude_unset=True)
            ),
            sort_keys=True,
            separators=(",", ":"),
        )

    def __validate_dataverse_target_access_boundary__(self) -> None:
        if not (
            self.config.type == PolicyWeaverConnectorType.DATAVERSE
            and (
                getattr(self.config.dataverse, "strict_access_parity", False)
                or getattr(self.config.dataverse, "partial_sync", False)
            )
        ):
            return

        current_roles = self.current_fabric_policies or []
        default_reader_present = any(
            (role.name or "").casefold() == self.__FABRIC_DEFAULT_READER_ROLE.casefold()
            for role in current_roles
        )
        if default_reader_present and not self.config.fabric.delete_default_reader_role:
            raise PolicyWeaverError(
                "Dataverse publication requires removing the DefaultReader role. "
                "Set fabric.delete_default_reader_role=true after reviewing the target."
            )

        suffix = self.FabricPolicyRoleSuffix.casefold()
        unmanaged_roles = [
            role.name
            for role in current_roles
            if (role.name or "").casefold()
            != self.__FABRIC_DEFAULT_READER_ROLE.casefold()
            and not (role.name or "").casefold().endswith(suffix)
        ]
        if unmanaged_roles:
            raise PolicyWeaverError(
                f"Dataverse publication cannot proceed while "
                f"{len(unmanaged_roles)} unmanaged Fabric Data Access Role(s) exist."
            )

    async def __apply_role_policies__(
        self,
        policy_export: RolePolicyExport,
        dry_run_only: bool = False,
        prepared_context: _PreparedRoleApplyContext | None = None,
        partial_sync_acknowledged: bool = False,
    ) -> None:
        """
        Apply the policies to Microsoft Fabric by creating or updating data access policies.
        This method builds data access policies based on the permissions in the policy export
        and applies them to the Fabric workspace.
        Args:
            policy_export (RolePolicyExport): The exported policies from the source, containing permissions and objects.
        """
        if self.config.type == PolicyWeaverConnectorType.DATAVERSE and not dry_run_only:
            if prepared_context is None:
                raise PolicyWeaverError(
                    "Dataverse apply requires prepare_role_apply() so the rollback "
                    "snapshot and authoritative PUT use the same target ETag."
                )
            self.__validate_prepared_role_apply_context__(
                prepared_context, partial_sync_acknowledged
            )

        self.used_role_names = []
        access_policies = []
        expanded_policies = [
            split_policy
            for policy in policy_export.policies
            for split_policy in WeaverAgent.split_permission_scopes(policy)
        ]
        expanded_policies.sort(
            key=lambda policy: (
                (policy.name or "").casefold(),
                policy.name or "",
                self.__canonical_role_policy__(policy),
            )
        )

        for policy in expanded_policies:
            access_policy = await self.__build_data_access_role_policy__(
                policy, FabricPolicyAccessType.READ
            )
            if not access_policy:
                continue
            self.fabric_snapshot_handler(access_policy)
            access_policies.append(access_policy)

        if (
            self.config.type == PolicyWeaverConnectorType.DATAVERSE
            and getattr(self.config.dataverse, "partial_sync", False)
            and not access_policies
        ):
            raise PolicyWeaverError(
                "Dataverse partial sync produced no publishable Fabric policies. "
                "Refusing to remove all managed roles."
            )

        current_policies = self.current_fabric_policies or []
        generated_by_name = {
            (policy.name or "").casefold(): policy for policy in access_policies
        }
        for current_policy in current_policies:
            current_name = (current_policy.name or "").casefold()
            generated_policy = generated_by_name.get(current_name)
            if generated_policy:
                generated_policy.id = current_policy.id
                continue

            is_default_reader = (
                current_name == self.__FABRIC_DEFAULT_READER_ROLE.casefold()
            )
            is_managed = current_name.endswith(self.FabricPolicyRoleSuffix.casefold())
            if is_managed or (
                is_default_reader and self.config.fabric.delete_default_reader_role
            ):
                continue
            access_policies.append(current_policy)

        if self.__canonical_role_collection__(
            current_policies
        ) == self.__canonical_role_collection__(access_policies):
            self.logger.info(
                "Fabric Data Access Roles already match the desired state."
            )
            return

        role_limit = getattr(
            getattr(self.config, "dataverse", None), "onelake_role_limit", None
        )
        if role_limit and len(access_policies) > role_limit:
            raise PolicyWeaverError(
                f"Desired Fabric payload contains {len(access_policies):,} roles, "
                f"exceeding the configured limit of {role_limit:,}."
            )

        payload = json.dumps(
            {
                "value": [
                    policy.model_dump(exclude_none=True, exclude_unset=True)
                    for policy in access_policies
                ]
            }
        )
        etag = (
            prepared_context.etag
            if prepared_context is not None
            else self.fabric_api.data_access_roles_etag
        )
        if not etag:
            raise PolicyWeaverError(
                "Fabric did not return an ETag for the Data Access Role collection."
            )
        if prepared_context is not None:
            self.__validate_prepared_role_apply_context__(
                prepared_context, partial_sync_acknowledged
            )

        self.__validate_strict_dataverse_export__(policy_export)
        self.fabric_api.put_data_access_policy(
            self.config.fabric.mirror_id,
            payload,
            dry_run=True,
            if_match=etag,
        )
        if dry_run_only:
            self.logger.info(
                "Fabric dry-run validation succeeded; no roles were applied."
            )
            return

        if prepared_context is not None:
            self.__validate_prepared_role_apply_context__(
                prepared_context, partial_sync_acknowledged
            )
        self.__validate_strict_dataverse_export__(policy_export)
        if prepared_context is not None:
            self.__validate_prepared_role_apply_context__(
                prepared_context, partial_sync_acknowledged
            )
        try:
            self.fabric_api.put_data_access_policy(
                self.config.fabric.mirror_id,
                payload,
                dry_run=False,
                if_match=etag,
            )
        except (RequestException, FabricCapacityNotActiveError):
            verified_payload = self.fabric_api.list_data_access_policy(
                self.config.fabric.mirror_id
            )
            verified_roles = TypeAdapter(List[DataAccessPolicy]).validate_python(
                verified_payload["value"]
            )
            if self.__canonical_role_collection__(
                verified_roles
            ) != self.__canonical_role_collection__(access_policies):
                raise
            self.logger.warning(
                "Fabric apply response was ambiguous, but GET verification matched "
                "the desired role collection."
            )
            return

        verified_payload = self.fabric_api.list_data_access_policy(
            self.config.fabric.mirror_id
        )
        verified_roles = TypeAdapter(List[DataAccessPolicy]).validate_python(
            verified_payload["value"]
        )
        if self.__canonical_role_collection__(
            verified_roles
        ) != self.__canonical_role_collection__(access_policies):
            raise PolicyWeaverError(
                "Fabric Data Access Role verification did not match the applied payload."
            )

        self.logger.info(
            f"Total Data Access Policies synced and verified: {len(access_policies)}"
        )

    async def __apply_policies__(self, policy_export: PolicyExport) -> None:
        """
        Apply the policies to Microsoft Fabric by creating or updating data access policies.
        This method builds data access policies based on the permissions in the policy export
        and applies them to the Fabric workspace.
        Args:
            policy_export (PolicyExport): The exported policies from the source, containing permissions and objects.
        """
        access_policies = []

        for policy in policy_export.policies:
            for permission in policy.permissions:
                if (
                    permission.name == PermissionType.SELECT
                    and permission.state == PermissionState.GRANT
                ):
                    access_policy = await self.__build_data_access_policy__(
                        policy, permission, FabricPolicyAccessType.READ
                    )
                    if not access_policy:
                        continue

                    self.fabric_snapshot_handler(access_policy)
                    access_policies.append(access_policy)

        inserted_policies = len(access_policies)
        updated_policies = 0
        deleted_policies = 0
        unmanaged_policies = 0

        # Append policies not managed by PolicyWeaver
        if self.current_fabric_policies:
            for p in self.current_fabric_policies:
                if self.FabricPolicyRoleSuffix not in p.name:
                    continue

                # Check if the policy already exists
                existing_policy = next(
                    (ap for ap in access_policies if ap.name.lower() == p.name.lower()),
                    None,
                )

                if existing_policy:
                    # Update existing policy
                    self.logger.debug(f"Updating Policy: {p.name}")
                    existing_policy.id = p.id
                    updated_policies += 1
                    inserted_policies -= 1
                else:
                    self.logger.debug(f"Removing Policy: {p.name}")

            xapply = [
                p
                for p in self.current_fabric_policies
                if not p.name.lower().endswith(self.FabricPolicyRoleSuffix.lower())
            ]

            if xapply:
                self.logger.debug(f"Unmanaged Policies: {len(xapply)}")

                if self.config.fabric.delete_default_reader_role:
                    self.logger.debug("Deleting default reader role as configured...")
                    for p in xapply:
                        xapply = [
                            p
                            for p in xapply
                            if not p.name.lower()
                            == self.__FABRIC_DEFAULT_READER_ROLE.lower()
                        ]

                unmanaged_policies += len(xapply)
                access_policies.extend(xapply)

            for p in self.current_fabric_policies:
                if p.name not in [ap.name for ap in access_policies]:
                    deleted_policies += 1
        else:
            self.logger.debug("No current Fabric policies found.")

        self.logger.info(
            f"Policies Summary - Inserted: {inserted_policies}, Updated: {updated_policies}, Deleted: {deleted_policies}, Unmanaged: {unmanaged_policies}"
        )

        if (
            inserted_policies + updated_policies + deleted_policies + unmanaged_policies
        ) > 0:
            dap_request = {
                "value": [
                    p.model_dump(exclude_none=True, exclude_unset=True)
                    for p in access_policies
                ]
            }

            self.fabric_api.put_data_access_policy(
                self.config.fabric.mirror_id, json.dumps(dap_request)
            )

            self.logger.info(
                f"Total Data Access Polices Synced: {len(access_policies)}"
            )
        else:
            self.logger.info("No Data Access Policies to sync...")

    def __get_current_access_policy__(self) -> None:
        """
        Retrieve the current data access policies from the Fabric Mirror.
        This method fetches the existing data access policies from the Fabric Mirror
        and stores them in the current_fabric_policies attribute.
        Raises:
            PolicyWeaverError: If Data Access Policies are not enabled on the Fabric Mirror.
            HTTPError: If there is an error retrieving the policies from the Fabric API.
        """
        try:
            result = self.fabric_api.list_data_access_policy(
                self.config.fabric.mirror_id
            )
            if not isinstance(result, dict) or not isinstance(
                result.get("value"), list
            ):
                raise PolicyWeaverError(
                    "Fabric returned a malformed Data Access Role collection."
                )
            raw_roles = result["value"]
            if any(not isinstance(role, dict) for role in raw_roles):
                raise PolicyWeaverError(
                    "Fabric returned a malformed Data Access Role entry."
                )
            type_adapter = TypeAdapter(List[DataAccessPolicy])
            current_fabric_policies = type_adapter.validate_python(raw_roles)
            etag = self.fabric_api.data_access_roles_etag
            self._current_fabric_policies_raw = deepcopy(raw_roles)
            self._current_fabric_policies_etag = etag
            self.current_fabric_policies = current_fabric_policies
        except HTTPError as e:
            if e.response.status_code == 400:
                raise PolicyWeaverError(
                    "ERROR: Please ensure Data Access Policies are enabled on the Fabric Mirror."
                )
            else:
                raise e

    def __get_table_mapping__(self, catalog: str, schema: str, table: str) -> str:
        """
        Get the table mapping for the specified catalog, schema, and table.
        This method checks if the table is mapped in the configuration and returns
        the appropriate table path for the Fabric API.
        Args:
            catalog (str): The catalog name.
            schema (str): The schema name.
            table (str): The table name.
        Returns:
            str: The table path in the format "Tables/{schema}/{table}" if mapped, otherwise None.
        """
        schema_nm = schema.strip() if isinstance(schema, str) else schema

        if not table:
            if self.config.type == PolicyWeaverConnectorType.DATAVERSE:
                # Dataverse table scopes are table-based and do not use schema path segments.
                return "*"
            if schema_nm:
                return f"Tables/{schema_nm}"
            return "*"

        table_nm = self.__get_mapped_table_name__(catalog, schema, table)

        if self.config.type == PolicyWeaverConnectorType.DATAVERSE:
            # Dataverse paths are /Tables/{table} (no /{schema}/ segment).
            table_path = f"Tables/{table_nm}"
        else:
            table_path = f"Tables/{schema_nm}/{table_nm}"

        return table_path

    def __get_mapped_table_name__(self, catalog: str, schema: str, table: str) -> str:
        if getattr(self.config, "mapped_items", None):
            matched_tbl = next(
                (
                    tbl
                    for tbl in self.config.mapped_items
                    if tbl.catalog == catalog
                    and tbl.catalog_schema == schema
                    and tbl.table == table
                ),
                None,
            )
        else:
            matched_tbl = None
        return table if not matched_tbl else matched_tbl.mirror_table_name or table

    async def __get_graph_map__(self, policy_export: PolicyExport) -> Dict[str, str]:
        """
        Retrieve a mapping of user and service principal IDs from the Microsoft Graph API.
        This method iterates through the permissions in the policy export and retrieves
        the corresponding user or service principal IDs based on their lookup IDs.
        Args:
            policy_export (PolicyExport): The exported policies from the source, containing permissions and objects.
        Returns:
            Dict[str, str]: A dictionary mapping lookup IDs to user or service principal IDs.
        """
        graph_map = dict()

        for policy in policy_export.policies:
            for permission in policy.permissions:
                for object in permission.objects:
                    if object.lookup_id not in graph_map:
                        match object.type:
                            case IamType.USER:
                                if not object.id:
                                    graph_map[
                                        object.lookup_id
                                    ] = await self.graph_client.get_user_by_email(
                                        object.email
                                    )
                                else:
                                    graph_map[object.lookup_id] = object.id
                            case IamType.SERVICE_PRINCIPAL:
                                if not object.id:
                                    graph_map[
                                        object.lookup_id
                                    ] = await self.graph_client.get_service_principal_by_id(
                                        object.app_id
                                    )
                                else:
                                    graph_map[object.lookup_id] = object.id

        return graph_map

    async def __get_graph_map_role__(
        self, policy_export: RolePolicyExport
    ) -> Dict[str, str]:
        """
        Retrieve a mapping of user and service principal IDs from the Microsoft Graph API.
        This method iterates through the permissions in the policy export and retrieves
        the corresponding user or service principal IDs based on their lookup IDs.
        Args:
            policy_export (PolicyExport): The exported policies from the source, containing permissions and objects.
        Returns:
            Dict[str, str]: A dictionary mapping lookup IDs to user or service principal IDs.
        """
        graph_map = dict()

        for policy in policy_export.policies:
            for object in policy.permissionobjects:
                if object.lookup_id not in graph_map:
                    match object.type:
                        case IamType.USER:
                            if not object.id:
                                graph_map[
                                    object.lookup_id
                                ] = await self.graph_client.get_user_by_email(
                                    object.email.lower()
                                )
                            else:
                                graph_map[object.lookup_id] = object.id
                        case IamType.SERVICE_PRINCIPAL:
                            if not object.id:
                                graph_map[
                                    object.lookup_id
                                ] = await self.graph_client.get_service_principal_by_id(
                                    object.app_id
                                )
                            else:
                                graph_map[object.lookup_id] = object.id

        return graph_map

    def __get_role_name__(self, policy: PolicyExport) -> str:
        """
        Generate a role name based on the policy's catalog, schema, and table.
        This method constructs a role name by concatenating the catalog, schema, and table
        information, ensuring it adheres to the naming conventions for Fabric policies.
        Args:
            policy (PolicyExport): The policy object containing catalog, schema, and table information.
        Returns:
            str: The generated role name in the format "xxPOLICYWEAVERxx<CATALOG><SCHEMA><TABLE>".
        """
        if policy.catalog_schema:
            role_description = f"{policy.catalog_schema.replace(' ', '')} {'' if not policy.table else policy.table.replace(' ', '')}"
        else:
            role_description = policy.catalog.replace(" ", "")

        role_name = f"{role_description.title()}{self.config.fabric.fabric_role_suffix}"
        # replace all signs
        role_name = (
            role_name.replace("-", "")
            .replace("_", "")
            .replace(" ", "")
            .replace(".", "")
        )
        role_name = (
            role_name.replace("@", "")
            .replace("'", "")
            .replace("`", "")
            .replace("!", "")
        )
        # replace all non alphanumeric signs
        role_name = re.sub(r"\W+", "", role_name)

        return re.sub(r"[^a-zA-Z0-9]", "", role_name)

    async def __build_data_access_policy__(
        self,
        policy: PolicyExport,
        permission: PermissionType,
        access_policy_type: FabricPolicyAccessType,
    ) -> DataAccessPolicy:
        """
        Build a Data Access Policy based on the provided policy and permission.
        This method constructs a Data Access Policy object that includes the role name,
        decision rules, and members based on the policy's catalog, schema, table, and permissions
        Args:
            policy (PolicyExport): The policy object containing catalog, schema, and table information.
            permission (PermissionType): The permission type to be applied (e.g., SELECT).
            access_policy_type (FabricPolicyAccessType): The type of access policy (e.g., READ).
        Returns:
            DataAccessPolicy: The constructed Data Access Policy object.
        """
        role_name = self.__get_role_name__(policy)

        table_path = self.__get_table_mapping__(
            policy.catalog, policy.catalog_schema, policy.table
        )
        if table_path and table_path != "*":
            table_path = f"/{table_path}"

        dap = DataAccessPolicy(
            name=role_name,
            decision_rules=[
                PolicyDecisionRule(
                    effect=PolicyEffectType.PERMIT,
                    permission=[
                        PolicyPermissionScope(
                            attribute_name=PolicyAttributeType.PATH,
                            attribute_value_included_in=[table_path],
                        ),
                        PolicyPermissionScope(
                            attribute_name=PolicyAttributeType.ACTION,
                            attribute_value_included_in=[access_policy_type],
                        ),
                    ],
                )
            ],
            members=PolicyMembers(entra_members=[]),
        )

        for o in permission.objects:
            object_id = await self.__lookup_entra_object_id__(o)
            if object_id:
                if o.type == IamType.GROUP:
                    object_type = FabricMemberObjectType.GROUP
                else:
                    object_type = (
                        FabricMemberObjectType.USER
                        if o.type == IamType.USER
                        else FabricMemberObjectType.SERVICE_PRINCIPAL
                    )

                dap.members.entra_members.append(
                    EntraMember(
                        object_id=object_id,
                        tenant_id=self.config.fabric.tenant_id,
                        object_type=object_type,
                    )
                )
            else:
                self.logger.warning(
                    f"POLICY WEAVER - {o.lookup_id} not found in Microsoft Graph. Skipping..."
                )
                if self._unmapped_policy_handler:
                    self._unmapped_policy_handler(o.lookup_id, policy)
                continue

        if dap.members.entra_members == []:
            self.logger.warning(
                f"POLICY WEAVER - No valid members found for policy {policy.name}. Skipping..."
            )
            return None

        self.logger.debug(
            f"POLICY WEAVER - Data Access Policy - {dap.name}: {dap.model_dump_json(indent=4)}"
        )

        return dap

    async def __lookup_entra_object_id__(self, object: PermissionObject) -> str:
        """
        Looks up the Entra object ID for a given policy object.
        Args:
            policy_object (PermissionObject): The policy object to look up.
        Returns:
            Optional[str]: The Entra object ID if found, otherwise None.
        """
        object_id = object.entra_object_id
        if object_id:
            return object_id

        if object.lookup_id in self.__graph_map:
            return self.__graph_map[object.lookup_id]

        if object.type not in [IamType.USER, IamType.SERVICE_PRINCIPAL]:
            return None

        match object.type:
            case IamType.USER:
                if not object.id:
                    self.__graph_map[
                        object.lookup_id
                    ] = await self.graph_client.get_user_by_email(object.email)
                else:
                    self.__graph_map[object.lookup_id] = object.id
            case IamType.SERVICE_PRINCIPAL:
                if not object.id:
                    self.__graph_map[
                        object.lookup_id
                    ] = await self.graph_client.get_service_principal_by_id(
                        object.app_id
                    )
                else:
                    self.__graph_map[object.lookup_id] = object.id

        return self.__graph_map[object.lookup_id]

    def __generate_rls_value__(
        self,
        schema_name: str,
        table_name: str,
        filter_condition: str,
        catalog_name: str = None,
    ) -> str:
        if self.config.type == PolicyWeaverConnectorType.DATAVERSE:
            target_table_name = self.__get_mapped_table_name__(
                catalog_name, schema_name, table_name
            )
            start = f"SELECT * FROM {target_table_name}"
        else:
            start = f"SELECT * FROM {schema_name}.{table_name}"
        filter_condition = filter_condition.replace("!=", "<>")
        if filter_condition.replace(" ", "").lower() == "true":
            return "true"
        elif filter_condition.replace(" ", "").lower() == "false":
            return "false"
        else:
            return f"{start} WHERE {filter_condition}"

    def __get_fabric_role_name__(self, source_name: str) -> str:
        suffix = self.FabricPolicyRoleSuffix or ""
        if not re.fullmatch(r"[a-zA-Z0-9]+", suffix):
            raise ValueError(
                "fabric.fabric_role_suffix must contain only alphanumeric characters."
            )

        source = re.sub(r"[^a-zA-Z0-9]", "", source_name or "") or "Role"
        if source[0].isdigit():
            source = f"ID{source}"

        source_budget = (
            self.__FABRIC_ROLE_NAME_MAX_LENGTH
            - len(suffix)
            - self.__FABRIC_ROLE_NAME_HASH_LENGTH
        )
        if source_budget < 1:
            raise ValueError(
                "fabric.fabric_role_suffix is too long to preserve a stable role-name "
                "hash within Fabric's 128-character limit."
            )

        def hashed_candidate(discriminator: str) -> str:
            digest = hashlib.sha256(discriminator.encode("utf-8")).hexdigest()[
                : self.__FABRIC_ROLE_NAME_HASH_LENGTH
            ]
            return f"{source[:source_budget]}{digest}{suffix}"

        role_name = hashed_candidate(source_name or source)

        used_names = {name.casefold() for name in self.used_role_names}
        if role_name.casefold() in used_names:
            collision_index = 1
            while True:
                candidate = hashed_candidate(
                    f"{source_name or source}:{collision_index}"
                )
                if candidate.casefold() not in used_names:
                    role_name = candidate
                    break
                collision_index += 1

        self.used_role_names.append(role_name)
        return role_name

    async def __build_data_access_role_policy__(
        self, policy: RolePolicy, access_policy_type: FabricPolicyAccessType
    ) -> DataAccessPolicy:
        """
        Build a Data Access Policy based on the provided policy and permission.
        This method constructs a Data Access Policy object that includes the role name,
        decision rules, and members based on the policy's catalog, schema, table, and permissions
        Args:
            policy (PolicyExport): The policy object containing catalog, schema, and table information.
            permission (PermissionType): The permission type to be applied (e.g., SELECT).
            access_policy_type (FabricPolicyAccessType): The type of access policy (e.g., READ).
        Returns:
            DataAccessPolicy: The constructed Data Access Policy object.
        """

        role_name = self.__get_fabric_role_name__(policy.name)

        table_paths = []
        for permission_scope in policy.permissionscopes:
            if (
                permission_scope.name == PermissionType.SELECT
                and permission_scope.state == PermissionState.GRANT
            ):
                table_path = self.__get_table_mapping__(
                    permission_scope.catalog,
                    permission_scope.catalog_schema,
                    permission_scope.table,
                )
                if table_path:
                    if table_path != "*":
                        table_path = f"/{table_path}"
                    table_paths.append(table_path)

        columnconstraints = []
        rowconstraints = []
        tables_with_all_columns_denied = []
        tables_with_all_rows_denied = []

        if (
            policy.columnconstraints
            and self.config.constraints
            and self.config.constraints.columns
            and self.config.constraints.columns.columnlevelsecurity
        ):
            for cc in policy.columnconstraints:
                if (
                    PermissionType.SELECT in cc.column_actions
                    and cc.column_effect == PermissionState.GRANT
                ):
                    table_path = self.__get_table_mapping__(
                        cc.catalog_name, cc.schema_name, cc.table_name
                    )
                    if table_path and table_path != "*":
                        table_path = f"/{table_path}"
                    column_names = cc.column_names
                    if not column_names:
                        tables_with_all_columns_denied.append(table_path)
                        continue

                    columnconstraints.append(
                        ColumnConstraint(
                            table_path=table_path,
                            column_names=column_names,
                            column_effect=PolicyEffectType.PERMIT,
                            column_action=[FabricPolicyAccessType.READ],
                        )
                    )

        if (
            policy.rowconstraints
            and self.config.constraints
            and self.config.constraints.rows
            and self.config.constraints.rows.rowlevelsecurity
        ):
            for rc in policy.rowconstraints:
                table_path = self.__get_table_mapping__(
                    rc.catalog_name, rc.schema_name, rc.table_name
                )
                if table_path and table_path != "*":
                    table_path = f"/{table_path}"
                if rc.filter_condition == "DENYALL":
                    tables_with_all_rows_denied.append(table_path)
                    continue
                value = self.__generate_rls_value__(
                    schema_name=rc.schema_name,
                    table_name=rc.table_name,
                    filter_condition=rc.filter_condition,
                    catalog_name=rc.catalog_name,
                )
                if value == "true":
                    continue
                if value == "false":
                    tables_with_all_rows_denied.append(table_path)
                    continue

                rowconstraints.append(RowConstraint(table_path=table_path, value=value))

        # Remove all tablepaths that have all columns denied
        table_paths = [
            tp for tp in table_paths if tp not in tables_with_all_columns_denied
        ]
        table_paths = [
            tp for tp in table_paths if tp not in tables_with_all_rows_denied
        ]

        if not table_paths:
            self.logger.warning(
                f"POLICY WEAVER - No valid table mappings found for policy {policy.name}. Skipping..."
            )
            return None

        ## Remove column constraints if there is no matching table path
        ## A constraint is valid if its table_path is in table_paths, or if "*" is in table_paths,
        ## or if a parent path of the constraint's table_path is in table_paths.
        table_paths_set = set(table_paths)
        has_wildcard = "*" in table_paths_set

        def _matches_table_paths(path: str) -> bool:
            if has_wildcard or path in table_paths_set:
                return True
            # Check if any table_path is a parent of this constraint path
            # e.g. /Tables/schema in table_paths should match /Tables/schema/table
            for tp in table_paths_set:
                if path.startswith(tp + "/"):
                    return True
            return False

        columnconstraints = [
            cc for cc in columnconstraints if _matches_table_paths(cc.table_path)
        ]
        rowconstraints = [
            rc for rc in rowconstraints if _matches_table_paths(rc.table_path)
        ]

        permission_scopes = [
            PolicyPermissionScope(
                attribute_name=PolicyAttributeType.PATH,
                attribute_value_included_in=table_paths,
            ),
            PolicyPermissionScope(
                attribute_name=PolicyAttributeType.ACTION,
                attribute_value_included_in=[access_policy_type],
            ),
        ]

        pdr = PolicyDecisionRule(
            effect=PolicyEffectType.PERMIT,
            permission=permission_scopes,
        )

        if columnconstraints or rowconstraints:
            constraints = Constraints()
            if columnconstraints:
                constraints.columns = columnconstraints
            if rowconstraints:
                constraints.rows = rowconstraints
            pdr.constraints = constraints

        dap = DataAccessPolicy(
            name=role_name,
            decision_rules=[pdr],
            members=PolicyMembers(entra_members=[]),
        )

        for o in policy.permissionobjects:
            object_id = await self.__lookup_entra_object_id__(o)
            if object_id:
                if o.type == IamType.GROUP:
                    object_type = FabricMemberObjectType.GROUP
                else:
                    object_type = (
                        FabricMemberObjectType.USER
                        if o.type == IamType.USER
                        else FabricMemberObjectType.SERVICE_PRINCIPAL
                    )

                dap.members.entra_members.append(
                    EntraMember(
                        object_id=object_id,
                        tenant_id=self.config.fabric.tenant_id,
                        object_type=object_type,
                    )
                )
            else:
                self.logger.warning(
                    f"POLICY WEAVER - {o.lookup_id} not found in Microsoft Graph. Skipping..."
                )
                if self.config.type == PolicyWeaverConnectorType.DATAVERSE and (
                    getattr(
                        getattr(self.config, "dataverse", None),
                        "strict_access_parity",
                        False,
                    )
                    or getattr(
                        getattr(self.config, "dataverse", None),
                        "partial_sync",
                        False,
                    )
                ):
                    raise PolicyWeaverError(
                        "Dataverse publication could not resolve a Fabric role "
                        "member in Microsoft Entra ID. No policies were applied."
                    )
                if self._unmapped_policy_handler:
                    self._unmapped_policy_handler(o.lookup_id, policy)
                continue

        if dap.members.entra_members == []:
            self.logger.warning(
                f"POLICY WEAVER - No valid members found for policy {policy.name}. Skipping..."
            )
            return None

        self.logger.debug(
            f"POLICY WEAVER - Data Access Policy - {dap.name}: {dap.model_dump_json(indent=4)}"
        )

        return dap

    def source_snapshot_handler(self, policy_export: PolicyExport) -> None:
        """
        Handle the source snapshot after it is generated.
        This method is called to process the source snapshot, allowing for external archival,
        logging or further processing of the snapshot.
        Args:
            policy_export (PolicyExport): The PolicyExport object containing the source snapshot data.
        """
        if self._source_snapshot_handler:
            if policy_export:
                snapshot = policy_export.model_dump_json(
                    exclude_none=True, exclude_unset=True, indent=4
                )
                self._source_snapshot_handler(snapshot)
            else:
                self._source_snapshot_handler(None)
        else:
            self.logger.debug(
                "No source snapshot handler set. Skipping snapshot processing."
            )

    def fabric_snapshot_handler(self, access_policy: DataAccessPolicy) -> None:
        """
        Handle the fabric snapshot after it is generated.
        This method is called to process the fabric snapshot, allowing for external archival,
        logging or further processing of the snapshot.
        Args:
            access_policy (DataAccessPolicy): The DataAccessPolicy object containing the fabric snapshot data.
        """
        if self._fabric_snapshot_handler:
            if access_policy:
                snapshot = access_policy.model_dump_json(
                    exclude_none=True, exclude_unset=True, indent=4
                )
                self._fabric_snapshot_handler(snapshot)
            else:
                self._fabric_snapshot_handler(None)
        else:
            self.logger.debug(
                "No fabric snapshot handler set. Skipping snapshot processing."
            )

    def unmapped_policy_handler(self, object_id: str, policy: PolicyExport) -> None:
        """
        Handle the unmapped policies after they are identified.
        This method is called to process the unmapped policies, allowing for external archival,
        logging or further processing of the unmapped policies.
        Args:
            json_unmapped_policies (str): The JSON string representation of the unmapped policies.
        """
        if self._unmapped_policy_handler:
            if object_id and policy:
                unmapped_policy = {
                    "unmapped_object_id": object_id,
                    "policy": policy.model_dump_json(
                        exclude_none=True, exclude_unset=True, indent=4
                    ),
                }
                self._unmapped_policy_handler(unmapped_policy)
            else:
                self._unmapped_policy_handler(None)
        else:
            self.logger.debug(
                "No unmapped policy handler set. Skipping unmapped policy processing."
            )

    def set_source_snaphot_handler(self, handler):
        """
        Set the source snapshot handler for the core class.
        This handler is called after the snapshot is generated to allow for
        external archival, logging or further processing of the snapshot.
        This is useful for integrating with external systems or for custom logging.
        Args:
            handler: The handler to set for processing snapshots.
            The handler should accept a single dictionary argument containing the snapshot data.
            Example: def handler(snapshot: Dict): ...
        """
        self._source_snapshot_handler = handler

    def set_fabric_snapshot_handler(self, handler):
        """
        Set the fabric snapshot handler for the core class.
        This handler is called after the fabric snapshot is generated to allow for
        external archival, logging or further processing of the snapshot.
        This is useful for integrating with external systems or for custom logging.
        Args:
            handler: The handler to set for processing fabric snapshots.
            The handler should accept a single dictionary argument containing the snapshot data.
            Example: def handler(snapshot: Dict): ...
        """
        self._fabric_snapshot_handler = handler

    def set_unmapped_policy_handler(self, handler):
        """
        Set the unmapped policy handler for the core class.
        This handler is called after unmapped policies are identified to allow for
        external archival, logging or further processing of the unmapped policies.
        This is useful for integrating with external systems or for custom logging.
        Args:
            handler: The handler to set for processing unmapped policies.
            The handler should accept a single dictionary argument containing the unmapped policy data.
            Example: def handler(unmapped_policy: Dict): ...
        """
        self._unmapped_policy_handler = handler
