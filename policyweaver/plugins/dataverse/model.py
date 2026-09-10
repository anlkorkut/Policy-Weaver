from pydantic import Field, PrivateAttr
from typing import Dict, Optional, List

from policyweaver.core.enum import IamType
from policyweaver.models.common import CommonBaseModel
from policyweaver.models.config import SourceMap


class DataverseUser(CommonBaseModel):
    """
    Represents a user in Dataverse (systemuser).
    Attributes:
        id (Optional[str]): The systemuserid.
        name (Optional[str]): The full name of the user.
        email (Optional[str]): The primary email address.
        azure_ad_object_id (Optional[str]): The Azure AD (Entra) object ID.
        is_disabled (Optional[bool]): Whether the user is disabled.
    """

    id: Optional[str] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)
    email: Optional[str] = Field(alias="email", default=None)
    azure_ad_object_id: Optional[str] = Field(alias="azure_ad_object_id", default=None)
    application_id: Optional[str] = Field(alias="application_id", default=None)
    business_unit_id: Optional[str] = Field(alias="business_unit_id", default=None)
    is_disabled: Optional[bool] = Field(alias="is_disabled", default=False)
    access_mode: Optional[int] = Field(alias="access_mode", default=None)
    is_licensed: Optional[bool] = Field(alias="is_licensed", default=None)
    azure_state: Optional[int] = Field(alias="azure_state", default=None)


class DataverseTeam(CommonBaseModel):
    """
    Represents a team in Dataverse.
    Attributes:
        id (Optional[str]): The teamid.
        name (Optional[str]): The team name.
        team_type (Optional[int]): The team type (0=Owner, 1=Access, 2=AAD Security Group, 3=AAD Office Group).
        azure_ad_object_id (Optional[str]): The Azure AD (Entra) object ID for AAD-backed teams.
        member_ids (Optional[List[str]]): List of systemuserids that are members.
    """

    id: Optional[str] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)
    team_type: Optional[int] = Field(alias="team_type", default=0)
    azure_ad_object_id: Optional[str] = Field(alias="azure_ad_object_id", default=None)
    business_unit_id: Optional[str] = Field(alias="business_unit_id", default=None)
    membership_type: Optional[int] = Field(alias="membership_type", default=0)
    member_ids: Optional[List[str]] = Field(alias="member_ids", default_factory=list)


class DataverseSecurityRole(CommonBaseModel):
    """
    Represents a security role in Dataverse.
    Attributes:
        id (Optional[str]): The roleid.
        name (Optional[str]): The role name.
    """

    id: Optional[str] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)
    business_unit_id: Optional[str] = Field(alias="business_unit_id", default=None)
    parent_root_role_id: Optional[str] = Field(
        alias="parent_root_role_id", default=None
    )
    is_inherited: Optional[int] = Field(alias="is_inherited", default=None)


class DataverseBusinessUnit(CommonBaseModel):
    """
    Represents a Dataverse business unit and its hierarchy relation.
    Attributes:
        id (Optional[str]): The businessunitid.
        name (Optional[str]): The business unit name.
        parent_business_unit_id (Optional[str]): The parent business unit ID.
    """

    id: Optional[str] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)
    parent_business_unit_id: Optional[str] = Field(
        alias="parent_business_unit_id", default=None
    )
    is_disabled: Optional[bool] = Field(alias="is_disabled", default=False)
    created_on: Optional[str] = Field(alias="created_on", default=None)
    modified_on: Optional[str] = Field(alias="modified_on", default=None)


class DataverseRolePrivilege(CommonBaseModel):
    """
    Represents a privilege within a security role.
    Attributes:
        privilege_id (Optional[str]): The privilegeid.
        role_id (Optional[str]): The ID of the security role granting this privilege.
        name (Optional[str]): The privilege name (e.g. 'prvReadaccount').
        access_right (Optional[int]): The access right bitmask.
        depth (Optional[str]): The depth/scope ('Basic', 'Local', 'Deep', 'Global').
        entity_name (Optional[str]): The logical name of the entity (table).
        can_read (Optional[bool]): Whether the privilege grants read access.
    """

    privilege_id: Optional[str] = Field(alias="privilege_id", default=None)
    role_id: Optional[str] = Field(alias="role_id", default=None)
    name: Optional[str] = Field(alias="name", default=None)
    access_right: Optional[int] = Field(alias="access_right", default=None)
    depth: Optional[str] = Field(alias="depth", default=None)
    entity_name: Optional[str] = Field(alias="entity_name", default=None)
    can_read: Optional[bool] = Field(alias="can_read", default=False)
    record_filter_id: Optional[str] = Field(alias="record_filter_id", default=None)


class DataverseFieldPermission(CommonBaseModel):
    """
    Represents a field-level security permission in Dataverse.
    Attributes:
        field_security_profile_id (Optional[str]): The profile this permission belongs to.
        field_security_profile_name (Optional[str]): The name of the profile.
        entity_name (Optional[str]): The logical name of the entity (table).
        attribute_logical_name (Optional[str]): The logical name of the field (column).
        can_read (Optional[int]): 0=Not Allowed, 4=Allowed.
    """

    field_security_profile_id: Optional[str] = Field(
        alias="field_security_profile_id", default=None
    )
    field_security_profile_name: Optional[str] = Field(
        alias="field_security_profile_name", default=None
    )
    entity_name: Optional[str] = Field(alias="entity_name", default=None)
    attribute_logical_name: Optional[str] = Field(
        alias="attribute_logical_name", default=None
    )
    can_read: Optional[int] = Field(alias="can_read", default=0)


class DataverseFieldSecurityProfile(CommonBaseModel):
    """
    Represents a field-level security profile in Dataverse.
    Attributes:
        id (Optional[str]): The fieldsecurityprofileid.
        name (Optional[str]): The profile name.
        user_ids (Optional[List[str]]): List of systemuserids assigned to this profile.
        team_ids (Optional[List[str]]): List of teamids assigned to this profile.
        permissions (Optional[List[DataverseFieldPermission]]): The field permissions in this profile.
    """

    id: Optional[str] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)
    user_ids: Optional[List[str]] = Field(alias="user_ids", default_factory=list)
    team_ids: Optional[List[str]] = Field(alias="team_ids", default_factory=list)
    permissions: Optional[List[DataverseFieldPermission]] = Field(
        alias="permissions", default_factory=list
    )


class DataverseTablePermission(CommonBaseModel):
    """
    Represents the effective read permission on a table for a principal.
    Attributes:
        table_name (Optional[str]): The logical name of the entity (table).
        principal_id (Optional[str]): The user or team ID.
        principal_type (Optional[IamType]): USER or GROUP.
        has_read (Optional[bool]): Whether read access is granted.
        depth (Optional[str]): The depth of the read privilege.
        role_name (Optional[str]): The role granting this access.
    """

    table_name: Optional[str] = Field(alias="table_name", default=None)
    principal_id: Optional[str] = Field(alias="principal_id", default=None)
    principal_type: Optional[IamType] = Field(alias="principal_type", default=None)
    principal_business_unit_id: Optional[str] = Field(
        alias="principal_business_unit_id", default=None
    )
    has_read: Optional[bool] = Field(alias="has_read", default=False)
    depth: Optional[str] = Field(alias="depth", default=None)
    role_id: Optional[str] = Field(alias="role_id", default=None)
    role_name: Optional[str] = Field(alias="role_name", default=None)
    role_business_unit_id: Optional[str] = Field(
        alias="role_business_unit_id", default=None
    )


class DataverseColumnMetadata(CommonBaseModel):
    metadata_id: Optional[str] = Field(alias="metadata_id", default=None)
    logical_name: Optional[str] = Field(alias="logical_name", default=None)
    is_secured: Optional[bool] = Field(alias="is_secured", default=False)


class DataverseTableMetadata(CommonBaseModel):
    logical_name: Optional[str] = Field(alias="logical_name", default=None)
    ownership_type: Optional[str] = Field(alias="ownership_type", default=None)
    has_secured_columns: Optional[bool] = Field(
        alias="has_secured_columns", default=False
    )
    columns: Optional[List[DataverseColumnMetadata]] = Field(
        alias="columns", default_factory=list
    )


class DataverseAttributeMaskingRule(CommonBaseModel):
    id: Optional[str] = Field(alias="id", default=None)
    entity_name: Optional[str] = Field(alias="entity_name", default=None)
    attribute_logical_name: Optional[str] = Field(
        alias="attribute_logical_name", default=None
    )
    masking_rule_id: Optional[str] = Field(alias="masking_rule_id", default=None)


class DataversePrincipalObjectAttributeAccess(CommonBaseModel):
    id: Optional[str] = Field(alias="id", default=None)
    attribute_id: Optional[str] = Field(alias="attribute_id", default=None)
    object_id: Optional[str] = Field(alias="object_id", default=None)
    object_type_code: Optional[str] = Field(alias="object_type_code", default=None)
    principal_id: Optional[str] = Field(alias="principal_id", default=None)
    principal_type: Optional[str] = Field(alias="principal_type", default=None)
    read_access: Optional[bool] = Field(alias="read_access", default=False)


class DataverseEnvironment(CommonBaseModel):
    """
    Represents the collected security metadata from a Dataverse environment.
    Attributes:
        users (Optional[List[DataverseUser]]): Active users.
        teams (Optional[List[DataverseTeam]]): Teams.
        security_roles (Optional[List[DataverseSecurityRole]]): Security roles.
        role_privileges (Optional[List[DataverseRolePrivilege]]): Privileges per role.
        user_role_assignments (Optional[dict]): Mapping of user ID to list of role IDs.
        team_role_assignments (Optional[dict]): Mapping of team ID to list of role IDs.
        field_security_profiles (Optional[List[DataverseFieldSecurityProfile]]): Field-level security.
        table_permissions (Optional[List[DataverseTablePermission]]): Resolved table-level permissions.
    """

    users: Optional[List[DataverseUser]] = Field(alias="users", default_factory=list)
    teams: Optional[List[DataverseTeam]] = Field(alias="teams", default_factory=list)
    business_units: Optional[List[DataverseBusinessUnit]] = Field(
        alias="business_units", default_factory=list
    )
    security_roles: Optional[List[DataverseSecurityRole]] = Field(
        alias="security_roles", default_factory=list
    )
    role_privileges: Optional[List[DataverseRolePrivilege]] = Field(
        alias="role_privileges", default_factory=list
    )
    user_role_assignments: Optional[dict] = Field(
        alias="user_role_assignments", default_factory=dict
    )
    team_role_assignments: Optional[dict] = Field(
        alias="team_role_assignments", default_factory=dict
    )
    field_security_profiles: Optional[List[DataverseFieldSecurityProfile]] = Field(
        alias="field_security_profiles", default_factory=list
    )
    table_permissions: Optional[List[DataverseTablePermission]] = Field(
        alias="table_permissions", default_factory=list
    )
    table_metadata: Optional[List[DataverseTableMetadata]] = Field(
        alias="table_metadata", default_factory=list
    )
    attribute_masking_rules: Optional[List[DataverseAttributeMaskingRule]] = Field(
        alias="attribute_masking_rules", default=None
    )
    principal_object_attribute_accesses: Optional[
        List[DataversePrincipalObjectAttributeAccess]
    ] = Field(alias="principal_object_attribute_accesses", default_factory=list)
    hierarchy_security_enabled: Optional[bool] = Field(
        alias="hierarchy_security_enabled", default=False
    )
    hierarchy_security_uses_position: Optional[bool] = Field(
        alias="hierarchy_security_uses_position", default=False
    )
    hierarchy_security_depth: Optional[int] = Field(
        alias="hierarchy_security_depth", default=None
    )

    _user_by_id: Dict[str, DataverseUser] = PrivateAttr(default_factory=dict)
    _team_by_id: Dict[str, DataverseTeam] = PrivateAttr(default_factory=dict)
    _business_unit_by_id: Dict[str, DataverseBusinessUnit] = PrivateAttr(
        default_factory=dict
    )
    _table_metadata_by_name: Dict[str, DataverseTableMetadata] = PrivateAttr(
        default_factory=dict
    )
    _teams_by_user_id: Dict[str, List[DataverseTeam]] = PrivateAttr(
        default_factory=dict
    )
    _indexes_ready: bool = PrivateAttr(default=False)

    def rebuild_indexes(self) -> None:
        """Rebuild lookup indexes after environment collections are populated."""
        self._user_by_id = {user.id: user for user in self.users or [] if user.id}
        self._team_by_id = {team.id: team for team in self.teams or [] if team.id}
        self._business_unit_by_id = {
            business_unit.id: business_unit
            for business_unit in self.business_units or []
            if business_unit.id
        }
        self._table_metadata_by_name = {
            metadata.logical_name.lower(): metadata
            for metadata in self.table_metadata or []
            if metadata.logical_name
        }

        teams_by_user_id: Dict[str, List[DataverseTeam]] = {}
        for team in self.teams or []:
            for user_id in team.member_ids or []:
                teams_by_user_id.setdefault(user_id, []).append(team)
        self._teams_by_user_id = teams_by_user_id
        self._indexes_ready = True

    def _ensure_indexes(self) -> None:
        if not self._indexes_ready:
            self.rebuild_indexes()

    def lookup_user_by_id(self, user_id: str) -> Optional[DataverseUser]:
        self._ensure_indexes()
        return self._user_by_id.get(user_id)

    def lookup_team_by_id(self, team_id: str) -> Optional[DataverseTeam]:
        self._ensure_indexes()
        return self._team_by_id.get(team_id)

    def get_user_teams(self, user_id: str) -> List[DataverseTeam]:
        self._ensure_indexes()
        return list(self._teams_by_user_id.get(user_id, []))

    def lookup_business_unit_by_id(
        self, business_unit_id: str
    ) -> Optional[DataverseBusinessUnit]:
        self._ensure_indexes()
        return self._business_unit_by_id.get(business_unit_id)

    def lookup_table_metadata(
        self, logical_name: str
    ) -> Optional[DataverseTableMetadata]:
        self._ensure_indexes()
        return self._table_metadata_by_name.get((logical_name or "").lower())


class DataverseSourceConfig(CommonBaseModel):
    """
    Configuration for connecting to a Dataverse environment.
    Attributes:
        environment_url (Optional[str]): The Dataverse environment URL (e.g. https://org.crm.dynamics.com).
    """

    environment_url: Optional[str] = Field(alias="environment_url", default=None)
    onelake_role_limit: Optional[int] = Field(alias="onelake_role_limit", default=250)
    row_constraint_chunk_length: Optional[int] = Field(
        alias="row_constraint_chunk_length", default=4096
    )
    strict_access_parity: Optional[bool] = Field(
        alias="strict_access_parity", default=True
    )
    partial_sync: Optional[bool] = Field(alias="partial_sync", default=False)
    column_masking_status: Optional[str] = Field(
        alias="column_masking_status", default="unverified"
    )
    poa_read_access_status: Optional[str] = Field(
        alias="poa_read_access_status", default="unverified"
    )


class DataverseSourceMap(SourceMap):
    """
    Extends SourceMap with Dataverse-specific configuration.
    Attributes:
        dataverse (Optional[DataverseSourceConfig]): The Dataverse source configuration.
    """

    dataverse: Optional[DataverseSourceConfig] = Field(alias="dataverse", default=None)
