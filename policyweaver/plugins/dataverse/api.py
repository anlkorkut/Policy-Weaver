import logging
import os
import re
import time
from typing import Dict, List, Tuple
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from policyweaver.core.auth import ServicePrincipal
from policyweaver.models.config import Source
from policyweaver.plugins.dataverse.model import (
    DataverseBusinessUnit,
    DataverseUser,
    DataverseTeam,
    DataverseSecurityRole,
    DataverseRolePrivilege,
    DataverseFieldSecurityProfile,
    DataverseFieldPermission,
    DataverseColumnMetadata,
    DataverseAttributeMaskingRule,
    DataversePrincipalObjectAttributeAccess,
    DataverseTableMetadata,
    DataverseEnvironment,
)


class DataverseAPIClient:
    """
    Dataverse API Client for fetching security metadata from Dynamics 365 / Dataverse.
    Uses the Dataverse Web API (OData v4) to retrieve users, teams, security roles,
    role privileges, field-level security profiles, and their assignments.
    """

    DEFAULT_API_VERSION = "v9.2"
    EMPTY_GUID = "00000000-0000-0000-0000-000000000000"
    READ_PRIVILEGE_PREFIX = "prvRead"
    READ_ACCESS_RIGHT = 1  # ReadAccess bit in Dataverse privilege access rights
    DEPTH_RANK = {"Basic": 1, "Local": 2, "Deep": 3, "Global": 4}

    @classmethod
    def _normalize_optional_guid(cls, value) -> str | None:
        if value is None:
            return None
        normalized = str(value)
        if normalized.casefold() == cls.EMPTY_GUID:
            return None
        return normalized

    def __init__(self):
        self.logger = logging.getLogger("POLICY_WEAVER")
        self.base_url = os.environ["DATAVERSE_ENVIRONMENT_URL"].rstrip("/")
        self.dataverse_scope = f"{self.base_url}/.default"
        self.api_version = os.getenv("DATAVERSE_API_VERSION", self.DEFAULT_API_VERSION)
        self.api_url = f"{self.base_url}/api/data/{self.api_version}"
        self.__token = None
        self.__token_expires_on = 0

        self.session = requests.Session()
        retry = Retry(
            total=5,
            connect=5,
            read=5,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(["GET"]),
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.timeout = (10, 120)

    def _get_access_token(self, force_refresh: bool = False) -> str:
        """Get a cached access token and refresh before expiry when needed."""
        refresh_window_seconds = 120
        now = int(time.time())

        if (
            force_refresh
            or not self.__token
            or now >= (self.__token_expires_on - refresh_window_seconds)
        ):
            token = ServicePrincipal.Credential.get_token(self.dataverse_scope)
            self.__token = token.token
            self.__token_expires_on = token.expires_on

        return self.__token

    def _request_get(self, url: str) -> requests.Response:
        """Issue GET with a single token-refresh retry when Dataverse returns 401."""
        response = self.session.get(url, headers=self._headers, timeout=self.timeout)
        if response.status_code == 401:
            self._get_access_token(force_refresh=True)
            response = self.session.get(
                url, headers=self._headers, timeout=self.timeout
            )
        return response

    @property
    def _headers(self) -> dict:
        token = self._get_access_token()
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "OData-MaxVersion": "4.0",
            "OData-Version": "4.0",
            "Prefer": "odata.include-annotations=*,odata.maxpagesize=5000",
        }

    def _get_paged(self, url: str) -> List[dict]:
        """Fetch all pages of an OData collection."""
        results = []
        seen_urls = set()
        api_origin = urlsplit(self.api_url)
        while url:
            page_origin = urlsplit(url)
            if (
                page_origin.scheme.lower(),
                page_origin.netloc.lower(),
            ) != (api_origin.scheme.lower(), api_origin.netloc.lower()):
                raise ValueError(
                    "Dataverse pagination link points outside the Dataverse API "
                    f"origin: {url}"
                )
            if url in seen_urls:
                raise ValueError(f"Dataverse pagination cycle detected at: {url}")
            seen_urls.add(url)

            response = self._request_get(url)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict) or "value" not in data:
                raise ValueError(
                    f"Dataverse collection response is missing a value collection: {url}"
                )
            page_values = data["value"]
            if not isinstance(page_values, list):
                raise ValueError(
                    f"Dataverse collection response has a non-list value: {url}"
                )
            results.extend(page_values)
            next_link = data.get("@odata.nextLink")
            if next_link is not None and not isinstance(next_link, str):
                raise ValueError(
                    f"Dataverse collection response has an invalid nextLink: {url}"
                )
            url = next_link
        return results

    def _get_expanded_collection(
        self, record: dict, relationship_name: str
    ) -> List[dict]:
        """Return a complete expanded relationship, including nested pages."""
        relationships = record.get(relationship_name, [])
        if relationships is None:
            relationships = []
        if not isinstance(relationships, list):
            raise ValueError(
                f"Dataverse relationship '{relationship_name}' was not a collection."
            )

        next_link = record.get(f"{relationship_name}@odata.nextLink")
        if next_link:
            relationships = [*relationships, *self._get_paged(next_link)]
        return relationships

    def get_environment_security_map(self, source: Source) -> DataverseEnvironment:
        """
        Fetches the complete security metadata for a Dataverse environment.
        Args:
            source (Source): The source configuration with table/schema filters.
        Returns:
            DataverseEnvironment: The collected security metadata.
        """
        env = DataverseEnvironment()

        self.logger.info("Fetching Dataverse hierarchy security settings...")
        hierarchy_settings = self.__get_hierarchy_security_settings__()
        env.hierarchy_security_enabled = hierarchy_settings[0]
        env.hierarchy_security_uses_position = hierarchy_settings[1]
        env.hierarchy_security_depth = hierarchy_settings[2]

        self.logger.info("Fetching Dataverse business units...")
        env.business_units = self.__get_business_units__()
        self.logger.info(f"Found {len(env.business_units)} business units.")

        self.logger.info("Fetching Dataverse users and security relationships...")
        (
            env.users,
            env.user_role_assignments,
            team_member_ids,
            profile_user_ids,
        ) = self.__get_users_and_relationships__()
        self.logger.info(f"Found {len(env.users)} active users.")

        self.logger.info("Fetching Dataverse teams and security relationships...")
        (
            env.teams,
            env.team_role_assignments,
            profile_team_ids,
        ) = self.__get_teams_and_relationships__()
        for team in env.teams:
            team.member_ids = team_member_ids.get(team.id, [])
        self.logger.info(f"Found {len(env.teams)} teams.")

        self.logger.info("Fetching security roles...")
        env.security_roles = self.__get_security_roles__()
        self.logger.info(f"Found {len(env.security_roles)} security roles.")

        self.logger.info("Fetching role privileges...")
        env.role_privileges = self.__get_role_read_privileges__(env.security_roles)
        self.logger.info(f"Found {len(env.role_privileges)} read privileges.")

        self.logger.info(
            f"Found user-role assignments for {len(env.user_role_assignments)} users."
        )

        self.logger.info(
            f"Found team-role assignments for {len(env.team_role_assignments)} teams."
        )

        self.logger.info("Fetching field-level security profiles...")
        env.field_security_profiles = self.__get_field_security_profiles__(
            profile_user_ids, profile_team_ids
        )
        self.logger.info(
            f"Found {len(env.field_security_profiles)} field security profiles."
        )

        readable_tables = {
            privilege.entity_name.lower()
            for privilege in env.role_privileges
            if privilege.can_read and privilege.entity_name
        }
        configured_tables = {
            str(table).strip().lower()
            for schema in source.schemas or []
            for table in schema.tables or []
            if table
        }
        if configured_tables:
            readable_tables.intersection_update(configured_tables)
        table_overview = self.__get_table_metadata_overview__(readable_tables)
        secured_tables = {
            table_name
            for table_name, metadata in table_overview.items()
            if metadata.has_secured_columns
        }
        detailed_metadata = {
            metadata.logical_name: metadata
            for metadata in self.__get_table_column_metadata__(
                secured_tables,
                {
                    table_name: metadata.ownership_type
                    for table_name, metadata in table_overview.items()
                },
            )
        }
        env.table_metadata = [
            detailed_metadata.get(table_name, metadata)
            for table_name, metadata in sorted(table_overview.items())
        ]
        self.logger.info(
            "Loaded column metadata for %d CLS-secured tables.",
            len(env.table_metadata),
        )

        self.logger.info("Fetching active secured-column masking assignments...")
        env.attribute_masking_rules = self.__get_attribute_masking_rules__(
            readable_tables
        )
        self.logger.info(
            "Found %d active masking assignments in the selected table scope.",
            len(env.attribute_masking_rules),
        )

        self.logger.info("Fetching record-specific field sharing (POAA)...")
        env.principal_object_attribute_accesses = (
            self.__get_principal_object_attribute_accesses__()
        )
        self.logger.info(
            "Found %d readable POAA grants.",
            len(env.principal_object_attribute_accesses),
        )

        self.logger.debug(
            "Dataverse security map counts: business_units=%d users=%d teams=%d "
            "roles=%d privileges=%d field_profiles=%d",
            len(env.business_units),
            len(env.users),
            len(env.teams),
            len(env.security_roles),
            len(env.role_privileges),
            len(env.field_security_profiles),
        )
        return env

    def __get_hierarchy_security_settings__(
        self,
    ) -> Tuple[bool, bool, int | None]:
        url = (
            f"{self.api_url}/organizations"
            "?$select=organizationid,ishierarchicalsecuritymodelenabled,"
            "usepositionhierarchy,maxdepthforhierarchicalsecuritymodel"
        )
        records = self._get_paged(url)
        if len(records) != 1:
            raise ValueError(
                "Expected exactly one Dataverse organization security record; "
                f"received {len(records)}."
            )
        record = records[0]
        if "ishierarchicalsecuritymodelenabled" not in record:
            raise ValueError(
                "Dataverse organization response omitted hierarchy security state."
            )
        return (
            bool(record["ishierarchicalsecuritymodelenabled"]),
            bool(record.get("usepositionhierarchy", False)),
            record.get("maxdepthforhierarchicalsecuritymodel"),
        )

    def __get_users_and_relationships__(
        self,
    ) -> Tuple[
        List[DataverseUser],
        Dict[str, List[str]],
        Dict[str, List[str]],
        Dict[str, List[str]],
    ]:
        """Retrieve active users with roles, teams, and field security profiles."""
        url = (
            f"{self.api_url}/systemusers"
            "?$select=systemuserid,fullname,internalemailaddress,"
            "azureactivedirectoryobjectid,applicationid,isdisabled,accessmode,"
            "islicensed,azurestate,_businessunitid_value"
            "&$expand=systemuserroles_association($select=roleid),"
            "teammembership_association($select=teamid),"
            "systemuserprofiles_association($select=fieldsecurityprofileid)"
            "&$filter=isdisabled eq false"
        )
        records = self._get_paged(url)
        users: List[DataverseUser] = []
        role_assignments: Dict[str, List[str]] = {}
        team_member_ids: Dict[str, set] = {}
        profile_user_ids: Dict[str, set] = {}

        for record in records:
            user_id = record["systemuserid"]
            users.append(
                DataverseUser(
                    id=user_id,
                    name=record.get("fullname"),
                    email=record.get("internalemailaddress", ""),
                    azure_ad_object_id=self._normalize_optional_guid(
                        record.get("azureactivedirectoryobjectid")
                    ),
                    application_id=self._normalize_optional_guid(
                        record.get("applicationid")
                    ),
                    business_unit_id=record.get("_businessunitid_value"),
                    is_disabled=record.get("isdisabled", False),
                    access_mode=record.get("accessmode", 0),
                    is_licensed=record.get("islicensed", True),
                    azure_state=record.get("azurestate"),
                )
            )

            role_ids = {
                role.get("roleid")
                for role in self._get_expanded_collection(
                    record, "systemuserroles_association"
                )
                if role.get("roleid")
            }
            if role_ids:
                role_assignments[user_id] = sorted(role_ids)

            for team in self._get_expanded_collection(
                record, "teammembership_association"
            ):
                team_id = team.get("teamid")
                if team_id:
                    team_member_ids.setdefault(team_id, set()).add(user_id)

            for profile in self._get_expanded_collection(
                record, "systemuserprofiles_association"
            ):
                profile_id = profile.get("fieldsecurityprofileid")
                if profile_id:
                    profile_user_ids.setdefault(profile_id, set()).add(user_id)

        self.logger.debug("Mapped %d active Dataverse users.", len(users))
        return (
            users,
            role_assignments,
            {team_id: sorted(ids) for team_id, ids in team_member_ids.items()},
            {profile_id: sorted(ids) for profile_id, ids in profile_user_ids.items()},
        )

    def __get_teams_and_relationships__(
        self,
    ) -> Tuple[List[DataverseTeam], Dict[str, List[str]], Dict[str, List[str]]]:
        """Retrieve teams with role and field security profile assignments."""
        url = (
            f"{self.api_url}/teams"
            "?$select=teamid,name,teamtype,membershiptype,"
            "azureactivedirectoryobjectid,_businessunitid_value"
            "&$expand=teamroles_association($select=roleid),"
            "teamprofiles_association($select=fieldsecurityprofileid)"
        )
        records = self._get_paged(url)
        teams: List[DataverseTeam] = []
        role_assignments: Dict[str, List[str]] = {}
        profile_team_ids: Dict[str, set] = {}

        for record in records:
            team_id = record["teamid"]
            teams.append(
                DataverseTeam(
                    id=team_id,
                    name=record.get("name"),
                    team_type=record.get("teamtype", 0),
                    azure_ad_object_id=self._normalize_optional_guid(
                        record.get("azureactivedirectoryobjectid")
                    ),
                    business_unit_id=record.get("_businessunitid_value"),
                    membership_type=record.get("membershiptype", 0),
                )
            )

            role_ids = {
                role.get("roleid")
                for role in self._get_expanded_collection(
                    record, "teamroles_association"
                )
                if role.get("roleid")
            }
            if role_ids:
                role_assignments[team_id] = sorted(role_ids)

            for profile in self._get_expanded_collection(
                record, "teamprofiles_association"
            ):
                profile_id = profile.get("fieldsecurityprofileid")
                if profile_id:
                    profile_team_ids.setdefault(profile_id, set()).add(team_id)

        self.logger.debug("Mapped %d Dataverse teams.", len(teams))
        return (
            teams,
            role_assignments,
            {profile_id: sorted(ids) for profile_id, ids in profile_team_ids.items()},
        )

    def __get_security_roles__(self) -> List[DataverseSecurityRole]:
        """Retrieve all published security roles (componentstate=0)."""
        url = (
            f"{self.api_url}/roles"
            "?$select=roleid,name,_businessunitid_value,_parentrootroleid_value,isinherited"
            "&$filter=componentstate eq 0"
        )
        records = self._get_paged(url)
        roles = [
            DataverseSecurityRole(
                id=r["roleid"],
                name=r.get("name"),
                business_unit_id=r.get("_businessunitid_value"),
                parent_root_role_id=r.get("_parentrootroleid_value"),
                is_inherited=r.get("isinherited"),
            )
            for r in records
        ]
        self.logger.debug("Mapped %d published Dataverse security roles.", len(roles))
        return roles

    def __get_business_units__(self) -> List[DataverseBusinessUnit]:
        """Retrieve all business units and hierarchy relations."""
        url = (
            f"{self.api_url}/businessunits"
            "?$select=businessunitid,name,_parentbusinessunitid_value,isdisabled,"
            "createdon,modifiedon"
        )
        records = self._get_paged(url)
        return [
            DataverseBusinessUnit(
                id=r.get("businessunitid"),
                name=r.get("name"),
                parent_business_unit_id=r.get("_parentbusinessunitid_value"),
                is_disabled=r.get("isdisabled", False),
                created_on=r.get("createdon"),
                modified_on=r.get("modifiedon"),
            )
            for r in records
            if r.get("businessunitid")
        ]

    def __get_role_read_privileges__(
        self, roles: List[DataverseSecurityRole]
    ) -> List[DataverseRolePrivilege]:
        """
        Retrieve role privileges and filter to only read-related privileges.
        Joins roleprivilegescollection depth assignments to the global privileges
        collection so extraction uses two paginated queries instead of one query
        per role.
        """
        # Dataverse privilegedepthmask uses bitmask values, not ordinals.
        DEPTH_MASK_MAP = {
            1: "Basic",  # User/Team 2^0
            2: "Local",  # Business Unit 2^1
            4: "Deep",  # Parent: Business Unit 2^2
            8: "Global",  # Organization 2^3
        }

        role_ids = {role.id for role in roles if role.id}
        root_role_ids = {
            role.parent_root_role_id or role.id for role in roles if role.id
        }
        depth_url = (
            f"{self.api_url}/roleprivilegescollection"
            "?$select=roleid,privilegeid,privilegedepthmask,"
            "_recordfilterid_value"
            "&$filter=componentstate eq 0"
        )
        depth_records = self._get_paged(depth_url)

        privilege_url = (
            f"{self.api_url}/privileges?$select=privilegeid,name,accessright"
        )
        privilege_records = self._get_paged(privilege_url)
        privilege_by_id = {
            privilege.get("privilegeid"): privilege
            for privilege in privilege_records
            if privilege.get("privilegeid")
        }

        depth_records_by_role: Dict[str, List[dict]] = {}
        for depth_record in depth_records:
            role_id = depth_record.get("roleid", "")
            if role_id not in role_ids and role_id not in root_role_ids:
                continue
            depth_records_by_role.setdefault(role_id, []).append(depth_record)

        all_privileges: List[DataverseRolePrivilege] = []
        for role in roles:
            if not role.id:
                continue
            privilege_source_role_id = role.parent_root_role_id or role.id
            for depth_record in depth_records_by_role.get(privilege_source_role_id, []):
                privilege_id = depth_record.get("privilegeid", "")

                privilege = privilege_by_id.get(privilege_id)
                if not privilege:
                    raise ValueError(
                        "Dataverse role privilege metadata join is incomplete. "
                        "No policies were generated."
                    )
                    continue

                privilege_name = privilege.get("name", "")
                access_right = privilege.get("accessright", 0)
                is_read = privilege_name.lower().startswith(
                    self.READ_PRIVILEGE_PREFIX.lower()
                )
                if not is_read and not (access_right & self.READ_ACCESS_RIGHT):
                    continue

                entity_name = None
                if privilege_name.lower().startswith("prvread"):
                    entity_name = privilege_name[7:].lower()

                raw_mask = depth_record.get("privilegedepthmask")
                depth = DEPTH_MASK_MAP.get(raw_mask, "Unknown")
                if depth == "Unknown":
                    self.logger.warning(
                        f"Missing or unrecognized privilegedepthmask={raw_mask} "
                        f"for role={role.id[:12]} privilege={privilege_id[:12]}. "
                        f"Treating as Unknown (fail-closed)."
                    )

                all_privileges.append(
                    DataverseRolePrivilege(
                        privilege_id=privilege_id,
                        role_id=role.id,
                        name=privilege_name,
                        access_right=access_right,
                        depth=depth,
                        entity_name=entity_name,
                        can_read=True,
                        record_filter_id=depth_record.get("_recordfilterid_value"),
                    )
                )

        return all_privileges

    def __get_field_security_profiles__(
        self,
        profile_user_ids: Dict[str, List[str]],
        profile_team_ids: Dict[str, List[str]],
    ) -> List[DataverseFieldSecurityProfile]:
        """Retrieve field profiles and join bulk permissions and assignments."""
        url = (
            f"{self.api_url}/fieldsecurityprofiles?$select=fieldsecurityprofileid,name"
        )
        records = self._get_paged(url)
        profiles = [
            DataverseFieldSecurityProfile(
                id=record["fieldsecurityprofileid"],
                name=record.get("name"),
                user_ids=profile_user_ids.get(record["fieldsecurityprofileid"], []),
                team_ids=profile_team_ids.get(record["fieldsecurityprofileid"], []),
            )
            for record in records
        ]
        profile_by_id = {profile.id: profile for profile in profiles}

        permission_url = (
            f"{self.api_url}/fieldpermissions"
            "?$select=fieldpermissionid,_fieldsecurityprofileid_value,"
            "entityname,attributelogicalname,canread"
            "&$filter=componentstate eq 0"
        )
        permission_records = self._get_paged(permission_url)
        for record in permission_records:
            profile_id = record.get("_fieldsecurityprofileid_value")
            profile = profile_by_id.get(profile_id)
            if not profile:
                continue
            profile.permissions.append(
                DataverseFieldPermission(
                    field_security_profile_id=profile_id,
                    field_security_profile_name=profile.name,
                    entity_name=record.get("entityname"),
                    attribute_logical_name=record.get("attributelogicalname"),
                    can_read=record.get("canread", 0),
                )
            )

        return profiles

    def __get_table_column_metadata__(
        self,
        table_names: set[str],
        ownership_by_table: Dict[str, str] | None = None,
    ) -> List[DataverseTableMetadata]:
        metadata = []
        for table_name in sorted(table_names):
            if not re.fullmatch(r"[A-Za-z0-9_]+", table_name):
                raise ValueError(
                    f"Invalid Dataverse table logical name in field metadata: {table_name}"
                )
            url = (
                f"{self.api_url}/EntityDefinitions(LogicalName='{table_name}')/"
                "Attributes?$select=MetadataId,LogicalName,IsSecured,IsValidForRead"
            )
            records = self._get_paged(url)
            required_fields = {
                "MetadataId",
                "LogicalName",
                "IsSecured",
                "IsValidForRead",
            }
            if any(
                not isinstance(record, dict)
                or not required_fields.issubset(record)
                or not isinstance(record["MetadataId"], str)
                or not record["MetadataId"]
                or not isinstance(record["LogicalName"], str)
                or not record["LogicalName"]
                or not isinstance(record["IsSecured"], bool)
                or not isinstance(record["IsValidForRead"], bool)
                for record in records
            ):
                raise ValueError(
                    f"Dataverse column metadata for '{table_name}' is incomplete."
                )
            columns = [
                DataverseColumnMetadata(
                    metadata_id=record.get("MetadataId"),
                    logical_name=record.get("LogicalName"),
                    is_secured=record.get("IsSecured", False),
                )
                for record in records
                if record.get("LogicalName") and record.get("IsValidForRead", True)
            ]
            if not columns:
                raise ValueError(
                    f"No readable column metadata returned for Dataverse table "
                    f"'{table_name}'."
                )
            metadata.append(
                DataverseTableMetadata(
                    logical_name=table_name,
                    ownership_type=(ownership_by_table or {}).get(table_name),
                    has_secured_columns=True,
                    columns=columns,
                )
            )
        return metadata

    def __get_table_metadata_overview__(
        self, candidates: set[str]
    ) -> Dict[str, DataverseTableMetadata]:
        if not candidates:
            return {}
        url = (
            f"{self.api_url}/EntityDefinitions?$select=LogicalName,OwnershipType&$expand="
            "Attributes($select=MetadataId,LogicalName,IsSecured,IsValidForRead;"
            "$filter=IsSecured eq true)"
        )
        metadata_by_table: Dict[str, DataverseTableMetadata] = {}
        for record in self._get_paged(url):
            logical_name = str(record.get("LogicalName") or "").lower()
            if logical_name not in candidates:
                continue
            if "Attributes" not in record:
                raise ValueError(
                    f"Dataverse table metadata for '{logical_name}' omitted the "
                    "expanded Attributes collection."
                )
            if record["Attributes"] is None:
                raise ValueError(
                    f"Dataverse table metadata for '{logical_name}' returned a null "
                    "Attributes collection."
                )
            if logical_name in metadata_by_table:
                raise ValueError(
                    f"Dataverse table metadata returned duplicate rows for "
                    f"'{logical_name}'."
                )
            secured_attributes = self._get_expanded_collection(record, "Attributes")
            required_fields = {
                "MetadataId",
                "LogicalName",
                "IsSecured",
                "IsValidForRead",
            }
            if any(
                not isinstance(attribute, dict)
                or not required_fields.issubset(attribute)
                or not isinstance(attribute["MetadataId"], str)
                or not attribute["MetadataId"]
                or not isinstance(attribute["LogicalName"], str)
                or not attribute["LogicalName"]
                or attribute["IsSecured"] is not True
                or not isinstance(attribute["IsValidForRead"], bool)
                for attribute in secured_attributes
            ):
                raise ValueError(
                    f"Dataverse table metadata for '{logical_name}' contains an "
                    "incomplete attribute record."
                )
            metadata_by_table[logical_name] = DataverseTableMetadata(
                logical_name=logical_name,
                ownership_type=record.get("OwnershipType"),
                has_secured_columns=any(
                    attribute.get("LogicalName")
                    and attribute.get("IsSecured")
                    and attribute.get("IsValidForRead", True)
                    for attribute in secured_attributes
                ),
            )
        return metadata_by_table

    def __get_secured_table_names__(self, candidates: set[str]) -> set[str]:
        return {
            table_name
            for table_name, metadata in self.__get_table_metadata_overview__(
                candidates
            ).items()
            if metadata.has_secured_columns
        }

    def __get_principal_object_attribute_accesses__(
        self,
    ) -> List[DataversePrincipalObjectAttributeAccess]:
        url = (
            f"{self.api_url}/principalobjectattributeaccessset"
            "?$select=principalobjectattributeaccessid,attributeid,"
            "readaccess,_objectid_value,"
            "_principalid_value&$filter=readaccess eq true"
        )
        return [
            DataversePrincipalObjectAttributeAccess(
                id=record.get("principalobjectattributeaccessid"),
                attribute_id=record.get("attributeid"),
                object_id=record.get("_objectid_value"),
                object_type_code=record.get(
                    "_objectid_value@Microsoft.Dynamics.CRM.lookuplogicalname"
                ),
                principal_id=record.get("_principalid_value"),
                principal_type=record.get(
                    "_principalid_value@Microsoft.Dynamics.CRM.lookuplogicalname"
                ),
                read_access=record.get("readaccess", False),
            )
            for record in self._get_paged(url)
            if record.get("readaccess")
        ]

    def __get_attribute_masking_rules__(
        self, table_names: set[str]
    ) -> List[DataverseAttributeMaskingRule]:
        if not table_names:
            return []
        url = (
            f"{self.api_url}/attributemaskingrules"
            "?$select=attributemaskingruleid,entityname,attributelogicalname,"
            "_maskingruleid_value&$filter=componentstate eq 0"
        )
        records = self._get_paged(url)
        required_fields = {
            "attributemaskingruleid",
            "entityname",
            "attributelogicalname",
            "_maskingruleid_value",
        }
        if any(
            not isinstance(record, dict)
            or not required_fields.issubset(record)
            or not all(record.get(field) for field in required_fields)
            for record in records
        ):
            raise ValueError("Dataverse masking assignment metadata is incomplete.")
        selected_tables = {table_name.casefold() for table_name in table_names}
        return [
            DataverseAttributeMaskingRule(
                id=record["attributemaskingruleid"],
                entity_name=record["entityname"],
                attribute_logical_name=record["attributelogicalname"],
                masking_rule_id=record["_maskingruleid_value"],
            )
            for record in records
            if record["entityname"].casefold() in selected_tables
        ]

    def __build_role_entity_map__(
        self,
        role_privileges: List[DataverseRolePrivilege],
        security_roles: List[DataverseSecurityRole],
    ) -> Dict[str, tuple]:
        """
        Build a map from role_id -> (role_name, {entity_name: depth}).
        Uses the role_id stored on each privilege to correctly associate
        privileges with their parent security role.
        """
        role_name_map = {r.id: r.name for r in security_roles}
        role_business_unit_map = {r.id: r.business_unit_id for r in security_roles}
        role_entity_map: Dict[str, tuple] = {}

        for priv in role_privileges:
            if not priv.role_id or not priv.entity_name or not priv.can_read:
                continue
            if priv.role_id not in role_entity_map:
                role_name = role_name_map.get(priv.role_id, "UnknownRole")
                role_business_unit_id = role_business_unit_map.get(priv.role_id)
                role_entity_map[priv.role_id] = (role_name, role_business_unit_id, {})
            current_depth = role_entity_map[priv.role_id][2].get(priv.entity_name)
            candidate_depth = (priv.depth or "Unknown").title()

            if not current_depth:
                role_entity_map[priv.role_id][2][priv.entity_name] = candidate_depth
                continue

            if self.DEPTH_RANK.get(candidate_depth, 0) >= self.DEPTH_RANK.get(
                current_depth,
                0,
            ):
                role_entity_map[priv.role_id][2][priv.entity_name] = candidate_depth

        return role_entity_map
