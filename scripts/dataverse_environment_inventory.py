"""Produce a read-only, aggregate Dataverse security inventory.

The report intentionally excludes user names, emails, object IDs, role names, and
configuration secrets. It is suitable for comparing a test environment with a
larger customer estate before creating representative security fixtures.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import mean
from typing import Any

from policyweaver.core.auth import ServicePrincipal
from policyweaver.core.conf import Configuration
from policyweaver.models.config import ColumnConstraintsConfig, ConstraintsConfig
from policyweaver.models.export import RolePolicyExport
from policyweaver.plugins.dataverse.api import DataverseAPIClient
from policyweaver.plugins.dataverse.client import DataversePolicyWeaver
from policyweaver.plugins.dataverse.model import (
    DataverseEnvironment,
    DataverseSourceMap,
)


DEPTH_RANK = DataverseAPIClient.DEPTH_RANK
DEPTHS = ("Basic", "Local", "Deep", "Global", "Unknown")
TEAM_TYPES = {
    0: "owner",
    1: "access",
    2: "aad_security_group",
    3: "aad_office_group",
}


def _markdown_text(value: Any, fallback: str = "-") -> str:
    text = str(value).strip() if value is not None else ""
    if not text:
        return fallback
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _numbered_markdown_cell(values: list[str]) -> str:
    unique_values = sorted({_markdown_text(value) for value in values if value})
    if not unique_values:
        return "-"
    return "<br>".join(
        f"{index}. {value}" for index, value in enumerate(unique_values, start=1)
    )


def _parse_dataverse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def build_markdown_inventory(
    environment: DataverseEnvironment,
    source_label: str,
    generated_at: datetime | None = None,
) -> str:
    """Render a detailed, numbered review inventory from a live Dataverse snapshot."""
    generated_at = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    business_units = environment.business_units or []
    users = environment.users or []
    roles = environment.security_roles or []
    teams = environment.teams or []

    business_unit_by_id = {
        business_unit.id: business_unit
        for business_unit in business_units
        if business_unit.id
    }
    role_by_id = {role.id: role for role in roles if role.id}
    team_by_id = {team.id: team for team in teams if team.id}
    business_unit_depths = _business_unit_depths(environment)
    effective_role_tables = _effective_role_tables(environment)

    users_by_business_unit: dict[str, set[str]] = defaultdict(set)
    teams_by_business_unit: dict[str, set[str]] = defaultdict(set)
    roles_by_business_unit: dict[str, set[str]] = defaultdict(set)
    teams_by_user: dict[str, set[str]] = defaultdict(set)
    direct_users_by_role: dict[str, set[str]] = defaultdict(set)
    assigned_teams_by_role: dict[str, set[str]] = defaultdict(set)
    effective_users_by_role: dict[str, set[str]] = defaultdict(set)

    for user in users:
        if user.id and user.business_unit_id:
            users_by_business_unit[user.business_unit_id].add(user.id)
    for team in teams:
        if team.id and team.business_unit_id:
            teams_by_business_unit[team.business_unit_id].add(team.id)
        for user_id in team.member_ids or []:
            if team.id:
                teams_by_user[user_id].add(team.id)
    for role in roles:
        if role.id and role.business_unit_id:
            roles_by_business_unit[role.business_unit_id].add(role.id)
    for user_id, role_ids in (environment.user_role_assignments or {}).items():
        for role_id in set(role_ids or []):
            direct_users_by_role[role_id].add(user_id)
            effective_users_by_role[role_id].add(user_id)
    for team_id, role_ids in (environment.team_role_assignments or {}).items():
        team = team_by_id.get(team_id)
        for role_id in set(role_ids or []):
            assigned_teams_by_role[role_id].add(team_id)
            if team:
                effective_users_by_role[role_id].update(team.member_ids or [])

    def business_unit_name(business_unit_id: str | None) -> str:
        business_unit = business_unit_by_id.get(business_unit_id)
        return business_unit.name if business_unit and business_unit.name else "Unknown"

    def role_label(role_id: str) -> str:
        role = role_by_id.get(role_id)
        if not role:
            return f"Unknown role [{role_id}]"
        return (
            f"{role.name or 'Unnamed role'} "
            f"[BU: {business_unit_name(role.business_unit_id)}; ID: {role.id}]"
        )

    sorted_business_units = sorted(
        business_units,
        key=lambda item: (
            business_unit_depths.get(item.id, 0),
            (item.name or "").casefold(),
            item.id or "",
        ),
    )
    sorted_users = sorted(
        users,
        key=lambda item: (
            business_unit_name(item.business_unit_id).casefold(),
            (item.name or "").casefold(),
            item.id or "",
        ),
    )
    sorted_roles = sorted(
        roles,
        key=lambda item: (
            business_unit_name(item.business_unit_id).casefold(),
            (item.name or "").casefold(),
            item.id or "",
        ),
    )
    recent_cutoff = generated_at - timedelta(hours=48)
    recent_business_units = [
        business_unit
        for business_unit in sorted_business_units
        if (created_on := _parse_dataverse_datetime(business_unit.created_on))
        and recent_cutoff <= created_on <= generated_at
    ]
    direct_assignment_count = sum(
        len(set(role_ids or []))
        for role_ids in (environment.user_role_assignments or {}).values()
    )
    team_assignment_count = sum(
        len(set(role_ids or []))
        for role_ids in (environment.team_role_assignments or {}).values()
    )
    unique_role_names = len({role.name for role in roles if role.name})

    lines = [
        "# Dataverse business unit, user, and security role inventory",
        "",
        "## 1. Summary",
        "",
        f"1. **Generated (UTC):** {generated_at.isoformat()}",
        f"2. **Dataverse environment:** {_markdown_text(source_label)}",
        f"3. **Business units:** {len(business_units)}",
        f"4. **Business units created in the last 48 hours:** {len(recent_business_units)}",
        f"5. **Active users:** {len(users)}",
        f"6. **Published security role instances:** {len(roles)}",
        f"7. **Unique security role names:** {unique_role_names}",
        f"8. **Direct user-role assignment edges:** {direct_assignment_count}",
        f"9. **Team-role assignment edges:** {team_assignment_count}",
        f"10. **Teams:** {len(teams)}",
        "",
        "## 2. Business units",
        "",
        "| # | Business unit | Status | Parent | Depth | Created (UTC) | Modified (UTC) | Active users | Published role instances | Teams | Business unit ID |",
        "|---:|---|---|---|---:|---|---|---:|---:|---:|---|",
    ]
    for index, business_unit in enumerate(sorted_business_units, start=1):
        lines.append(
            "| "
            + " | ".join(
                [
                    str(index),
                    _markdown_text(business_unit.name, "Unnamed business unit"),
                    "Disabled" if business_unit.is_disabled else "Active",
                    _markdown_text(
                        business_unit_name(business_unit.parent_business_unit_id)
                        if business_unit.parent_business_unit_id
                        else "Root"
                    ),
                    str(business_unit_depths.get(business_unit.id, 0)),
                    _markdown_text(business_unit.created_on),
                    _markdown_text(business_unit.modified_on),
                    str(len(users_by_business_unit.get(business_unit.id, set()))),
                    str(len(roles_by_business_unit.get(business_unit.id, set()))),
                    str(len(teams_by_business_unit.get(business_unit.id, set()))),
                    _markdown_text(business_unit.id),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "### 2.1 Business units created in the last 48 hours",
            "",
        ]
    )
    if recent_business_units:
        for index, business_unit in enumerate(recent_business_units, start=1):
            lines.append(
                f"{index}. **{_markdown_text(business_unit.name)}** - "
                f"created {_markdown_text(business_unit.created_on)}; "
                f"parent: {_markdown_text(business_unit_name(business_unit.parent_business_unit_id) if business_unit.parent_business_unit_id else 'Root')}; "
                f"ID: `{_markdown_text(business_unit.id)}`"
            )
    else:
        lines.append(
            "1. No business unit in the snapshot has a creation timestamp within the last 48 hours."
        )

    lines.extend(
        [
            "",
            "## 3. Active users",
            "",
            "| # | User | Type | Business unit | Email | License | Access mode | Azure state | Direct roles | Team-derived roles | Teams | System user ID | Entra object ID | Application ID |",
            "|---:|---|---|---|---|---|---:|---:|---|---|---|---|---|---|",
        ]
    )
    for index, user in enumerate(sorted_users, start=1):
        direct_role_ids = set(
            (environment.user_role_assignments or {}).get(user.id, []) or []
        )
        user_team_ids = teams_by_user.get(user.id, set())
        team_role_labels = [
            f"{role_label(role_id)} via {team_by_id[team_id].name or team_id}"
            for team_id in user_team_ids
            if team_id in team_by_id
            for role_id in (environment.team_role_assignments or {}).get(team_id, [])
        ]
        lines.append(
            "| "
            + " | ".join(
                [
                    str(index),
                    _markdown_text(user.name, "Unnamed user"),
                    "Application" if user.application_id else "User",
                    _markdown_text(business_unit_name(user.business_unit_id)),
                    _markdown_text(user.email),
                    "Licensed" if user.is_licensed else "Unlicensed",
                    _markdown_text(user.access_mode),
                    _markdown_text(user.azure_state),
                    _numbered_markdown_cell(
                        [role_label(role_id) for role_id in direct_role_ids]
                    ),
                    _numbered_markdown_cell(team_role_labels),
                    _numbered_markdown_cell(
                        [
                            team_by_id[team_id].name or team_id
                            for team_id in user_team_ids
                            if team_id in team_by_id
                        ]
                    ),
                    _markdown_text(user.id),
                    _markdown_text(user.azure_ad_object_id),
                    _markdown_text(user.application_id),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## 4. Published security role instances",
            "",
            "| # | Security role | Business unit | Inheritance value | Direct users | Assigned teams | Effective users | Read tables | Effective read depths | Role ID | Parent root role ID |",
            "|---:|---|---|---:|---:|---:|---:|---:|---|---|---|",
        ]
    )
    for index, role in enumerate(sorted_roles, start=1):
        depth_counts = Counter(effective_role_tables.get(role.id, {}).values())
        depth_summary = ", ".join(
            f"{depth}: {depth_counts[depth]}" for depth in DEPTHS if depth_counts[depth]
        )
        lines.append(
            "| "
            + " | ".join(
                [
                    str(index),
                    _markdown_text(role.name, "Unnamed role"),
                    _markdown_text(business_unit_name(role.business_unit_id)),
                    _markdown_text(role.is_inherited),
                    str(len(direct_users_by_role.get(role.id, set()))),
                    str(len(assigned_teams_by_role.get(role.id, set()))),
                    str(len(effective_users_by_role.get(role.id, set()))),
                    str(len(effective_role_tables.get(role.id, {}))),
                    _markdown_text(depth_summary),
                    _markdown_text(role.id),
                    _markdown_text(role.parent_root_role_id),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## 5. Review notes",
            "",
            "1. Users are limited to active Dataverse `systemuser` records because that is the connector's mapping scope.",
            "2. Security roles are published role instances (`componentstate = 0`); the same role name may appear once per business unit.",
            "3. Direct roles and team-derived roles are listed separately so overlapping access paths remain visible.",
            "4. Effective user counts for a role are the union of direct users and current members of teams assigned that role.",
            "5. This is a read-only inventory. It does not apply, remove, or change Dataverse or Fabric security.",
            "",
        ]
    )
    return "\n".join(lines)


def build_entitlement_fingerprint_summary(
    export: RolePolicyExport,
    environment: DataverseEnvironment | None = None,
) -> dict[str, Any]:
    """Summarize cumulative compiled access without exposing principal IDs."""
    access_by_principal: dict[str, dict[tuple[str, str, str], dict[str, Any]]] = {}

    for policy in export.policies or []:
        members = {
            permission_object.entra_object_id
            or permission_object.id
            or permission_object.app_id
            for permission_object in policy.permissionobjects or []
        }
        members.discard(None)
        if not members:
            continue

        for scope in policy.permissionscopes or []:
            if scope.name != "SELECT" or scope.state != "GRANT":
                continue
            table_key = (scope.catalog or "", scope.catalog_schema or "", scope.table)
            matching_rows = [
                constraint
                for constraint in policy.rowconstraints or []
                if constraint.table_name == scope.table
                and constraint.schema_name == scope.catalog_schema
            ]
            row_values = {
                (constraint.filter_condition or "").strip()
                for constraint in matching_rows
            }
            row_values.discard("")
            row_denied = bool(row_values) and all(
                value.casefold() in {"false", "denyall"} for value in row_values
            )
            if row_denied:
                continue
            row_unrestricted = not matching_rows or any(
                value.casefold() == "true" for value in row_values
            )
            row_values = {
                value
                for value in row_values
                if value.casefold() not in {"true", "false", "denyall"}
            }

            matching_columns = [
                constraint
                for constraint in policy.columnconstraints or []
                if constraint.table_name == scope.table
                and constraint.schema_name == scope.catalog_schema
            ]
            column_values = {
                column_name
                for constraint in matching_columns
                for column_name in constraint.column_names or []
            }
            if matching_columns and not column_values:
                continue
            column_unrestricted = not matching_columns or "*" in column_values
            column_values.discard("*")

            for member_id in members:
                table_access = access_by_principal.setdefault(member_id, {}).setdefault(
                    table_key,
                    {
                        "row_unrestricted": False,
                        "rows": set(),
                        "column_unrestricted": False,
                        "columns": set(),
                    },
                )
                table_access["row_unrestricted"] |= row_unrestricted
                table_access["rows"].update(row_values)
                table_access["column_unrestricted"] |= column_unrestricted
                table_access["columns"].update(column_values)

    compiled_signatures: dict[str, tuple] = {}
    for principal_id, tables in access_by_principal.items():
        compiled_signatures[principal_id] = tuple(
            sorted(
                (
                    table_key,
                    "*"
                    if access["row_unrestricted"]
                    else tuple(sorted(access["rows"])),
                    "*"
                    if access["column_unrestricted"]
                    else tuple(sorted(access["columns"])),
                )
                for table_key, access in tables.items()
            )
        )

    if environment is None:
        eligible_principal_ids = set(compiled_signatures)
    else:
        eligible_principal_ids = {
            user.azure_ad_object_id or user.application_id
            for user in environment.users or []
            if not user.is_disabled
            and user.azure_state in {None, 0}
            and user.access_mode in {0, 4}
            and (user.access_mode != 0 or user.is_licensed is not False)
            and (user.azure_ad_object_id or user.application_id)
        }

    access_signature_counts = Counter(
        compiled_signatures[principal_id]
        for principal_id in eligible_principal_ids.intersection(compiled_signatures)
    )
    principals_with_access = sum(access_signature_counts.values())
    principals_without_access = len(eligible_principal_ids) - principals_with_access
    unique_including_no_access = len(access_signature_counts) + bool(
        principals_without_access
    )

    return {
        "eligible_principals": len(eligible_principal_ids),
        "principals_with_compiled_access": principals_with_access,
        "eligible_principals_without_compiled_access": principals_without_access,
        "unique_fingerprints_with_access": len(access_signature_counts),
        "unique_fingerprints_including_no_access": unique_including_no_access,
        "largest_access_cohort": max(access_signature_counts.values(), default=0),
        "exact_dataverse_parity_proven": False,
    }


def _distribution(values: list[int]) -> dict[str, float | int]:
    if not values:
        return {"minimum": 0, "maximum": 0, "average": 0.0}
    return {
        "minimum": min(values),
        "maximum": max(values),
        "average": round(mean(values), 2),
    }


def _business_unit_depths(environment: DataverseEnvironment) -> dict[str, int]:
    parent_by_id = {
        business_unit.id: business_unit.parent_business_unit_id
        for business_unit in environment.business_units or []
        if business_unit.id
    }
    depths: dict[str, int] = {}
    for business_unit_id in parent_by_id:
        seen: set[str] = set()
        current_id = business_unit_id
        depth = 0
        while parent_by_id.get(current_id):
            if current_id in seen:
                depth = -1
                break
            seen.add(current_id)
            current_id = parent_by_id[current_id]
            depth += 1
        depths[business_unit_id] = depth
    return depths


def _descendants_by_business_unit(
    environment: DataverseEnvironment,
) -> dict[str, set[str]]:
    children_by_parent: dict[str, list[str]] = defaultdict(list)
    for business_unit in environment.business_units or []:
        if business_unit.id and business_unit.parent_business_unit_id:
            children_by_parent[business_unit.parent_business_unit_id].append(
                business_unit.id
            )

    result: dict[str, set[str]] = {}
    for business_unit in environment.business_units or []:
        if not business_unit.id:
            continue
        descendants: set[str] = set()
        stack = [business_unit.id]
        while stack:
            current_id = stack.pop()
            if current_id in descendants:
                continue
            descendants.add(current_id)
            stack.extend(children_by_parent.get(current_id, []))
        result[business_unit.id] = descendants
    return result


def _effective_role_tables(
    environment: DataverseEnvironment,
) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = defaultdict(dict)
    for privilege in environment.role_privileges or []:
        if not privilege.role_id or not privilege.entity_name or not privilege.can_read:
            continue
        candidate_depth = (privilege.depth or "Unknown").title()
        current_depth = result[privilege.role_id].get(privilege.entity_name)
        if current_depth is None or DEPTH_RANK.get(
            candidate_depth, 0
        ) >= DEPTH_RANK.get(current_depth, 0):
            result[privilege.role_id][privilege.entity_name] = candidate_depth
    return result


def _deep_predicate_summary(
    environment: DataverseEnvironment,
    effective_role_tables: dict[str, dict[str, str]],
) -> dict[str, int]:
    role_business_unit = {
        role.id: role.business_unit_id
        for role in environment.security_roles or []
        if role.id
    }
    descendants_by_bu = _descendants_by_business_unit(environment)
    maximum_characters = 0
    maximum_business_units = 0
    deep_role_table_count = 0

    for role_id, table_depths in effective_role_tables.items():
        business_unit_id = role_business_unit.get(role_id)
        values = sorted(descendants_by_bu.get(business_unit_id, set()))
        for table_name, depth in table_depths.items():
            if depth != "Deep":
                continue
            deep_role_table_count += 1
            quoted_values = ",".join(f"'{value}'" for value in values)
            predicate = (
                f"SELECT * FROM dbo.{table_name} WHERE "
                f"owningbusinessunit in ({quoted_values})"
            )
            maximum_characters = max(maximum_characters, len(predicate))
            maximum_business_units = max(maximum_business_units, len(values))

    return {
        "effective_deep_role_table_entries": deep_role_table_count,
        "maximum_descendant_business_units": maximum_business_units,
        "maximum_generated_sql_characters": maximum_characters,
    }


def build_inventory(environment: DataverseEnvironment) -> dict[str, Any]:
    users = environment.users or []
    teams = environment.teams or []
    roles = environment.security_roles or []
    business_units = environment.business_units or []
    profiles = environment.field_security_profiles or []

    user_role_counts = [
        len(set((environment.user_role_assignments or {}).get(user.id, [])))
        for user in users
        if user.id
    ]
    team_role_counts = [
        len(set((environment.team_role_assignments or {}).get(team.id, [])))
        for team in teams
        if team.id
    ]
    team_member_counts = [len(set(team.member_ids or [])) for team in teams]

    def has_eligible_entra_identity(user) -> bool:
        if user.is_disabled or user.azure_state not in {None, 0}:
            return False
        if user.application_id:
            return True
        if not user.azure_ad_object_id:
            return False
        if user.access_mode in {1, 3, 5}:
            return False
        return user.is_licensed is not False or user.access_mode == 4

    effective_role_tables = _effective_role_tables(environment)
    effective_depth_counts = Counter(
        depth
        for table_depths in effective_role_tables.values()
        for depth in table_depths.values()
    )
    raw_depth_counts = Counter(
        (privilege.depth or "Unknown").title()
        for privilege in environment.role_privileges or []
    )

    role_names = [role.name for role in roles if role.name]
    role_name_counts = Counter(role_names)
    business_unit_depths = _business_unit_depths(environment)
    field_permissions = [
        permission for profile in profiles for permission in profile.permissions or []
    ]

    users_in_teams = {
        user_id for team in teams for user_id in set(team.member_ids or [])
    }
    assigned_role_ids = {
        role_id
        for role_ids in (environment.user_role_assignments or {}).values()
        for role_id in role_ids or []
    }.union(
        {
            role_id
            for role_ids in (environment.team_role_assignments or {}).values()
            for role_id in role_ids or []
        }
    )
    role_by_id = {role.id: role for role in roles if role.id}
    missing_assigned_role_ids = assigned_role_ids.difference(role_by_id)
    team_assigned_role_ids = {
        role_id
        for role_ids in (environment.team_role_assignments or {}).values()
        for role_id in role_ids or []
    }
    poaa_read_grants = [
        access
        for access in environment.principal_object_attribute_accesses or []
        if access.read_access
    ]
    record_filter_privileges = [
        privilege
        for privilege in environment.role_privileges or []
        if privilege.can_read and privilege.record_filter_id
    ]
    unknown_depth_privileges = [
        privilege
        for privilege in environment.role_privileges or []
        if privilege.can_read
        and privilege.entity_name
        and (privilege.depth or "Unknown").title() not in DEPTH_RANK
    ]
    readable_table_names = {
        privilege.entity_name.lower()
        for privilege in environment.role_privileges or []
        if privilege.can_read and privilege.entity_name
    }
    table_metadata_by_name = {
        metadata.logical_name.lower(): metadata
        for metadata in environment.table_metadata or []
        if metadata.logical_name
    }

    return {
        "users": {
            "active": len(users),
            "with_entra_object_id": sum(
                bool(user.azure_ad_object_id) for user in users
            ),
            "without_entra_object_id": sum(
                not bool(user.azure_ad_object_id) for user in users
            ),
            "with_direct_roles": sum(count > 0 for count in user_role_counts),
            "with_direct_roles_and_eligible_entra_identity": sum(
                bool((environment.user_role_assignments or {}).get(user.id))
                and has_eligible_entra_identity(user)
                for user in users
            ),
            "with_direct_roles_without_eligible_entra_identity": sum(
                bool((environment.user_role_assignments or {}).get(user.id))
                and not has_eligible_entra_identity(user)
                for user in users
            ),
            "direct_user_role_assignments": sum(user_role_counts),
            "direct_roles_per_user": _distribution(user_role_counts),
            "members_of_any_team": len(users_in_teams),
            "application_users": sum(bool(user.application_id) for user in users),
            "administrative_support_or_delegated": sum(
                user.access_mode in {1, 3, 5} for user in users
            ),
            "unlicensed_interactive": sum(
                user.is_licensed is False
                and user.access_mode != 4
                and not user.application_id
                for user in users
            ),
            "soft_or_hard_deleted_in_entra": sum(
                user.azure_state not in {None, 0} for user in users
            ),
        },
        "teams": {
            "total": len(teams),
            "by_type": dict(
                sorted(
                    Counter(
                        TEAM_TYPES.get(team.team_type, f"other_{team.team_type}")
                        for team in teams
                    ).items()
                )
            ),
            "with_entra_object_id": sum(
                bool(team.azure_ad_object_id) for team in teams
            ),
            "with_roles": sum(count > 0 for count in team_role_counts),
            "team_role_assignments": sum(team_role_counts),
            "roles_per_team": _distribution(team_role_counts),
            "membership_edges": sum(team_member_counts),
            "members_per_team": _distribution(team_member_counts),
            "role_assigned_entra_group_teams": sum(
                team.team_type in {2, 3}
                and bool((environment.team_role_assignments or {}).get(team.id))
                for team in teams
            ),
            "field_profile_assigned_entra_group_teams": sum(
                team.team_type in {2, 3}
                and any(team.id in (profile.team_ids or []) for profile in profiles)
                for team in teams
            ),
        },
        "business_units": {
            "active": len(business_units),
            "roots": sum(
                not bool(business_unit.parent_business_unit_id)
                for business_unit in business_units
            ),
            "maximum_hierarchy_depth": max(business_unit_depths.values(), default=0),
            "cycles_detected": sum(
                depth < 0 for depth in business_unit_depths.values()
            ),
            "orphaned_parent_references": sum(
                bool(business_unit.parent_business_unit_id)
                and business_unit.parent_business_unit_id
                not in {unit.id for unit in business_units if unit.id}
                for business_unit in business_units
            ),
            "hierarchy_security_enabled": bool(environment.hierarchy_security_enabled),
            "hierarchy_security_model": (
                "position"
                if environment.hierarchy_security_enabled
                and environment.hierarchy_security_uses_position
                else "manager"
                if environment.hierarchy_security_enabled
                else "disabled"
            ),
            "hierarchy_security_depth": environment.hierarchy_security_depth,
        },
        "security_roles": {
            "role_instances": len(roles),
            "unique_role_names": len(role_name_counts),
            "duplicated_role_name_groups": sum(
                count > 1 for count in role_name_counts.values()
            ),
            "maximum_instances_for_one_name": max(role_name_counts.values(), default=0),
            "assigned_role_instances": len(assigned_role_ids),
            "instances_with_read_privileges": len(effective_role_tables),
            "team_assigned_roles_with_unknown_inheritance": sum(
                role_by_id.get(role_id) is None
                or role_by_id[role_id].is_inherited not in {0, 1}
                for role_id in team_assigned_role_ids
            ),
            "missing_assigned_role_references": len(missing_assigned_role_ids),
        },
        "read_privileges": {
            "raw_role_privilege_entries": len(environment.role_privileges or []),
            "unique_privilege_ids": len(
                {
                    privilege.privilege_id
                    for privilege in environment.role_privileges or []
                    if privilege.privilege_id
                }
            ),
            "unique_target_tables": len(
                {
                    privilege.entity_name
                    for privilege in environment.role_privileges or []
                    if privilege.entity_name
                }
            ),
            "effective_role_table_entries": sum(
                len(table_depths) for table_depths in effective_role_tables.values()
            ),
            "raw_depth_distribution": {
                depth: raw_depth_counts.get(depth, 0) for depth in DEPTHS
            },
            "effective_depth_distribution": {
                depth: effective_depth_counts.get(depth, 0) for depth in DEPTHS
            },
            "unknown_depth_entries": len(unknown_depth_privileges),
            "record_filter_entries": len(record_filter_privileges),
        },
        "field_security": {
            "profiles": len(profiles),
            "permission_entries": len(field_permissions),
            "read_allowed_entries": sum(
                permission.can_read == 4 for permission in field_permissions
            ),
            "secured_tables": len(
                {
                    permission.entity_name
                    for permission in field_permissions
                    if permission.entity_name
                }
            ),
            "secured_columns": len(
                {
                    (permission.entity_name, permission.attribute_logical_name)
                    for permission in field_permissions
                    if permission.entity_name and permission.attribute_logical_name
                }
            ),
            "direct_user_assignments": sum(
                len(profile.user_ids or []) for profile in profiles
            ),
            "team_assignments": sum(
                len(profile.team_ids or []) for profile in profiles
            ),
            "metadata_tables": len(environment.table_metadata or []),
            "poaa_read_grants": len(poaa_read_grants),
        },
        "table_ownership": {
            "readable_tables": len(readable_table_names),
            "tables_with_metadata": len(
                readable_table_names.intersection(table_metadata_by_name)
            ),
            "tables_missing_metadata": len(
                readable_table_names.difference(table_metadata_by_name)
            ),
            "ownership_type_distribution": dict(
                sorted(
                    Counter(
                        table_metadata_by_name[table_name].ownership_type or "Unknown"
                        for table_name in readable_table_names.intersection(
                            table_metadata_by_name
                        )
                    ).items()
                )
            ),
        },
        "deep_predicates": _deep_predicate_summary(environment, effective_role_tables),
    }


def compile_policy_summary(
    config: DataverseSourceMap, environment: DataverseEnvironment
) -> dict[str, Any]:
    """Compile policies in memory without calling the Fabric API."""
    weaver = DataversePolicyWeaver(config)
    weaver.environment = environment
    try:
        weaver.__validate_security_coverage__()
        export = weaver.__build_role_based_export__()
    except ValueError as error:
        message = str(error).lower()
        if "onelake_role_limit" in message:
            category = "role_capacity_exceeded"
        elif "rls/cls" in message:
            category = "unsupported_rls_cls_composition"
        elif "unresolvable entra" in message:
            category = "unresolvable_entra_identities"
        elif "recordfilter" in message:
            category = "unsupported_record_filter"
        elif "poaa" in message:
            category = "unsupported_poaa"
        elif "poa" in message:
            category = "unverified_poa"
        elif "hierarchy security" in message:
            category = "unsupported_hierarchy_security"
        elif "group-team" in message:
            category = "unverified_group_team_membership"
        elif "constraint" in message:
            category = "constraint_validation_failed"
        else:
            category = "mapping_validation_failed"
        return {
            "status": "failed",
            "category": category,
            "exception_type": type(error).__name__,
            "strict_access_parity": config.dataverse.strict_access_parity,
        }

    policies = export.policies if export and export.policies else []
    row_constraints = [
        constraint for policy in policies for constraint in policy.rowconstraints or []
    ]
    column_constraints = [
        constraint
        for policy in policies
        for constraint in policy.columnconstraints or []
    ]
    full_row_rule_lengths = [
        len(
            f"SELECT * FROM {constraint.schema_name}.{constraint.table_name} "
            f"WHERE {constraint.filter_condition}"
        )
        for constraint in row_constraints
    ]
    members_per_policy = [len(policy.permissionobjects or []) for policy in policies]

    return {
        "status": "success",
        "strict_access_parity": config.dataverse.strict_access_parity,
        "generated_policies": len(policies),
        "permission_scopes": sum(
            len(policy.permissionscopes or []) for policy in policies
        ),
        "row_constraints": len(row_constraints),
        "column_constraints": len(column_constraints),
        "members_per_policy": _distribution(members_per_policy),
        "maximum_generated_row_rule_characters": max(full_row_rule_lengths, default=0),
        "row_rules_above_1000_probe_point": sum(
            length > 1000 for length in full_row_rule_lengths
        ),
        "row_rules_above_4096_probe_point": sum(
            length > 4096 for length in full_row_rule_lengths
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create an aggregate, read-only Dataverse security inventory."
    )
    parser.add_argument("--config", default="configdataverse.yaml")
    parser.add_argument("--output", help="Optional JSON output path.")
    parser.add_argument(
        "--markdown-output",
        help="Optional detailed Markdown output path with numbered BUs, users, and roles.",
    )
    parser.add_argument(
        "--compile-policies",
        action="store_true",
        help="Compile policies in memory without applying them to Fabric.",
    )
    parser.add_argument(
        "--compile-without-cls",
        action="store_true",
        help="Compile an in-memory RLS-only diagnostic scenario.",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level))

    config = DataverseSourceMap.from_yaml(args.config)
    Configuration.configure_environment(config)
    if not config.service_principal:
        raise ValueError("service_principal configuration is required")
    if not config.dataverse or not config.dataverse.environment_url:
        raise ValueError("dataverse.environment_url configuration is required")

    ServicePrincipal.initialize(
        tenant_id=config.service_principal.tenant_id,
        client_id=config.service_principal.client_id,
        client_secret=config.service_principal.client_secret,
    )
    os.environ["DATAVERSE_ENVIRONMENT_URL"] = config.dataverse.environment_url
    environment = DataverseAPIClient().get_environment_security_map(config.source)
    report = build_inventory(environment)
    if args.compile_policies:
        report["policy_compilation"] = compile_policy_summary(config, environment)
    if args.compile_without_cls:
        rls_only_config = config.model_copy(deep=True)
        if rls_only_config.constraints is None:
            rls_only_config.constraints = ConstraintsConfig()
        if rls_only_config.constraints.columns is None:
            rls_only_config.constraints.columns = ColumnConstraintsConfig()
        rls_only_config.constraints.columns.columnlevelsecurity = False
        rls_only_config.dataverse.strict_access_parity = False
        report["policy_compilation_without_cls"] = compile_policy_summary(
            rls_only_config, environment
        )
    payload = json.dumps(report, indent=2, sort_keys=True)
    print(payload)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(payload + "\n", encoding="utf-8")
    if args.markdown_output:
        markdown_path = Path(args.markdown_output)
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(
            build_markdown_inventory(
                environment,
                config.dataverse.environment_url,
            ),
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
