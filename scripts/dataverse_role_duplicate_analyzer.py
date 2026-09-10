"""
Analyze Dataverse security roles and generated Fabric role policies for duplicates.

This script is read-only. It fetches Dataverse security metadata through the
existing Policy Weaver Dataverse connector, generates the role-based policy export,
and writes JSON/CSV reports that identify:
- Dataverse roles with identical read privilege definitions.
- Dataverse roles with identical read privileges and identical assignments.
- Generated Policy Weaver role policies with identical access signatures.
- Generated Policy Weaver role policies that are exact duplicates including members.
- Field security profiles with identical field permission definitions.

Usage:
    python scripts/dataverse_role_duplicate_analyzer.py --config configdataverse.yaml
    python scripts/dataverse_role_duplicate_analyzer.py --config configdataverse.yaml --output-dir reports/dataverse
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import os
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from policyweaver.core.auth import ServicePrincipal  # noqa: E402
from policyweaver.core.conf import Configuration  # noqa: E402
from policyweaver.models.export import RolePolicy  # noqa: E402
from policyweaver.plugins.dataverse.api import DataverseAPIClient  # noqa: E402
from policyweaver.plugins.dataverse.client import DataversePolicyWeaver  # noqa: E402
from policyweaver.plugins.dataverse.model import (  # noqa: E402
    DataverseEnvironment,
    DataverseFieldSecurityProfile,
    DataverseSecurityRole,
    DataverseSourceMap,
)
from policyweaver.weaver import WeaverAgent  # noqa: E402


DEPTH_RANK = DataverseAPIClient.DEPTH_RANK


@dataclass(frozen=True)
class SignatureGroup:
    signature_hash: str
    signature: dict[str, Any]
    members: list[dict[str, Any]]


class DataverseRoleDuplicateAnalyzer:
    def __init__(
        self,
        config_path: Path,
        output_dir: Path,
        sample_size: int,
        include_member_details: bool,
    ) -> None:
        self.config_path = config_path
        self.output_dir = output_dir
        self.sample_size = sample_size
        self.include_member_details = include_member_details
        self.logger = logging.getLogger("DATAVERSE_ROLE_DUPLICATE_ANALYZER")

    def run(self) -> dict[str, Any]:
        config = self._load_config()
        self._configure_auth(config)

        weaver = DataversePolicyWeaver(config)
        export = weaver.map_policy("role_based")
        env = weaver.environment
        policies = []
        if export and export.policies:
            for policy in export.policies:
                policies.extend(WeaverAgent.split_permission_scopes(policy))

        self.output_dir.mkdir(parents=True, exist_ok=True)

        role_records = self._build_role_records(env)
        policy_records = self._build_policy_records(policies)
        profile_records = self._build_field_security_profile_records(env)

        duplicate_role_permission_groups = self._duplicate_groups(
            role_records, "permission_signature_hash"
        )
        duplicate_role_full_groups = self._duplicate_groups(
            role_records, "permission_and_assignment_signature_hash"
        )
        duplicate_policy_access_groups = self._duplicate_groups(
            policy_records, "access_signature_hash"
        )
        duplicate_policy_full_groups = self._duplicate_groups(
            policy_records, "full_signature_hash"
        )
        duplicate_profile_permission_groups = self._duplicate_groups(
            profile_records, "permission_signature_hash"
        )
        duplicate_profile_full_groups = self._duplicate_groups(
            profile_records, "full_signature_hash"
        )

        report = {
            "summary": {
                "config_path": str(self.config_path),
                "source_name": config.source.name if config.source else None,
                "dataverse_environment_url": config.dataverse.environment_url
                if config.dataverse
                else None,
                "business_units": len(env.business_units or []),
                "active_users": len(env.users or []),
                "teams": len(env.teams or []),
                "security_roles": len(env.security_roles or []),
                "role_read_privileges": len(env.role_privileges or []),
                "field_security_profiles": len(env.field_security_profiles or []),
                "role_read_table_entries": sum(
                    record["read_table_count"] for record in role_records
                ),
                "generated_role_policies": len(policies),
                "duplicate_role_permission_groups": len(
                    duplicate_role_permission_groups
                ),
                "duplicate_role_full_groups": len(duplicate_role_full_groups),
                "duplicate_policy_access_groups": len(duplicate_policy_access_groups),
                "duplicate_policy_full_groups": len(duplicate_policy_full_groups),
                "duplicate_profile_permission_groups": len(
                    duplicate_profile_permission_groups
                ),
                "duplicate_profile_full_groups": len(duplicate_profile_full_groups),
            },
            "duplicate_role_permission_groups": self._serialize_groups(
                duplicate_role_permission_groups
            ),
            "duplicate_role_full_groups": self._serialize_groups(
                duplicate_role_full_groups
            ),
            "duplicate_policy_access_groups": self._serialize_groups(
                duplicate_policy_access_groups
            ),
            "duplicate_policy_full_groups": self._serialize_groups(
                duplicate_policy_full_groups
            ),
            "duplicate_profile_permission_groups": self._serialize_groups(
                duplicate_profile_permission_groups
            ),
            "duplicate_profile_full_groups": self._serialize_groups(
                duplicate_profile_full_groups
            ),
        }

        self._write_json(report, self.output_dir / "dataverse_duplicate_report.json")
        self._write_group_csv(
            duplicate_role_permission_groups,
            self.output_dir / "duplicate_dataverse_role_permissions.csv",
            member_label_key="role_name",
            member_id_key="role_id",
        )
        self._write_group_csv(
            duplicate_role_full_groups,
            self.output_dir / "duplicate_dataverse_role_full_entitlements.csv",
            member_label_key="role_name",
            member_id_key="role_id",
        )
        self._write_group_csv(
            duplicate_policy_access_groups,
            self.output_dir / "duplicate_generated_policy_access.csv",
            member_label_key="policy_name",
            member_id_key="policy_index",
        )
        self._write_group_csv(
            duplicate_policy_full_groups,
            self.output_dir / "duplicate_generated_policy_full.csv",
            member_label_key="policy_name",
            member_id_key="policy_index",
        )
        self._write_group_csv(
            duplicate_profile_permission_groups,
            self.output_dir / "duplicate_field_security_profile_permissions.csv",
            member_label_key="profile_name",
            member_id_key="profile_id",
        )
        self._write_group_csv(
            duplicate_profile_full_groups,
            self.output_dir / "duplicate_field_security_profile_full.csv",
            member_label_key="profile_name",
            member_id_key="profile_id",
        )
        self._write_detail_csv(role_records, self.output_dir / "role_summary.csv")
        self._write_detail_csv(policy_records, self.output_dir / "policy_summary.csv")
        self._write_detail_csv(
            profile_records, self.output_dir / "field_security_profile_summary.csv"
        )

        self._print_summary(report)
        return report

    def _load_config(self) -> DataverseSourceMap:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        return DataverseSourceMap.from_yaml(str(self.config_path))

    def _configure_auth(self, config: DataverseSourceMap) -> None:
        Configuration.configure_environment(config)
        if not config.service_principal:
            raise ValueError("service_principal config is required.")
        if not config.dataverse or not config.dataverse.environment_url:
            raise ValueError("dataverse.environment_url config is required.")

        sp = config.service_principal
        ServicePrincipal.initialize(
            tenant_id=sp.tenant_id,
            client_id=sp.client_id,
            client_secret=sp.client_secret,
        )
        os.environ["DATAVERSE_ENVIRONMENT_URL"] = config.dataverse.environment_url

    def _build_role_records(self, env: DataverseEnvironment) -> list[dict[str, Any]]:
        users_by_id = {u.id: u for u in env.users or [] if u.id}
        teams_by_id = {t.id: t for t in env.teams or [] if t.id}
        business_units_by_id = {b.id: b for b in env.business_units or [] if b.id}
        role_privileges_by_role: dict[str, list[Any]] = defaultdict(list)
        for privilege in env.role_privileges or []:
            if privilege.role_id:
                role_privileges_by_role[privilege.role_id].append(privilege)

        records = []
        for role in sorted(env.security_roles or [], key=self._role_sort_key):
            read_privileges = self._effective_read_privileges(
                role_privileges_by_role.get(role.id, [])
            )
            direct_user_ids = sorted(
                user_id
                for user_id, role_ids in (env.user_role_assignments or {}).items()
                if role.id in role_ids
            )
            direct_team_ids = sorted(
                team_id
                for team_id, role_ids in (env.team_role_assignments or {}).items()
                if role.id in role_ids
            )
            effective_user_ids = set(direct_user_ids)
            for team_id in direct_team_ids:
                team = teams_by_id.get(team_id)
                if team:
                    effective_user_ids.update(team.member_ids or [])

            permission_signature = {"read_privileges": read_privileges}
            assignment_signature = {
                "direct_user_ids": direct_user_ids,
                "direct_team_ids": direct_team_ids,
            }
            permission_and_assignment_signature = {
                **permission_signature,
                "assignments": assignment_signature,
            }

            business_unit = business_units_by_id.get(role.business_unit_id)
            record = {
                "role_id": role.id,
                "role_name": role.name,
                "business_unit_id": role.business_unit_id,
                "business_unit_name": business_unit.name if business_unit else None,
                "read_table_count": len(read_privileges),
                "direct_user_count": len(direct_user_ids),
                "direct_team_count": len(direct_team_ids),
                "effective_user_count": len(effective_user_ids),
                "permission_signature_hash": stable_hash(permission_signature),
                "permission_and_assignment_signature_hash": stable_hash(
                    permission_and_assignment_signature
                ),
                "permission_signature": permission_signature,
                "assignment_signature": assignment_signature,
            }
            if self.include_member_details:
                record["direct_users"] = [
                    self._user_summary(users_by_id.get(user_id), user_id)
                    for user_id in direct_user_ids
                ]
                record["direct_teams"] = [
                    self._team_summary(teams_by_id.get(team_id), team_id)
                    for team_id in direct_team_ids
                ]
                record["effective_users_sample"] = [
                    self._user_summary(users_by_id.get(user_id), user_id)
                    for user_id in sorted(effective_user_ids)[: self.sample_size]
                ]
            records.append(record)
        return records

    def _effective_read_privileges(
        self, privileges: Iterable[Any]
    ) -> list[dict[str, str]]:
        table_to_depth: dict[str, str] = {}
        for privilege in privileges:
            if not privilege.can_read or not privilege.entity_name:
                continue
            candidate_depth = (privilege.depth or "Unknown").title()
            current_depth = table_to_depth.get(privilege.entity_name)
            if current_depth is None or DEPTH_RANK.get(
                candidate_depth, 0
            ) >= DEPTH_RANK.get(current_depth, 0):
                table_to_depth[privilege.entity_name] = candidate_depth
        return [
            {"table": table_name, "depth": depth}
            for table_name, depth in sorted(table_to_depth.items())
        ]

    def _build_policy_records(self, policies: list[RolePolicy]) -> list[dict[str, Any]]:
        records = []
        for index, policy in enumerate(policies, start=1):
            access_signature = {
                "permission_scopes": canonical_permission_scopes(
                    policy.permissionscopes or []
                ),
                "row_constraints": canonical_row_constraints(
                    policy.rowconstraints or []
                ),
                "column_constraints": canonical_column_constraints(
                    policy.columnconstraints or []
                ),
            }
            members = canonical_permission_objects(policy.permissionobjects or [])
            full_signature = {**access_signature, "members": members}
            row_constraints = access_signature["row_constraints"]
            column_constraints = access_signature["column_constraints"]
            member_count = len(members)

            record = {
                "policy_index": index,
                "policy_name": policy.name,
                "member_count": member_count,
                "table_scope_count": len(access_signature["permission_scopes"]),
                "row_constraint_count": len(row_constraints),
                "column_constraint_count": len(column_constraints),
                "has_basic_owner_filter": any(
                    "ownerid" in str(rc.get("filter_condition", "")).lower()
                    for rc in row_constraints
                ),
                "has_deny_all_filter": any(
                    str(rc.get("filter_condition", "")).lower() == "false"
                    for rc in row_constraints
                ),
                "access_signature_hash": stable_hash(access_signature),
                "full_signature_hash": stable_hash(full_signature),
                "access_signature": access_signature,
            }
            if self.include_member_details:
                record["members"] = members
            else:
                record["members_sample"] = members[: self.sample_size]
            records.append(record)
        return records

    def _build_field_security_profile_records(
        self, env: DataverseEnvironment
    ) -> list[dict[str, Any]]:
        profiles = sorted(
            env.field_security_profiles or [],
            key=lambda p: ((p.name or ""), (p.id or "")),
        )
        records = []
        for profile in profiles:
            permission_signature = self._profile_permission_signature(profile)
            full_signature = {
                **permission_signature,
                "user_ids": sorted(profile.user_ids or []),
                "team_ids": sorted(profile.team_ids or []),
            }
            records.append(
                {
                    "profile_id": profile.id,
                    "profile_name": profile.name,
                    "permission_count": len(permission_signature["field_permissions"]),
                    "assigned_user_count": len(profile.user_ids or []),
                    "assigned_team_count": len(profile.team_ids or []),
                    "permission_signature_hash": stable_hash(permission_signature),
                    "full_signature_hash": stable_hash(full_signature),
                    "permission_signature": permission_signature,
                    "assignment_signature": {
                        "user_ids": sorted(profile.user_ids or []),
                        "team_ids": sorted(profile.team_ids or []),
                    },
                }
            )
        return records

    def _profile_permission_signature(
        self, profile: DataverseFieldSecurityProfile
    ) -> dict[str, Any]:
        permissions = []
        for permission in profile.permissions or []:
            permissions.append(
                {
                    "table": permission.entity_name,
                    "column": permission.attribute_logical_name,
                    "can_read": permission.can_read,
                }
            )
        permissions.sort(
            key=lambda p: (
                str(p["table"] or ""),
                str(p["column"] or ""),
                str(p["can_read"]),
            )
        )
        return {"field_permissions": permissions}

    def _duplicate_groups(
        self, records: list[dict[str, Any]], hash_key: str
    ) -> list[SignatureGroup]:
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in records:
            groups[record[hash_key]].append(record)

        duplicate_groups = []
        for signature_hash, members in groups.items():
            if len(members) < 2:
                continue
            signature = self._signature_for_hash_key(members[0], hash_key)
            duplicate_groups.append(
                SignatureGroup(
                    signature_hash=signature_hash,
                    signature=signature,
                    members=members,
                )
            )
        duplicate_groups.sort(key=lambda g: (-len(g.members), g.signature_hash))
        return duplicate_groups

    def _signature_for_hash_key(
        self, record: dict[str, Any], hash_key: str
    ) -> dict[str, Any]:
        if hash_key == "permission_signature_hash":
            return record.get("permission_signature", {})
        if hash_key == "permission_and_assignment_signature_hash":
            return {
                **record.get("permission_signature", {}),
                "assignments": record.get("assignment_signature", {}),
            }
        if hash_key == "access_signature_hash":
            return record.get("access_signature", {})
        if hash_key == "full_signature_hash" and "access_signature" in record:
            if self.include_member_details:
                members = record.get("members", [])
            else:
                members = record.get("members_sample", [])
            return {**record.get("access_signature", {}), "members_sample": members}
        if hash_key == "full_signature_hash":
            return {
                **record.get("permission_signature", {}),
                "assignments": record.get("assignment_signature", {}),
            }
        return {}

    def _serialize_groups(self, groups: list[SignatureGroup]) -> list[dict[str, Any]]:
        return [
            {
                "signature_hash": group.signature_hash,
                "group_size": len(group.members),
                "signature": group.signature,
                "members": [self._compact_record(member) for member in group.members],
            }
            for group in groups
        ]

    def _compact_record(self, record: dict[str, Any]) -> dict[str, Any]:
        excluded_suffixes = ("_signature",)
        excluded_keys = {
            "permission_signature",
            "assignment_signature",
            "access_signature",
            "members",
        }
        return {
            key: value
            for key, value in record.items()
            if key not in excluded_keys and not key.endswith(excluded_suffixes)
        }

    def _write_json(self, value: dict[str, Any], path: Path) -> None:
        path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")

    def _write_group_csv(
        self,
        groups: list[SignatureGroup],
        path: Path,
        member_label_key: str,
        member_id_key: str,
    ) -> None:
        fieldnames = [
            "group_id",
            "signature_hash",
            "group_size",
            "member_labels",
            "member_ids",
            "business_units",
            "member_counts",
        ]
        with path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for group_id, group in enumerate(groups, start=1):
                writer.writerow(
                    {
                        "group_id": group_id,
                        "signature_hash": group.signature_hash,
                        "group_size": len(group.members),
                        "member_labels": join_values(
                            member.get(member_label_key) for member in group.members
                        ),
                        "member_ids": join_values(
                            member.get(member_id_key) for member in group.members
                        ),
                        "business_units": join_values(
                            member.get("business_unit_name")
                            for member in group.members
                            if member.get("business_unit_name")
                        ),
                        "member_counts": join_values(
                            self._member_count_label(member) for member in group.members
                        ),
                    }
                )

    def _write_detail_csv(self, records: list[dict[str, Any]], path: Path) -> None:
        if not records:
            path.write_text("", encoding="utf-8")
            return
        simple_records = [flatten_record(record) for record in records]
        fieldnames = sorted({key for record in simple_records for key in record.keys()})
        with path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for record in simple_records:
                writer.writerow(record)

    def _print_summary(self, report: dict[str, Any]) -> None:
        summary = report["summary"]
        print("\nDataverse duplicate role analysis complete")
        print("=" * 52)
        print(f"Security roles:                 {summary['security_roles']}")
        print(f"Active users:                    {summary['active_users']}")
        print(f"Teams:                           {summary['teams']}")
        print(f"Field security profiles:         {summary['field_security_profiles']}")
        print(f"Generated role policies:         {summary['generated_role_policies']}")
        print(
            f"Duplicate role permission groups:{summary['duplicate_role_permission_groups']:>7}"
        )
        print(
            f"Duplicate generated access groups:{summary['duplicate_policy_access_groups']:>6}"
        )
        print(
            f"Duplicate FSP permission groups: {summary['duplicate_profile_permission_groups']:>7}"
        )
        print(f"\nReports written to: {self.output_dir}")
        print("Primary report: dataverse_duplicate_report.json")

    def _member_count_label(self, member: dict[str, Any]) -> str:
        if "effective_user_count" in member:
            return f"effective_users={member['effective_user_count']}"
        if "member_count" in member:
            return f"members={member['member_count']}"
        if "assigned_user_count" in member:
            return (
                f"users={member['assigned_user_count']},"
                f"teams={member.get('assigned_team_count', 0)}"
            )
        return ""

    def _user_summary(self, user: Any, fallback_id: str) -> dict[str, Any]:
        if not user:
            return {"id": fallback_id}
        return {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "business_unit_id": user.business_unit_id,
            "entra_object_id": user.azure_ad_object_id,
        }

    def _team_summary(self, team: Any, fallback_id: str) -> dict[str, Any]:
        if not team:
            return {"id": fallback_id}
        return {
            "id": team.id,
            "name": team.name,
            "team_type": team.team_type,
            "business_unit_id": team.business_unit_id,
            "entra_object_id": team.azure_ad_object_id,
            "member_count": len(team.member_ids or []),
        }

    def _role_sort_key(self, role: DataverseSecurityRole) -> tuple[str, str, str]:
        return (role.name or "", role.business_unit_id or "", role.id or "")


def canonical_permission_scopes(values: Iterable[Any]) -> list[dict[str, Any]]:
    scopes = []
    for value in values:
        scopes.append(
            {
                "catalog": value.catalog,
                "schema": value.catalog_schema,
                "table": value.table,
                "name": enum_value(value.name),
                "state": enum_value(value.state),
            }
        )
    scopes.sort(key=lambda v: tuple(str(v.get(k) or "") for k in sorted(v.keys())))
    return scopes


def canonical_row_constraints(values: Iterable[Any]) -> list[dict[str, Any]]:
    constraints = []
    for value in values:
        constraints.append(
            {
                "catalog": value.catalog_name,
                "schema": value.schema_name,
                "table": value.table_name,
                "filter_condition": value.filter_condition,
            }
        )
    constraints.sort(key=lambda v: tuple(str(v.get(k) or "") for k in sorted(v.keys())))
    return constraints


def canonical_column_constraints(values: Iterable[Any]) -> list[dict[str, Any]]:
    constraints = []
    for value in values:
        constraints.append(
            {
                "catalog": value.catalog_name,
                "schema": value.schema_name,
                "table": value.table_name,
                "actions": sorted(enum_value(a) for a in (value.column_actions or [])),
                "effect": enum_value(value.column_effect),
                "columns": sorted(value.column_names or []),
            }
        )
    constraints.sort(key=lambda v: tuple(str(v.get(k) or "") for k in sorted(v.keys())))
    return constraints


def canonical_permission_objects(values: Iterable[Any]) -> list[dict[str, Any]]:
    objects = []
    for value in values:
        objects.append(
            {
                "id": value.id,
                "email": value.email,
                "type": enum_value(value.type),
                "entra_object_id": value.entra_object_id,
                "app_id": value.app_id,
            }
        )
    objects.sort(key=lambda v: tuple(str(v.get(k) or "") for k in sorted(v.keys())))
    return objects


def stable_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def join_values(values: Iterable[Any]) -> str:
    return "; ".join(str(value) for value in values if value is not None)


def flatten_record(record: dict[str, Any]) -> dict[str, Any]:
    flattened = {}
    for key, value in record.items():
        if isinstance(value, (dict, list)):
            flattened[key] = json.dumps(value, sort_keys=True, default=str)
        else:
            flattened[key] = value
    return flattened


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Identify duplicate Dataverse security roles and generated policy signatures."
    )
    parser.add_argument(
        "--config",
        default="configdataverse.yaml",
        help="Path to Dataverse Policy Weaver YAML config.",
    )
    parser.add_argument(
        "--output-dir",
        default="reports/dataverse-role-duplicates",
        help="Directory for JSON and CSV reports.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=10,
        help="Number of members to include in sample fields.",
    )
    parser.add_argument(
        "--include-member-details",
        action="store_true",
        help="Include full user/team/member details in the JSON report.",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s - %(asctime)s - %(message)s",
    )
    analyzer = DataverseRoleDuplicateAnalyzer(
        config_path=Path(args.config),
        output_dir=Path(args.output_dir),
        sample_size=args.sample_size,
        include_member_details=args.include_member_details,
    )
    analyzer.run()


if __name__ == "__main__":
    main()
