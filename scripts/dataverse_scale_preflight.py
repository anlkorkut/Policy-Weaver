"""Exercise Dataverse policy mapping at customer-scale without service calls."""

from __future__ import annotations

import argparse
import json
import logging
import time
import tracemalloc
from pathlib import Path
from typing import Any, Callable

from policyweaver.models.config import (
    ColumnConstraintsConfig,
    ConstraintsConfig,
    FabricConfig,
    RowConstraintsConfig,
    Source,
    SourceSchema,
)
from policyweaver.plugins.dataverse.client import DataversePolicyWeaver
from policyweaver.plugins.dataverse.model import (
    DataverseBusinessUnit,
    DataverseColumnMetadata,
    DataverseEnvironment,
    DataverseFieldPermission,
    DataverseFieldSecurityProfile,
    DataverseRolePrivilege,
    DataverseSecurityRole,
    DataverseSourceConfig,
    DataverseSourceMap,
    DataverseTableMetadata,
    DataverseTeam,
    DataverseUser,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an offline Dataverse policy scale preflight."
    )
    parser.add_argument("--users", type=int, default=12500)
    parser.add_argument("--roles", type=int, default=500)
    parser.add_argument("--profiles", type=int, default=25)
    parser.add_argument("--roles-per-user", type=int, default=5)
    parser.add_argument("--business-units", type=int, default=10)
    parser.add_argument("--owner-teams", type=int, default=100)
    parser.add_argument("--tables-per-role", type=int, default=10)
    parser.add_argument("--role-limit", type=int, default=1000)
    parser.add_argument("--output", default="reports/dataverse-scale-preflight.json")
    return parser.parse_args()


def build_config(role_limit: int, column_security: bool) -> DataverseSourceMap:
    return DataverseSourceMap(
        source=Source(name="SyntheticDataverse", schemas=[SourceSchema(name="dbo")]),
        fabric=FabricConfig(policy_mapping="role_based"),
        constraints=ConstraintsConfig(
            columns=ColumnConstraintsConfig(columnlevelsecurity=column_security),
            rows=RowConstraintsConfig(rowlevelsecurity=True),
        ),
        dataverse=DataverseSourceConfig(
            environment_url="https://synthetic.crm.dynamics.com",
            onelake_role_limit=role_limit,
            strict_access_parity=False,
        ),
    )


def build_client(
    environment: DataverseEnvironment, config: DataverseSourceMap
) -> DataversePolicyWeaver:
    client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
    client.config = config
    client.environment = environment
    client.logger = logging.getLogger("dataverse_scale_preflight")
    return client


def build_users(user_count: int, business_unit_count: int) -> list[DataverseUser]:
    return [
        DataverseUser(
            id=f"user-{index:05d}",
            email=f"user-{index:05d}@example.invalid",
            azure_ad_object_id=f"00000000-0000-4000-8000-{index:012d}",
            business_unit_id=f"bu-{index % business_unit_count:02d}",
            access_mode=0,
            is_licensed=True,
            azure_state=0,
        )
        for index in range(user_count)
    ]


def build_business_units(count: int) -> list[DataverseBusinessUnit]:
    return [
        DataverseBusinessUnit(
            id=f"bu-{index:02d}",
            name=f"Business Unit {index:02d}",
            parent_business_unit_id=None if index == 0 else "bu-00",
        )
        for index in range(count)
    ]


def build_owner_teams(
    users: list[DataverseUser], team_count: int, business_unit_count: int
) -> list[DataverseTeam]:
    members_by_team = {index: set() for index in range(team_count)}
    for index, user in enumerate(users):
        members_by_team[index % team_count].add(user.id)
        members_by_team[(index * 7 + 3) % team_count].add(user.id)
    return [
        DataverseTeam(
            id=f"team-{index:03d}",
            name=f"Owner Team {index:03d}",
            team_type=0,
            business_unit_id=f"bu-{index % business_unit_count:02d}",
            member_ids=sorted(members_by_team[index]),
        )
        for index in range(team_count)
    ]


def build_rbac_environment(args: argparse.Namespace) -> DataverseEnvironment:
    users = build_users(args.users, args.business_units)
    business_units = build_business_units(args.business_units)
    roles = [
        DataverseSecurityRole(
            id=f"role-{index:04d}",
            name=f"Synthetic Role {index:04d}",
            business_unit_id=f"bu-{index % args.business_units:02d}",
            is_inherited=1,
        )
        for index in range(args.roles)
    ]
    roles_by_bu: dict[str, list[str]] = {}
    for role in roles:
        roles_by_bu.setdefault(role.business_unit_id, []).append(role.id)

    user_role_assignments = {}
    for index, user in enumerate(users):
        candidates = roles_by_bu[user.business_unit_id]
        local_user_index = index // args.business_units
        user_role_assignments[user.id] = sorted(
            {
                candidates[
                    (local_user_index * args.roles_per_user + offset) % len(candidates)
                ]
                for offset in range(args.roles_per_user)
            }
        )

    teams = build_owner_teams(users, args.owner_teams, args.business_units)
    team_role_assignments = {}
    for index, team in enumerate(teams):
        candidates = roles_by_bu[team.business_unit_id]
        team_role_assignments[team.id] = [candidates[index % len(candidates)]]

    depths = ("Global", "Local", "Deep")
    privileges = [
        DataverseRolePrivilege(
            privilege_id=f"priv-{role_index:04d}-{table_index:02d}",
            role_id=f"role-{role_index:04d}",
            name=f"prvReadtable_{(role_index * 11 + table_index) % 250:03d}",
            entity_name=f"table_{(role_index * 11 + table_index) % 250:03d}",
            depth=depths[role_index % len(depths)],
            can_read=True,
        )
        for role_index in range(args.roles)
        for table_index in range(args.tables_per_role)
    ]
    profiles = [
        DataverseFieldSecurityProfile(
            id=f"profile-{profile_index:02d}",
            name=f"Profile {profile_index:02d}",
            user_ids=[
                user.id
                for user_index, user in enumerate(users)
                if user_index % args.profiles == profile_index
            ],
            permissions=[
                DataverseFieldPermission(
                    entity_name="account",
                    attribute_logical_name=f"secured_{profile_index:02d}",
                    can_read=4,
                )
            ],
        )
        for profile_index in range(args.profiles)
    ]
    return DataverseEnvironment(
        users=users,
        teams=teams,
        business_units=business_units,
        security_roles=roles,
        role_privileges=privileges,
        user_role_assignments=user_role_assignments,
        team_role_assignments=team_role_assignments,
        field_security_profiles=profiles,
    )


def measure(operation: Callable[[], Any]) -> tuple[Any, float, float]:
    tracemalloc.start()
    started = time.perf_counter()
    try:
        result = operation()
    finally:
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    return result, round(elapsed, 3), round(peak / (1024 * 1024), 2)


def compile_rbac_scale(
    environment: DataverseEnvironment, args: argparse.Namespace
) -> dict[str, Any]:
    client = build_client(
        environment, build_config(args.role_limit, column_security=False)
    )
    try:
        export, seconds, peak_mb = measure(client.__build_role_based_export__)
    except ValueError as error:
        return {
            "status": "blocked",
            "reason": str(error),
        }
    policies = export.policies or []
    return {
        "status": "success",
        "seconds": seconds,
        "peak_traced_memory_mb": peak_mb,
        "generated_roles": len(policies),
        "memberships": sum(len(policy.permissionobjects or []) for policy in policies),
        "table_scopes": sum(len(policy.permissionscopes or []) for policy in policies),
        "row_constraints": sum(len(policy.rowconstraints or []) for policy in policies),
        "maximum_members_per_role": max(
            (len(policy.permissionobjects or []) for policy in policies), default=0
        ),
    }


def verify_basic_capacity_block(
    users: list[DataverseUser], args: argparse.Namespace
) -> dict[str, Any]:
    role = DataverseSecurityRole(
        id="basic-role", name="Basic Reader", business_unit_id="bu-00"
    )
    environment = DataverseEnvironment(
        users=users,
        security_roles=[role],
        role_privileges=[
            DataverseRolePrivilege(
                privilege_id="basic-read",
                role_id=role.id,
                entity_name="incident",
                depth="Basic",
                can_read=True,
            )
        ],
        user_role_assignments={user.id: [role.id] for user in users},
    )
    client = build_client(
        environment, build_config(args.role_limit, column_security=False)
    )

    def compile_policy() -> str:
        try:
            client.__build_role_based_export__()
        except ValueError as error:
            return str(error)
        raise AssertionError("Basic-depth scale unexpectedly fit within the role limit")

    message, seconds, peak_mb = measure(compile_policy)
    return {
        "status": "blocked-as-expected",
        "seconds": seconds,
        "peak_traced_memory_mb": peak_mb,
        "reason": message,
    }


def verify_rls_cls_composition_block(
    users: list[DataverseUser], args: argparse.Namespace
) -> dict[str, Any]:
    scenario_users = [
        user.model_copy(update={"business_unit_id": "bu-00"}) for user in users
    ]
    roles = [
        DataverseSecurityRole(
            id="local-role", name="Local Reader", business_unit_id="bu-00"
        ),
        DataverseSecurityRole(
            id="global-role", name="Global Reader", business_unit_id="bu-00"
        ),
    ]
    profiles = []
    for profile_index in range(args.profiles):
        profiles.append(
            DataverseFieldSecurityProfile(
                id=f"profile-{profile_index:02d}",
                user_ids=[
                    user.id
                    for user_index, user in enumerate(scenario_users)
                    if user_index % args.profiles == profile_index
                ],
                permissions=[
                    DataverseFieldPermission(
                        entity_name="account",
                        attribute_logical_name="secretcolumn",
                        can_read=4 if profile_index % 2 == 0 else 0,
                    )
                ],
            )
        )
    environment = DataverseEnvironment(
        users=scenario_users,
        business_units=[DataverseBusinessUnit(id="bu-00", name="Root")],
        security_roles=roles,
        role_privileges=[
            DataverseRolePrivilege(
                privilege_id="local-read",
                role_id="local-role",
                entity_name="account",
                depth="Local",
                can_read=True,
            ),
            DataverseRolePrivilege(
                privilege_id="global-read",
                role_id="global-role",
                entity_name="account",
                depth="Global",
                can_read=True,
            ),
        ],
        user_role_assignments={
            user.id: ["local-role", "global-role"] for user in scenario_users
        },
        field_security_profiles=profiles,
        table_metadata=[
            DataverseTableMetadata(
                logical_name="account",
                columns=[
                    DataverseColumnMetadata(
                        metadata_id="account-id",
                        logical_name="accountid",
                        is_secured=False,
                    ),
                    DataverseColumnMetadata(
                        metadata_id="secret-id",
                        logical_name="secretcolumn",
                        is_secured=True,
                    ),
                ],
            )
        ],
    )
    client = build_client(
        environment, build_config(args.role_limit, column_security=True)
    )

    def compile_policy() -> str:
        try:
            client.__build_role_based_export__()
        except ValueError as error:
            return str(error)
        raise AssertionError("Unsupported multi-role RLS+CLS composition was accepted")

    message, seconds, peak_mb = measure(compile_policy)
    return {
        "status": "blocked-as-expected",
        "seconds": seconds,
        "peak_traced_memory_mb": peak_mb,
        "reason": message,
    }


def main() -> None:
    args = parse_args()
    if (
        min(
            args.users,
            args.roles,
            args.profiles,
            args.roles_per_user,
            args.business_units,
            args.owner_teams,
            args.tables_per_role,
            args.role_limit,
        )
        < 1
    ):
        raise ValueError("All scale parameters must be positive integers.")
    if args.roles < args.business_units:
        raise ValueError("--roles must be at least --business-units.")

    logging.basicConfig(level=logging.WARNING)
    environment = build_rbac_environment(args)
    direct_environment = environment.model_copy(deep=True)
    direct_environment.teams = []
    direct_environment.team_role_assignments = {}
    report = {
        "input": {
            "users": args.users,
            "role_instances": args.roles,
            "field_security_profiles": args.profiles,
            "roles_per_user": args.roles_per_user,
            "business_units": args.business_units,
            "owner_teams": args.owner_teams,
            "tables_per_role": args.tables_per_role,
            "onelake_role_limit": args.role_limit,
        },
        "certification_note": (
            "Synthetic scale results test mapper capacity and fail-closed gates; "
            "they do not certify customer entitlement parity."
        ),
        "direct_role_rls_scale": compile_rbac_scale(direct_environment, args),
        "overlapping_team_role_rls_scale": compile_rbac_scale(environment, args),
        "basic_depth_capacity": verify_basic_capacity_block(environment.users, args),
        "multi_role_rls_cls": verify_rls_cls_composition_block(environment.users, args),
    }
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
