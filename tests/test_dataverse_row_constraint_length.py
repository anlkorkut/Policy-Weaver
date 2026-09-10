import logging
import unittest

from policyweaver.core.enum import IamType
from policyweaver.models.config import (
    ColumnConstraintsConfig,
    ConstraintsConfig,
    FabricConfig,
    RowConstraintsConfig,
    Source,
    SourceSchema,
    SourceMapItem,
)
from policyweaver.plugins.dataverse.client import DataversePolicyWeaver
from policyweaver.plugins.dataverse.model import (
    DataverseBusinessUnit,
    DataverseEnvironment,
    DataverseSecurityRole,
    DataverseSourceConfig,
    DataverseSourceMap,
    DataverseTablePermission,
    DataverseUser,
)


def _guid(index: int) -> str:
    return f"00000000-0000-0000-0000-{index:012d}"


def _make_config(
    chunk_length: int = 4096, mirror_table_name: str | None = None
) -> DataverseSourceMap:
    return DataverseSourceMap(
        source=Source(name="TestCatalog", schemas=[SourceSchema(name="dbo")]),
        fabric=FabricConfig(
            tenant_id="t",
            workspace_id="w",
            mirror_id="m",
            policy_mapping="role_based",
        ),
        constraints=ConstraintsConfig(
            columns=ColumnConstraintsConfig(columnlevelsecurity=False),
            rows=RowConstraintsConfig(rowlevelsecurity=True),
        ),
        dataverse=DataverseSourceConfig(
            environment_url="https://test.crm.dynamics.com",
            row_constraint_chunk_length=chunk_length,
        ),
        mapped_items=(
            [
                SourceMapItem(
                    catalog="TestCatalog",
                    catalog_schema="dbo",
                    table="account",
                    mirror_table_name=mirror_table_name,
                )
            ]
            if mirror_table_name
            else None
        ),
    )


def _make_business_units(child_count: int) -> list[DataverseBusinessUnit]:
    business_units = [
        DataverseBusinessUnit(id=_guid(0), name="Root", parent_business_unit_id=None)
    ]
    for index in range(1, child_count + 1):
        business_units.append(
            DataverseBusinessUnit(
                id=_guid(index),
                name=f"Child {index}",
                parent_business_unit_id=_guid(0),
            )
        )
    return business_units


def _make_table_permission(table_name: str, depth: str) -> DataverseTablePermission:
    return DataverseTablePermission(
        table_name=table_name,
        principal_id="user-1",
        principal_type=IamType.USER,
        principal_business_unit_id=_guid(0),
        has_read=True,
        depth=depth,
        role_id="role-1",
        role_name="LargeBuRole",
        role_business_unit_id=_guid(0),
    )


def _make_environment(include_global_table: bool = False) -> DataverseEnvironment:
    table_permissions = [_make_table_permission("account", "Deep")]
    if include_global_table:
        table_permissions.append(_make_table_permission("contact", "Global"))

    return DataverseEnvironment(
        users=[
            DataverseUser(
                id="user-1",
                name="Test User",
                email="test@example.com",
                azure_ad_object_id="entra-user-1",
                business_unit_id=_guid(0),
            ),
        ],
        teams=[],
        business_units=_make_business_units(child_count=160),
        security_roles=[
            DataverseSecurityRole(
                id="role-1", name="LargeBuRole", business_unit_id=_guid(0)
            ),
        ],
        role_privileges=[],
        user_role_assignments={"user-1": ["role-1"]},
        team_role_assignments={},
        field_security_profiles=[],
        table_permissions=table_permissions,
    )


def _build_export(
    environment: DataverseEnvironment,
    chunk_length: int = 4096,
    mirror_table_name: str | None = None,
):
    client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
    client.config = _make_config(chunk_length, mirror_table_name)
    client.logger = logging.getLogger("test_dataverse_row_constraint_length")
    client.environment = environment
    return client.__build_role_based_export__()


class TestDataverseRowConstraintLength(unittest.TestCase):
    def test_deep_filter_is_split_at_configured_internal_boundary(self) -> None:
        export = _build_export(_make_environment())

        self.assertGreater(len(export.policies), 1)
        conditions = [
            row_constraint.filter_condition
            for policy in export.policies
            for row_constraint in policy.rowconstraints or []
        ]
        self.assertGreater(len(conditions), 1)

        fabric_values = [
            f"SELECT * FROM account WHERE {condition}" for condition in conditions
        ]
        self.assertLessEqual(max(len(value) for value in fabric_values), 4096)
        self.assertTrue(any(_guid(0) in condition for condition in conditions))
        self.assertTrue(any(_guid(160) in condition for condition in conditions))

    def test_custom_chunk_length_changes_generated_rule_size(self) -> None:
        export = _build_export(_make_environment(), chunk_length=1200)

        values = [
            f"SELECT * FROM account WHERE {constraint.filter_condition}"
            for policy in export.policies
            for constraint in policy.rowconstraints or []
        ]

        self.assertGreater(len(values), 1)
        self.assertLessEqual(max(len(value) for value in values), 1200)

    def test_mapped_table_name_is_included_in_chunk_budget(self) -> None:
        mirror_table_name = "mapped_" + ("x" * 120)
        export = _build_export(_make_environment(), mirror_table_name=mirror_table_name)

        values = [
            f"SELECT * FROM {mirror_table_name} WHERE {constraint.filter_condition}"
            for policy in export.policies
            for constraint in policy.rowconstraints or []
        ]

        self.assertGreater(len(values), 1)
        self.assertLessEqual(max(len(value) for value in values), 4096)

    def test_chunked_table_is_not_in_unfiltered_global_table_policy(self) -> None:
        export = _build_export(_make_environment(include_global_table=True))

        global_table_policies = [
            policy for policy in export.policies if not policy.rowconstraints
        ]
        self.assertEqual(len(global_table_policies), 1)
        self.assertEqual(
            {scope.table for scope in global_table_policies[0].permissionscopes},
            {"contact"},
        )

        chunked_policies = [
            policy for policy in export.policies if policy.rowconstraints
        ]
        self.assertGreater(len(chunked_policies), 1)
        for policy in chunked_policies:
            self.assertEqual(
                {scope.table for scope in policy.permissionscopes}, {"account"}
            )

    def test_unrepresentable_filter_fails_role_with_global_sibling(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot fit"):
            _build_export(
                _make_environment(include_global_table=True),
                chunk_length=40,
            )

    def test_unrepresentable_local_filter_fails_role(self) -> None:
        environment = _make_environment()
        environment.table_permissions[0].depth = "Local"

        with self.assertRaisesRegex(ValueError, "cannot fit"):
            _build_export(environment, chunk_length=40)


if __name__ == "__main__":
    unittest.main()
