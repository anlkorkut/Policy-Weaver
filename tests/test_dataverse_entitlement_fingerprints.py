from policyweaver.core.enum import IamType, PermissionState, PermissionType
from policyweaver.models.export import (
    ColumnConstraint,
    PermissionObject,
    PermissionScope,
    RolePolicy,
    RolePolicyExport,
    RowConstraint,
)
from policyweaver.plugins.dataverse.model import DataverseEnvironment, DataverseUser
from scripts.dataverse_environment_inventory import (
    build_entitlement_fingerprint_summary,
)


def _member(object_id: str) -> PermissionObject:
    return PermissionObject(
        id=object_id,
        entra_object_id=object_id,
        type=IamType.USER,
    )


def _scope(table: str) -> PermissionScope:
    return PermissionScope(
        catalog="Dataverse",
        catalog_schema="dbo",
        table=table,
        name=PermissionType.SELECT,
        state=PermissionState.GRANT,
    )


def test_identical_effective_access_collapses_different_source_roles() -> None:
    export = RolePolicyExport(
        policies=[
            RolePolicy(
                name="Source Role A",
                permissionobjects=[_member("entra-a")],
                permissionscopes=[_scope("account")],
            ),
            RolePolicy(
                name="Source Role B",
                permissionobjects=[_member("entra-b")],
                permissionscopes=[_scope("account")],
            ),
        ]
    )

    summary = build_entitlement_fingerprint_summary(export)

    assert summary["eligible_principals"] == 2
    assert summary["unique_fingerprints_with_access"] == 1
    assert summary["largest_access_cohort"] == 2
    assert summary["exact_dataverse_parity_proven"] is False


def test_row_chunks_are_combined_before_fingerprinting() -> None:
    export = RolePolicyExport(
        policies=[
            RolePolicy(
                name="Reader Part 1",
                permissionobjects=[_member("entra-a")],
                permissionscopes=[_scope("account")],
                rowconstraints=[
                    RowConstraint(
                        catalog_name="Dataverse",
                        schema_name="dbo",
                        table_name="account",
                        filter_condition="ownerid in ('owner-a')",
                    )
                ],
            ),
            RolePolicy(
                name="Reader Part 2",
                permissionobjects=[_member("entra-a")],
                permissionscopes=[_scope("account")],
                rowconstraints=[
                    RowConstraint(
                        catalog_name="Dataverse",
                        schema_name="dbo",
                        table_name="account",
                        filter_condition="ownerid in ('owner-b')",
                    )
                ],
            ),
            RolePolicy(
                name="Reader B Part 1",
                permissionobjects=[_member("entra-b")],
                permissionscopes=[_scope("account")],
                rowconstraints=[
                    RowConstraint(
                        catalog_name="Dataverse",
                        schema_name="dbo",
                        table_name="account",
                        filter_condition="ownerid in ('owner-b')",
                    )
                ],
            ),
            RolePolicy(
                name="Reader B Part 2",
                permissionobjects=[_member("entra-b")],
                permissionscopes=[_scope("account")],
                rowconstraints=[
                    RowConstraint(
                        catalog_name="Dataverse",
                        schema_name="dbo",
                        table_name="account",
                        filter_condition="ownerid in ('owner-a')",
                    ),
                ],
            ),
        ]
    )

    summary = build_entitlement_fingerprint_summary(export)

    assert summary["unique_fingerprints_with_access"] == 1
    assert summary["largest_access_cohort"] == 2


def test_unrestricted_rules_dominate_equivalent_explicit_rules() -> None:
    export = RolePolicyExport(
        policies=[
            RolePolicy(
                name="Unrestricted A",
                permissionobjects=[_member("entra-a")],
                permissionscopes=[_scope("account")],
            ),
            RolePolicy(
                name="Unrestricted B",
                permissionobjects=[_member("entra-b")],
                permissionscopes=[_scope("account")],
                rowconstraints=[
                    RowConstraint(
                        catalog_name="Dataverse",
                        schema_name="dbo",
                        table_name="account",
                        filter_condition="TRUE",
                    )
                ],
                columnconstraints=[
                    ColumnConstraint(
                        catalog_name="Dataverse",
                        schema_name="dbo",
                        table_name="account",
                        column_actions=[PermissionType.SELECT],
                        column_effect=PermissionState.GRANT,
                        column_names=["*"],
                    )
                ],
            ),
        ]
    )

    summary = build_entitlement_fingerprint_summary(export)

    assert summary["unique_fingerprints_with_access"] == 1


def test_zero_access_users_are_included_without_exposing_identifiers() -> None:
    environment = DataverseEnvironment(
        users=[
            DataverseUser(
                id="user-a",
                azure_ad_object_id="entra-a",
                azure_state=0,
                access_mode=0,
                is_licensed=True,
            ),
            DataverseUser(
                id="user-b",
                azure_ad_object_id="entra-b",
                azure_state=0,
                access_mode=0,
                is_licensed=True,
            ),
        ]
    )
    export = RolePolicyExport(
        policies=[
            RolePolicy(
                name="Reader",
                permissionobjects=[_member("entra-a")],
                permissionscopes=[_scope("account")],
                columnconstraints=[
                    ColumnConstraint(
                        catalog_name="Dataverse",
                        schema_name="dbo",
                        table_name="account",
                        column_actions=[PermissionType.SELECT],
                        column_effect=PermissionState.GRANT,
                        column_names=["accountid"],
                    )
                ],
            )
        ]
    )

    summary = build_entitlement_fingerprint_summary(export, environment)

    assert summary["eligible_principals"] == 2
    assert summary["principals_with_compiled_access"] == 1
    assert summary["eligible_principals_without_compiled_access"] == 1
    assert summary["unique_fingerprints_including_no_access"] == 2
    assert "entra-a" not in str(summary)
    assert "entra-b" not in str(summary)
