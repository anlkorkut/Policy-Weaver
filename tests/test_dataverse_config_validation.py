"""
Tests for DataversePolicyWeaver.__config_validation.

Covers invalid/missing Dataverse configuration scenarios that must
raise ValueError with clear messages before any API calls are made.
"""

import unittest

from policyweaver.plugins.dataverse.client import DataversePolicyWeaver
from policyweaver.plugins.dataverse.model import (
    DataverseAttributeMaskingRule,
    DataverseBusinessUnit,
    DataverseColumnMetadata,
    DataverseEnvironment,
    DataverseFieldPermission,
    DataverseFieldSecurityProfile,
    DataversePrincipalObjectAttributeAccess,
    DataverseRolePrivilege,
    DataverseSecurityRole,
    DataverseSourceMap,
    DataverseSourceConfig,
    DataverseTeam,
    DataverseTableMetadata,
    DataverseUser,
)
from policyweaver.models.config import (
    ColumnConstraintsConfig,
    Source,
    SourceSchema,
    ConstraintsConfig,
    FabricConfig,
    RowConstraintsConfig,
)


def _base_config(**overrides) -> dict:
    """Return kwargs for a valid DataverseSourceMap, with overrides applied."""
    defaults = dict(
        source=Source(name="TestCatalog", schemas=[SourceSchema(name="dbo")]),
        fabric=FabricConfig(
            tenant_id="t",
            workspace_id="w",
            mirror_id="m",
            policy_mapping="role_based",
        ),
        dataverse=DataverseSourceConfig(
            environment_url="https://test.crm.dynamics.com"
        ),
    )
    defaults.update(overrides)
    return defaults


class TestDataverseConfigValidation(unittest.TestCase):
    """Validation must reject missing or malformed Dataverse config early."""

    def test_missing_dataverse_section_raises_valueerror(self) -> None:
        """dataverse=None must raise with a clear message."""
        cfg = DataverseSourceMap(**_base_config(dataverse=None))
        with self.assertRaises(ValueError) as ctx:
            DataversePolicyWeaver(cfg)
        self.assertIn(
            "DataverseSourceMap configuration is required", str(ctx.exception)
        )

    def test_missing_environment_url_raises_valueerror(self) -> None:
        """environment_url=None must raise."""
        cfg = DataverseSourceMap(
            **_base_config(dataverse=DataverseSourceConfig(environment_url=None))
        )
        with self.assertRaises(ValueError) as ctx:
            DataversePolicyWeaver(cfg)
        self.assertIn("environment_url is required", str(ctx.exception))

    def test_empty_environment_url_raises_valueerror(self) -> None:
        """environment_url='' must raise."""
        cfg = DataverseSourceMap(
            **_base_config(dataverse=DataverseSourceConfig(environment_url=""))
        )
        with self.assertRaises(ValueError) as ctx:
            DataversePolicyWeaver(cfg)
        self.assertIn("environment_url is required", str(ctx.exception))

    def test_http_environment_url_raises_valueerror(self) -> None:
        """Plain http:// URLs must be rejected (requires https)."""
        cfg = DataverseSourceMap(
            **_base_config(
                dataverse=DataverseSourceConfig(
                    environment_url="http://org.crm.dynamics.com"
                )
            )
        )
        with self.assertRaises(ValueError) as ctx:
            DataversePolicyWeaver(cfg)
        self.assertIn("must start with 'https://'", str(ctx.exception))

    def test_non_url_environment_url_raises_valueerror(self) -> None:
        """Arbitrary strings without https:// prefix must be rejected."""
        cfg = DataverseSourceMap(
            **_base_config(
                dataverse=DataverseSourceConfig(environment_url="org.crm.dynamics.com")
            )
        )
        with self.assertRaises(ValueError) as ctx:
            DataversePolicyWeaver(cfg)
        self.assertIn("must start with 'https://'", str(ctx.exception))

    def test_environment_url_without_hostname_raises_valueerror(self) -> None:
        cfg = DataverseSourceMap(
            **_base_config(dataverse=DataverseSourceConfig(environment_url="https://"))
        )

        with self.assertRaisesRegex(ValueError, "valid hostname"):
            DataversePolicyWeaver(cfg)

    def test_environment_url_with_path_raises_valueerror(self) -> None:
        cfg = DataverseSourceMap(
            **_base_config(
                dataverse=DataverseSourceConfig(
                    environment_url="https://org.crm.dynamics.com/api/data/v9.2"
                )
            )
        )

        with self.assertRaisesRegex(ValueError, "origin only"):
            DataversePolicyWeaver(cfg)

    def test_environment_url_with_embedded_credentials_raises_valueerror(self) -> None:
        cfg = DataverseSourceMap(
            **_base_config(
                dataverse=DataverseSourceConfig(
                    environment_url="https://user:password@org.crm.dynamics.com"
                )
            )
        )

        with self.assertRaisesRegex(ValueError, "embedded credentials"):
            DataversePolicyWeaver(cfg)

    def test_valid_config_does_not_raise(self) -> None:
        """A well-formed config must pass validation without error."""
        cfg = DataverseSourceMap(**_base_config())
        # Should not raise — instantiation succeeds.
        weaver = DataversePolicyWeaver(cfg)
        self.assertIsNotNone(weaver)

    def test_strict_and_partial_sync_cannot_both_be_enabled(self) -> None:
        cfg = DataverseSourceMap(
            **_base_config(
                dataverse=DataverseSourceConfig(
                    environment_url="https://test.crm.dynamics.com",
                    strict_access_parity=True,
                    partial_sync=True,
                )
            )
        )

        with self.assertRaisesRegex(ValueError, "cannot both be true"):
            DataversePolicyWeaver(cfg)

    def test_invalid_column_masking_status_is_rejected(self) -> None:
        cfg = DataverseSourceMap(
            **_base_config(
                dataverse=DataverseSourceConfig(
                    environment_url="https://test.crm.dynamics.com",
                    column_masking_status="assumed_safe",
                )
            )
        )

        with self.assertRaisesRegex(ValueError, "column_masking_status"):
            DataversePolicyWeaver(cfg)

    def test_missing_rls_config_is_created_and_enabled(self) -> None:
        cfg = DataverseSourceMap(**_base_config(constraints=None))

        DataversePolicyWeaver(cfg)

        self.assertIsNotNone(cfg.constraints)
        self.assertIsNotNone(cfg.constraints.rows)
        self.assertTrue(cfg.constraints.rows.rowlevelsecurity)

    def test_disabled_rls_config_is_overridden_to_enabled(self) -> None:
        cfg = DataverseSourceMap(
            **_base_config(
                constraints=ConstraintsConfig(
                    rows=RowConstraintsConfig(rowlevelsecurity=False)
                )
            )
        )

        DataversePolicyWeaver(cfg)

        self.assertTrue(cfg.constraints.rows.rowlevelsecurity)

    def test_table_based_policy_mapping_raises_valueerror(self) -> None:
        """table_based mode is structurally incompatible with Dataverse depth/CLS."""
        cfg = DataverseSourceMap(**_base_config())
        weaver = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        weaver.config = cfg
        weaver.logger = __import__("logging").getLogger("test")
        with self.assertRaises(ValueError) as ctx:
            weaver.map_policy("table_based")
        self.assertIn("role_based", str(ctx.exception))

    def test_default_policy_mapping_does_not_raise(self) -> None:
        """Default parameter is role_based and should not raise ValueError."""
        cfg = DataverseSourceMap(**_base_config())
        weaver = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        weaver.config = cfg
        weaver.logger = __import__("logging").getLogger("test")
        weaver.api_client = type(
            "Stub",
            (),
            {
                "get_environment_security_map": staticmethod(
                    lambda _: __import__(
                        "policyweaver.plugins.dataverse.model",
                        fromlist=["DataverseEnvironment"],
                    ).DataverseEnvironment()
                )
            },
        )()
        # A successful empty extraction is authoritative, not an ambiguous failure.
        cfg.dataverse.strict_access_parity = False
        result = weaver.map_policy()
        self.assertIsNotNone(result)
        self.assertEqual([], result.policies)

    def _strict_weaver(
        self,
        environment: DataverseEnvironment,
        poa_status: str = "verified_empty",
    ) -> DataversePolicyWeaver:
        cfg = DataverseSourceMap(
            **_base_config(
                constraints=ConstraintsConfig(
                    columns=ColumnConstraintsConfig(columnlevelsecurity=True)
                ),
                dataverse=DataverseSourceConfig(
                    environment_url="https://test.crm.dynamics.com",
                    poa_read_access_status=poa_status,
                ),
            )
        )
        weaver = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        weaver.config = cfg
        weaver.environment = environment
        weaver.logger = __import__("logging").getLogger("test")
        return weaver

    def test_strict_mode_rejects_unverified_poa_coverage(self) -> None:
        weaver = self._strict_weaver(DataverseEnvironment(), "unverified")

        with self.assertRaisesRegex(ValueError, "POA.*unverified"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_poaa_read_grants(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                principal_object_attribute_accesses=[
                    DataversePrincipalObjectAttributeAccess(
                        id="poaa-1", read_access=True
                    )
                ]
            )
        )

        with self.assertRaisesRegex(ValueError, "POAA"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_record_filter_privileges(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                role_privileges=[
                    DataverseRolePrivilege(
                        role_id="role-1",
                        entity_name="account",
                        can_read=True,
                        record_filter_id="filter-1",
                    )
                ]
            )
        )

        with self.assertRaisesRegex(ValueError, "RecordFilter"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_enabled_hierarchy_security(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                hierarchy_security_enabled=True,
                hierarchy_security_uses_position=True,
                hierarchy_security_depth=3,
            )
        )

        with self.assertRaisesRegex(ValueError, "hierarchy security"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_dynamic_entra_group_team_roles(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                teams=[DataverseTeam(id="team-1", team_type=2)],
                team_role_assignments={"team-1": ["role-1"]},
            )
        )

        with self.assertRaisesRegex(ValueError, "group-team"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_dynamic_group_team_field_profile(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                teams=[DataverseTeam(id="team-1", team_type=2)],
                field_security_profiles=[
                    DataverseFieldSecurityProfile(id="profile-1", team_ids=["team-1"])
                ],
            )
        )

        with self.assertRaisesRegex(ValueError, "group-team field security"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_unknown_privilege_depth(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                role_privileges=[
                    DataverseRolePrivilege(
                        role_id="role-1",
                        entity_name="account",
                        depth="Unknown",
                        can_read=True,
                    )
                ]
            )
        )

        with self.assertRaisesRegex(ValueError, "unknown privilege depth"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_missing_role_inheritance_mode(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                security_roles=[DataverseSecurityRole(id="role-1")],
                team_role_assignments={"team-1": ["role-1"]},
            )
        )

        with self.assertRaisesRegex(ValueError, "inheritance mode"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_assignment_to_missing_role(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(user_role_assignments={"user-1": ["missing-role"]})
        )

        with self.assertRaisesRegex(ValueError, "assigned role"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_orphaned_business_unit_parent(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                business_units=[
                    DataverseBusinessUnit(
                        id="bu-child", parent_business_unit_id="missing-parent"
                    )
                ]
            )
        )

        with self.assertRaisesRegex(ValueError, "business unit hierarchy"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_business_unit_cycle(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                business_units=[
                    DataverseBusinessUnit(id="bu-a", parent_business_unit_id="bu-b"),
                    DataverseBusinessUnit(id="bu-b", parent_business_unit_id="bu-a"),
                ]
            )
        )

        with self.assertRaisesRegex(ValueError, "business unit hierarchy"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_cross_bu_role_assignment(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                business_units=[
                    DataverseBusinessUnit(id="bu-a"),
                    DataverseBusinessUnit(id="bu-b"),
                ],
                users=[DataverseUser(id="user-1", business_unit_id="bu-a")],
                security_roles=[
                    DataverseSecurityRole(
                        id="role-1", business_unit_id="bu-b", is_inherited=1
                    )
                ],
                user_role_assignments={"user-1": ["role-1"]},
            )
        )

        with self.assertRaisesRegex(ValueError, "role assignment context"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_missing_table_ownership_metadata(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                role_privileges=[
                    DataverseRolePrivilege(
                        role_id="role-1",
                        entity_name="account",
                        depth="Global",
                        can_read=True,
                    )
                ]
            )
        )

        with self.assertRaisesRegex(ValueError, "ownership metadata"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_allows_global_business_owned_table(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                role_privileges=[
                    DataverseRolePrivilege(
                        role_id="role-1",
                        entity_name="account",
                        depth="Global",
                        can_read=True,
                    )
                ],
                table_metadata=[
                    DataverseTableMetadata(
                        logical_name="account", ownership_type="BusinessOwned"
                    )
                ],
            )
        )

        weaver.__validate_security_coverage__()

    def test_strict_mode_allows_local_business_owned_table(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
                security_roles=[
                    DataverseSecurityRole(
                        id="role-1",
                        name="Basic User",
                        business_unit_id="bu-root",
                    )
                ],
                role_privileges=[
                    DataverseRolePrivilege(
                        role_id="role-1",
                        entity_name="role",
                        depth="Local",
                        can_read=True,
                    )
                ],
                table_metadata=[
                    DataverseTableMetadata(
                        logical_name="role", ownership_type="BusinessOwned"
                    )
                ],
            )
        )

        weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_basic_business_owned_table(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                role_privileges=[
                    DataverseRolePrivilege(
                        role_id="role-1",
                        entity_name="role",
                        depth="Basic",
                        can_read=True,
                    )
                ],
                table_metadata=[
                    DataverseTableMetadata(
                        logical_name="role", ownership_type="BusinessOwned"
                    )
                ],
            )
        )

        with self.assertRaisesRegex(ValueError, "scoped read grants"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_contradictory_field_security_metadata(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                role_privileges=[
                    DataverseRolePrivilege(
                        role_id="role-1",
                        entity_name="account",
                        depth="Global",
                        can_read=True,
                    )
                ],
                field_security_profiles=[
                    DataverseFieldSecurityProfile(
                        id="profile-1",
                        permissions=[
                            DataverseFieldPermission(
                                entity_name="account",
                                attribute_logical_name="secretcolumn",
                                can_read=4,
                            )
                        ],
                    )
                ],
                table_metadata=[
                    DataverseTableMetadata(
                        logical_name="account",
                        ownership_type="UserOwned",
                        has_secured_columns=False,
                        columns=[
                            DataverseColumnMetadata(
                                logical_name="accountid", is_secured=False
                            )
                        ],
                    )
                ],
            )
        )

        with self.assertRaisesRegex(ValueError, "contradictory field-security"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_active_masking_with_unsecured_metadata(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                role_privileges=[
                    DataverseRolePrivilege(
                        role_id="role-1",
                        entity_name="account",
                        depth="Global",
                        can_read=True,
                    )
                ],
                attribute_masking_rules=[
                    DataverseAttributeMaskingRule(
                        id="assignment-1",
                        entity_name="account",
                        attribute_logical_name="secretcolumn",
                        masking_rule_id="mask-1",
                    )
                ],
                table_metadata=[
                    DataverseTableMetadata(
                        logical_name="account",
                        ownership_type="UserOwned",
                        has_secured_columns=False,
                    )
                ],
            )
        )
        weaver.config.dataverse.column_masking_status = "verified_absent"

        with self.assertRaisesRegex(ValueError, "column masking"):
            weaver.__validate_security_coverage__()

    def test_strict_mode_rejects_scoped_organization_owned_grant(self) -> None:
        weaver = self._strict_weaver(
            DataverseEnvironment(
                role_privileges=[
                    DataverseRolePrivilege(
                        role_id="role-1",
                        entity_name="account",
                        depth="Local",
                        can_read=True,
                    )
                ],
                table_metadata=[
                    DataverseTableMetadata(
                        logical_name="account", ownership_type="OrganizationOwned"
                    )
                ],
            )
        )

        with self.assertRaisesRegex(ValueError, "OrganizationOwned"):
            weaver.__validate_security_coverage__()


if __name__ == "__main__":
    unittest.main()
