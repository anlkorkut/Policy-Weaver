import asyncio
import json
import logging
import os
import unittest
from argparse import Namespace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from httpx import RemoteProtocolError

from policyweaver.core.enum import IamType
from policyweaver.core.exception import FabricCapacityNotActiveError
from policyweaver.models.config import (
    ColumnConstraintsConfig,
    ConstraintsConfig,
    FabricConfig,
    RowConstraintsConfig,
    Source,
    SourceSchema,
)
from policyweaver.plugins.dataverse.client import (
    DataversePolicyWeaver,
    is_dataverse_export_validated,
    is_strict_dataverse_export_validated,
)
from policyweaver.plugins.dataverse.model import (
    DataverseBusinessUnit,
    DataverseAttributeMaskingRule,
    DataverseColumnMetadata,
    DataverseEnvironment,
    DataverseFieldPermission,
    DataverseFieldSecurityProfile,
    DataverseRolePrivilege,
    DataverseSecurityRole,
    DataverseSourceConfig,
    DataverseSourceMap,
    DataverseTeam,
    DataverseTableMetadata,
    DataverseTablePermission,
    DataverseUser,
)
from scripts.dataverse_policy_sync import (
    configure_source_tables,
    configure_sync_mode,
    main,
    resolve_application_ids,
    run_cli,
)


def _config(
    *, role_limit: int = 1000, column_security: bool = True
) -> DataverseSourceMap:
    return DataverseSourceMap(
        source=Source(name="Dataverse", schemas=[SourceSchema(name="dbo")]),
        fabric=FabricConfig(
            tenant_id="tenant-id",
            workspace_id="workspace-id",
            mirror_id="item-id",
            fabric_role_suffix="PWPolicy",
            delete_default_reader_role=True,
            policy_mapping="role_based",
        ),
        constraints=ConstraintsConfig(
            columns=ColumnConstraintsConfig(columnlevelsecurity=column_security),
            rows=RowConstraintsConfig(rowlevelsecurity=True),
        ),
        dataverse=DataverseSourceConfig(
            environment_url="https://example.crm.dynamics.com",
            onelake_role_limit=role_limit,
            strict_access_parity=False,
            partial_sync=True,
            column_masking_status="verified_absent",
            poa_read_access_status="unverified",
        ),
    )


def _user(user_id: str = "user-1") -> DataverseUser:
    return DataverseUser(
        id=user_id,
        azure_ad_object_id=f"entra-{user_id}",
        business_unit_id="bu-root",
        access_mode=0,
        is_licensed=True,
        azure_state=0,
    )


def _role(role_id: str, name: str) -> DataverseSecurityRole:
    return DataverseSecurityRole(
        id=role_id,
        name=name,
        business_unit_id="bu-root",
        is_inherited=1,
    )


def _privilege(
    role_id: str,
    table_name: str,
    depth: str = "Global",
    record_filter_id: str | None = None,
) -> DataverseRolePrivilege:
    return DataverseRolePrivilege(
        privilege_id=f"priv-{role_id}-{table_name}",
        role_id=role_id,
        entity_name=table_name,
        depth=depth,
        can_read=True,
        record_filter_id=record_filter_id,
    )


def _metadata(
    table_name: str, ownership_type: str = "UserOwned"
) -> DataverseTableMetadata:
    return DataverseTableMetadata(
        logical_name=table_name,
        ownership_type=ownership_type,
        has_secured_columns=False,
    )


def _secured_metadata(table_name: str = "account") -> DataverseTableMetadata:
    return DataverseTableMetadata(
        logical_name=table_name,
        ownership_type="UserOwned",
        has_secured_columns=True,
        columns=[
            DataverseColumnMetadata(
                metadata_id=f"{table_name}-id",
                logical_name=f"{table_name}id",
                is_secured=False,
            ),
            DataverseColumnMetadata(
                metadata_id=f"{table_name}-secret-id",
                logical_name="secretcolumn",
                is_secured=True,
            ),
        ],
    )


def _owner_teams(
    user_id: str, *, business_unit_id: str = "bu-root", count: int = 12
) -> list[DataverseTeam]:
    return [
        DataverseTeam(
            id=f"owner-team-{index:02d}",
            team_type=0,
            business_unit_id=business_unit_id,
            member_ids=[user_id],
        )
        for index in range(count)
    ]


def _client(
    environment: DataverseEnvironment, config: DataverseSourceMap
) -> DataversePolicyWeaver:
    client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
    client.config = config
    client.environment = environment
    client.logger = logging.getLogger("test_dataverse_partial_sync")
    client.partial_sync_report = {}
    return client


def _two_role_environment(
    *,
    bad_depth: str = "Global",
    bad_record_filter_id: str | None = None,
    bad_ownership_type: str = "UserOwned",
) -> DataverseEnvironment:
    user = _user()
    return DataverseEnvironment(
        users=[user],
        business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
        security_roles=[
            _role("role-good", "Good Reader"),
            _role("role-bad", "Bad Reader"),
        ],
        role_privileges=[
            _privilege("role-good", "account"),
            _privilege(
                "role-bad",
                "contact",
                depth=bad_depth,
                record_filter_id=bad_record_filter_id,
            ),
        ],
        user_role_assignments={user.id: ["role-good", "role-bad"]},
        table_metadata=[
            _metadata("account"),
            _metadata("contact", bad_ownership_type),
        ],
    )


class TestDataversePartialSync(unittest.TestCase):
    def test_tables_file_sets_deduplicated_scope_when_config_has_no_tables(
        self,
    ) -> None:
        config = _config()
        with TemporaryDirectory() as directory:
            path = Path(directory) / "tables.txt"
            path.write_text(
                "# Mirrored tables\naccount\nContact\nACCOUNT\n\n",
                encoding="utf-8",
            )

            scope = configure_source_tables(config, str(path))

        self.assertEqual(["account", "Contact"], config.source.schemas[0].tables)
        self.assertEqual(2, scope["table_count"])
        self.assertEqual("dbo", scope["schema"])
        self.assertEqual(str(path.resolve()), scope["path"])

    def test_tables_file_intersects_existing_scope_case_insensitively(self) -> None:
        config = _config()
        config.source.schemas[0].tables = ["Account", "CONTACT", "lead"]
        with TemporaryDirectory() as directory:
            path = Path(directory) / "tables.txt"
            path.write_text(
                "contact\naccount\nopportunity\nACCOUNT\n",
                encoding="utf-8",
            )

            scope = configure_source_tables(config, str(path))

        self.assertEqual(["account", "contact"], config.source.schemas[0].tables)
        self.assertEqual(2, scope["table_count"])
        self.assertEqual(str(path.resolve()), scope["path"])

    def test_tables_file_intersects_allowlists_across_all_schemas(self) -> None:
        config = _config()
        config.source.schemas = [
            SourceSchema(tables=["account"]),
            SourceSchema(name="secondary", tables=["Contact"]),
        ]
        with TemporaryDirectory() as directory:
            path = Path(directory) / "tables.txt"
            path.write_text("contact\nopportunity\n", encoding="utf-8")

            scope = configure_source_tables(config, str(path))

        self.assertEqual("secondary", config.source.schemas[0].name)
        self.assertEqual(["contact"], config.source.schemas[0].tables)
        self.assertEqual(1, scope["table_count"])
        self.assertEqual("secondary", scope["schema"])

    def test_tables_file_rejects_empty_intersection_with_existing_scope(self) -> None:
        config = _config()
        config.source.schemas = [
            SourceSchema(name="dbo", tables=["account"]),
            SourceSchema(name="secondary", tables=["contact"]),
        ]
        with TemporaryDirectory() as directory:
            path = Path(directory) / "tables.txt"
            path.write_text("lead\nopportunity\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "no tables in common"):
                configure_source_tables(config, str(path))

        self.assertEqual(["account"], config.source.schemas[0].tables)
        self.assertEqual(["contact"], config.source.schemas[1].tables)

    def test_tables_file_rejects_invalid_logical_name(self) -> None:
        config = _config()
        with TemporaryDirectory() as directory:
            path = Path(directory) / "tables.txt"
            path.write_text("account\naccount;drop table role\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "line 2"):
                configure_source_tables(config, str(path))

    def test_tables_file_rejects_empty_scope(self) -> None:
        config = _config()
        with TemporaryDirectory() as directory:
            path = Path(directory) / "tables.txt"
            path.write_text("# no tables\n\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "contains no table names"):
                configure_source_tables(config, str(path))

    def test_main_reports_mixed_case_deduplicated_table_scope(self) -> None:
        config = _config()
        config.dataverse.partial_sync = False
        config.service_principal = SimpleNamespace(
            tenant_id="tenant-id",
            client_id="client-id",
            client_secret="client-secret",
        )
        mapper = unittest.mock.Mock()
        mapper.environment = _two_role_environment()
        mapper.map_policy.return_value = SimpleNamespace(policies=[])

        with TemporaryDirectory() as directory:
            tables_path = Path(directory) / "tables.txt"
            tables_path.write_text("account\nACCOUNT\n", encoding="utf-8")
            output_path = Path(directory) / "compile-report.json"
            args = Namespace(
                config="unused.yaml",
                tables_file=str(tables_path),
                output=str(output_path),
                rollback_output=str(Path(directory) / "rollback.json"),
                fabric_dry_run=False,
                apply=False,
                rollback=None,
                assessment_mode=True,
                partial_sync=False,
                confirm_partial_sync=False,
                confirm_item=None,
                log_level="ERROR",
            )

            with (
                patch("scripts.dataverse_policy_sync.parse_args", return_value=args),
                patch.object(DataverseSourceMap, "from_yaml", return_value=config),
                patch(
                    "scripts.dataverse_policy_sync.Configuration.configure_environment"
                ),
                patch("scripts.dataverse_policy_sync.ServicePrincipal.initialize"),
                patch(
                    "scripts.dataverse_policy_sync.DataversePolicyWeaver",
                    return_value=mapper,
                ),
            ):
                main()

            report = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(["account"], config.source.schemas[0].tables)
        self.assertEqual(
            {
                "path": str(tables_path.resolve()),
                "schema": "dbo",
                "table_count": 1,
            },
            report["source_table_scope"],
        )

    def test_inactive_capacity_stops_before_dataverse_extraction(self) -> None:
        config = _config()
        config.service_principal = SimpleNamespace(
            tenant_id="tenant-id",
            client_id="client-id",
            client_secret="client-secret",
        )
        mapper = unittest.mock.Mock()
        mapper.environment = None
        agent = unittest.mock.Mock()
        agent.validate_role_target_write_ready.side_effect = (
            FabricCapacityNotActiveError("capacity-id", "workspace-id", "item-id")
        )

        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "preflight.json"
            args = Namespace(
                config="unused.yaml",
                output=str(output_path),
                rollback_output=str(Path(directory) / "rollback.json"),
                fabric_dry_run=True,
                apply=False,
                rollback=None,
                assessment_mode=False,
                partial_sync=True,
                confirm_partial_sync=False,
                confirm_item="item-id",
                log_level="ERROR",
            )

            with (
                patch("scripts.dataverse_policy_sync.parse_args", return_value=args),
                patch.object(DataverseSourceMap, "from_yaml", return_value=config),
                patch(
                    "scripts.dataverse_policy_sync.Configuration.configure_environment"
                ),
                patch("scripts.dataverse_policy_sync.ServicePrincipal.initialize"),
                patch(
                    "scripts.dataverse_policy_sync.DataversePolicyWeaver",
                    return_value=mapper,
                ),
                patch(
                    "scripts.dataverse_policy_sync.WeaverAgent",
                    return_value=agent,
                ),
                self.assertRaises(FabricCapacityNotActiveError),
            ):
                main()

            report = json.loads(output_path.read_text(encoding="utf-8"))

        mapper.map_policy.assert_not_called()
        self.assertEqual("failed", report["status"])
        self.assertEqual("capacity-id", report["fabric_capacity_id"])
        self.assertEqual(
            "blocked-capacity-not-active", report["fabric_write_preflight"]
        )
        self.assertEqual("readiness", report["fabric_operation_stage"])
        self.assertEqual(
            "blocked-capacity-not-active", report["fabric_operation_status"]
        )

    def test_late_capacity_failure_preserves_validated_preflight(self) -> None:
        for apply, expected_stage in (
            (False, "candidate-dry-run"),
            (True, "candidate-apply"),
        ):
            with self.subTest(apply=apply):
                config = _config()
                config.dataverse.partial_sync = False
                config.dataverse.strict_access_parity = True
                config.service_principal = SimpleNamespace(
                    tenant_id="tenant-id",
                    client_id="client-id",
                    client_secret="client-secret",
                )
                mapper = unittest.mock.Mock()
                mapper.environment = _two_role_environment()
                mapper.map_policy.return_value = SimpleNamespace(policies=[])
                mapper.get_strict_application_ids_to_validate.return_value = set()
                agent = unittest.mock.Mock()
                agent.apply_role = AsyncMock(
                    side_effect=FabricCapacityNotActiveError(
                        "capacity-id", "workspace-id", "item-id"
                    )
                )

                with TemporaryDirectory() as directory:
                    output_path = Path(directory) / "operation.json"
                    args = Namespace(
                        config="unused.yaml",
                        output=str(output_path),
                        rollback_output=str(Path(directory) / "rollback.json"),
                        fabric_dry_run=not apply,
                        apply=apply,
                        rollback=None,
                        assessment_mode=False,
                        partial_sync=False,
                        confirm_partial_sync=False,
                        confirm_item="item-id",
                        log_level="ERROR",
                    )

                    with (
                        patch(
                            "scripts.dataverse_policy_sync.parse_args",
                            return_value=args,
                        ),
                        patch.object(
                            DataverseSourceMap, "from_yaml", return_value=config
                        ),
                        patch(
                            "scripts.dataverse_policy_sync.Configuration.configure_environment"
                        ),
                        patch(
                            "scripts.dataverse_policy_sync.ServicePrincipal.initialize"
                        ),
                        patch(
                            "scripts.dataverse_policy_sync.DataversePolicyWeaver",
                            return_value=mapper,
                        ),
                        patch(
                            "scripts.dataverse_policy_sync.WeaverAgent",
                            return_value=agent,
                        ),
                        self.assertRaises(FabricCapacityNotActiveError),
                    ):
                        main()

                    report = json.loads(output_path.read_text(encoding="utf-8"))

                self.assertEqual("failed", report["status"])
                self.assertEqual("validated", report["fabric_write_preflight"])
                self.assertEqual(expected_stage, report["fabric_operation_stage"])
                self.assertEqual(
                    "blocked-capacity-not-active",
                    report["fabric_operation_status"],
                )

    def test_cli_prints_concise_inactive_capacity_error(self) -> None:
        error = FabricCapacityNotActiveError("capacity-id", "workspace-id", "item-id")

        with (
            patch(
                "scripts.dataverse_policy_sync.main",
                side_effect=error,
            ),
            self.assertRaises(SystemExit) as raised,
        ):
            run_cli()

        self.assertIn("capacity-id", str(raised.exception))
        self.assertIn("No roles were changed", str(raised.exception))

    def test_apply_rejects_output_rollback_alias_before_config_load(self) -> None:
        output_path = "partial-sync-collision.json"
        args = Namespace(
            apply=True,
            output=output_path,
            rollback_output=str((Path.cwd() / output_path).resolve()),
        )

        with (
            patch("scripts.dataverse_policy_sync.parse_args", return_value=args),
            patch.object(DataverseSourceMap, "from_yaml") as load_config,
            self.assertRaisesRegex(ValueError, "identify different files"),
        ):
            main()

        load_config.assert_not_called()

    def test_apply_rejects_hard_link_paths_before_config_load(self) -> None:
        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "apply-report.json"
            rollback_path = Path(directory) / "rollback-snapshot.json"
            output_path.write_text("existing report", encoding="utf-8")
            os.link(output_path, rollback_path)
            args = Namespace(
                apply=True,
                output=str(output_path),
                rollback_output=str(rollback_path),
                log_level="INFO",
                config="unused.yaml",
            )

            with (
                patch("scripts.dataverse_policy_sync.parse_args", return_value=args),
                patch.object(
                    DataverseSourceMap,
                    "from_yaml",
                    side_effect=AssertionError("config loaded before path validation"),
                ) as load_config,
                self.assertRaisesRegex(ValueError, "identify different files"),
            ):
                main()

            load_config.assert_not_called()

    def test_graph_transport_failure_is_quarantined_as_unresolved(self) -> None:
        graph_client = unittest.mock.Mock()
        graph_client.get_service_principal_by_id = AsyncMock(
            side_effect=RemoteProtocolError("connection closed")
        )

        with patch(
            "scripts.dataverse_policy_sync.MicrosoftGraphClient",
            return_value=graph_client,
        ):
            unresolved = asyncio.run(resolve_application_ids({"application-id"}))

        self.assertEqual({"application-id"}, unresolved)

    def test_partial_sync_requires_column_security(self) -> None:
        environment = _two_role_environment()
        client = _client(environment, _config(column_security=False))

        with self.assertRaisesRegex(ValueError, "requires column-level security"):
            client.__build_role_based_export__()

    def test_unverified_masking_quarantines_secured_table_role(self) -> None:
        user = _user()
        environment = DataverseEnvironment(
            users=[user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-secured", "Secured Reader")],
            role_privileges=[_privilege("role-secured", "account")],
            user_role_assignments={user.id: ["role-secured"]},
            table_metadata=[
                DataverseTableMetadata(
                    logical_name="account",
                    ownership_type="UserOwned",
                    has_secured_columns=True,
                    columns=[
                        DataverseColumnMetadata(
                            metadata_id="secret-id",
                            logical_name="secretcolumn",
                            is_secured=True,
                        )
                    ],
                )
            ],
        )
        config = _config()
        config.dataverse.column_masking_status = "unverified"
        client = _client(environment, config)

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual([], export.policies)
        self.assertIn(
            "column_masking_unverified", report["skipped_roles"][0]["reasons"]
        )

    def test_checked_absent_masking_allows_secured_table_role(self) -> None:
        user = _user()
        environment = DataverseEnvironment(
            users=[user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-secured", "Secured Reader")],
            role_privileges=[_privilege("role-secured", "account")],
            user_role_assignments={user.id: ["role-secured"]},
            attribute_masking_rules=[],
            table_metadata=[
                DataverseTableMetadata(
                    logical_name="account",
                    ownership_type="UserOwned",
                    has_secured_columns=True,
                    columns=[
                        DataverseColumnMetadata(
                            metadata_id="name-id",
                            logical_name="name",
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
        config = _config()
        config.dataverse.column_masking_status = "unverified"
        client = _client(environment, config)

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertNotIn("column_masking_unverified", report["reason_counts"])

    def test_active_masking_rule_quarantines_affected_table_role(self) -> None:
        user = _user()
        environment = DataverseEnvironment(
            users=[user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-masked", "Masked Reader"),
                _role("role-unaffected", "Unaffected Reader"),
            ],
            role_privileges=[
                _privilege("role-masked", "account"),
                _privilege("role-masked", "contact"),
                _privilege("role-unaffected", "contact"),
            ],
            user_role_assignments={
                user.id: ["role-masked", "role-unaffected"],
            },
            attribute_masking_rules=[
                DataverseAttributeMaskingRule(
                    id="assignment-id",
                    entity_name="account",
                    attribute_logical_name="secretcolumn",
                    masking_rule_id="mask-id",
                )
            ],
            table_metadata=[
                DataverseTableMetadata(
                    logical_name="account",
                    ownership_type="UserOwned",
                    has_secured_columns=False,
                ),
                _metadata("contact"),
            ],
        )
        client = _client(environment, _config())

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertIn("Unaffected Reader", export.policies[0].name)
        self.assertEqual(1, report["skipped_role_count"])
        self.assertEqual("Masked Reader", report["skipped_roles"][0]["role_name"])
        self.assertEqual(["account"], report["skipped_roles"][0]["tables"])
        self.assertIn(
            "column_masking_not_supported",
            report["skipped_roles"][0]["reasons"],
        )

    def test_partial_apply_requires_explicit_acknowledgement(self) -> None:
        config = _config()
        config.dataverse.partial_sync = False
        args = Namespace(
            assessment_mode=False,
            partial_sync=True,
            confirm_partial_sync=False,
            fabric_dry_run=False,
            apply=True,
            rollback=None,
            confirm_item="item-id",
        )

        with self.assertRaisesRegex(ValueError, "confirm-partial-sync"):
            configure_sync_mode(config, args)

    def test_partial_dry_run_enables_only_partial_mode(self) -> None:
        config = _config()
        config.dataverse.partial_sync = False
        config.dataverse.strict_access_parity = True
        args = Namespace(
            assessment_mode=False,
            partial_sync=True,
            confirm_partial_sync=False,
            fabric_dry_run=True,
            apply=False,
            rollback=None,
            confirm_item="item-id",
        )

        configure_sync_mode(config, args)

        self.assertFalse(config.dataverse.strict_access_parity)
        self.assertTrue(config.dataverse.partial_sync)

    def test_partial_dry_run_requires_exact_item_confirmation(self) -> None:
        config = _config()
        config.dataverse.partial_sync = False
        args = Namespace(
            assessment_mode=False,
            partial_sync=True,
            confirm_partial_sync=False,
            fabric_dry_run=True,
            apply=False,
            rollback=None,
            confirm_item="wrong-item",
        )

        with self.assertRaisesRegex(ValueError, "confirm-item"):
            configure_sync_mode(config, args)

    def test_record_filter_role_is_quarantined_and_valid_role_continues(self) -> None:
        environment = _two_role_environment(
            bad_depth="Unknown", bad_record_filter_id="filter-1"
        )
        client = _client(environment, _config())

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertIn("Good Reader", export.policies[0].name)
        self.assertEqual(1, report["included_role_count"])
        self.assertEqual(1, report["skipped_role_count"])
        self.assertEqual("Bad Reader", report["skipped_roles"][0]["role_name"])
        self.assertIn(
            "record_filter_not_supported",
            report["skipped_roles"][0]["reasons"],
        )
        self.assertIn(
            "unknown_privilege_depth",
            report["skipped_roles"][0]["reasons"],
        )
        self.assertNotIn(
            "no_resolvable_members",
            report["skipped_roles"][0]["reasons"],
        )
        self.assertIn(
            "poa_record_shares_unverified",
            {item["code"] for item in report["environment_limitations"]},
        )

    def test_local_business_owned_role_uses_business_unit_id(self) -> None:
        environment = _two_role_environment(
            bad_depth="Local", bad_ownership_type="BusinessOwned"
        )
        client = _client(environment, _config())

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(2, len(export.policies))
        business_owned_policy = next(
            policy for policy in export.policies if "Bad Reader" in policy.name
        )
        self.assertEqual(
            "businessunitid = 'bu-root'",
            business_owned_policy.rowconstraints[0].filter_condition,
        )
        self.assertEqual(0, report["skipped_role_count"])

    def test_scoped_business_owned_roles_never_add_owner_overlays(self) -> None:
        for depth in ("Local", "Deep"):
            with self.subTest(depth=depth):
                users = [_user("first-user"), _user("second-user")]
                environment = DataverseEnvironment(
                    users=users,
                    teams=[
                        DataverseTeam(
                            id="owner-team",
                            team_type=0,
                            business_unit_id="bu-other",
                            member_ids=[users[0].id],
                        )
                    ],
                    business_units=[
                        DataverseBusinessUnit(id="bu-root", name="Root"),
                        DataverseBusinessUnit(id="bu-other", name="Other"),
                    ],
                    security_roles=[_role("role-business", "Business Reader")],
                    role_privileges=[
                        _privilege("role-business", "account", depth=depth)
                    ],
                    user_role_assignments={
                        user.id: ["role-business"] for user in users
                    },
                    table_metadata=[_metadata("account", "BusinessOwned")],
                )
                client = _client(environment, _config())

                export = client.__build_role_based_export__()

                self.assertEqual(1, len(export.policies))
                filter_conditions = [
                    constraint.filter_condition
                    for constraint in export.policies[0].rowconstraints
                ]
                self.assertTrue(
                    all(
                        "businessunitid" in condition for condition in filter_conditions
                    )
                )
                self.assertTrue(
                    all("ownerid" not in condition for condition in filter_conditions)
                )

    def test_basic_business_owned_role_is_quarantined(self) -> None:
        environment = _two_role_environment(
            bad_depth="Basic", bad_ownership_type="BusinessOwned"
        )
        client = _client(environment, _config())

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertIn(
            "unsupported_table_ownership",
            report["skipped_roles"][0]["reasons"],
        )

    def test_basic_business_owned_role_denies_all_in_assessment_mode(self) -> None:
        user = _user()
        environment = DataverseEnvironment(
            users=[user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-business", "Business Reader")],
            role_privileges=[_privilege("role-business", "account", depth="Basic")],
            user_role_assignments={user.id: ["role-business"]},
            table_metadata=[_metadata("account", "BusinessOwned")],
        )
        config = _config()
        config.dataverse.partial_sync = False
        config.dataverse.strict_access_parity = False
        client = _client(environment, config)

        export = client.__build_role_based_export__()

        self.assertEqual(1, len(export.policies))
        self.assertEqual(
            ["false"],
            [
                constraint.filter_condition
                for constraint in export.policies[0].rowconstraints
            ],
        )

    def test_global_business_owned_role_is_transferable(self) -> None:
        environment = _two_role_environment(bad_ownership_type="BusinessOwned")
        client = _client(environment, _config())

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(2, len(export.policies))
        self.assertEqual(0, report["skipped_role_count"])

    def test_capacity_quarantine_is_deterministic(self) -> None:
        user = _user()
        environment = DataverseEnvironment(
            users=[user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-a", "Alpha Reader"),
                _role("role-b", "Beta Reader"),
            ],
            role_privileges=[
                _privilege("role-a", "account"),
                _privilege("role-b", "contact"),
            ],
            user_role_assignments={user.id: ["role-a", "role-b"]},
            table_metadata=[_metadata("account"), _metadata("contact")],
        )
        client = _client(environment, _config(role_limit=1))

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertIn("Alpha Reader", export.policies[0].name)
        self.assertEqual("Beta Reader", report["skipped_roles"][0]["role_name"])
        self.assertIn("onelake_role_capacity", report["skipped_roles"][0]["reasons"])

    def test_scoped_rls_cls_conflicting_roles_are_both_quarantined(self) -> None:
        user = _user()
        environment = DataverseEnvironment(
            users=[user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-local", "Local Reader"),
                _role("role-global", "Global Reader"),
            ],
            role_privileges=[
                _privilege("role-local", "account", depth="Local"),
                _privilege("role-global", "account", depth="Basic"),
            ],
            user_role_assignments={user.id: ["role-local", "role-global"]},
            field_security_profiles=[
                DataverseFieldSecurityProfile(
                    id="profile-1",
                    user_ids=[user.id],
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
                    has_secured_columns=True,
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
        client = _client(environment, _config(column_security=True))

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual([], export.policies)
        self.assertEqual(2, report["skipped_role_count"])
        self.assertTrue(
            all(
                "unsupported_multi_role_rls_cls" in role["reasons"]
                for role in report["skipped_roles"]
            )
        )
        self.assertEqual(
            [
                {
                    "principal_id": user.id,
                    "table_name": "account",
                    "roles": [
                        {
                            "role_id": "role-global",
                            "role_name": "Global Reader",
                            "depth": "Basic",
                        },
                        {
                            "role_id": "role-local",
                            "role_name": "Local Reader",
                            "depth": "Local",
                        },
                    ],
                    "resolution": "quarantined",
                }
            ],
            report["constraint_composition_conflicts"],
        )

    def test_global_dominance_preserves_other_members_and_tables(self) -> None:
        conflict_user = _user("conflict-user")
        local_user = _user("local-user")
        environment = DataverseEnvironment(
            users=[conflict_user, local_user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-local", "Local Reader"),
                _role("role-global", "Global Reader"),
            ],
            role_privileges=[
                _privilege("role-local", "account", depth="Local"),
                _privilege("role-local", "contact", depth="Local"),
                _privilege("role-global", "account", depth="Global"),
            ],
            user_role_assignments={
                conflict_user.id: ["role-local", "role-global"],
                local_user.id: ["role-local"],
            },
            field_security_profiles=[
                DataverseFieldSecurityProfile(
                    id="profile-1",
                    user_ids=[conflict_user.id, local_user.id],
                    permissions=[
                        DataverseFieldPermission(
                            entity_name="account",
                            attribute_logical_name="secretcolumn",
                            can_read=4,
                        )
                    ],
                )
            ],
            table_metadata=[_secured_metadata("account"), _metadata("contact")],
        )
        client = _client(environment, _config(column_security=True))

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(3, len(export.policies))
        policies_by_member = {}
        for policy in export.policies:
            for permission_object in policy.permissionobjects:
                policies_by_member.setdefault(
                    permission_object.entra_object_id, []
                ).append(policy)

        conflict_scopes = [
            {scope.table for scope in policy.permissionscopes}
            for policy in policies_by_member[conflict_user.azure_ad_object_id]
        ]
        local_scopes = [
            {scope.table for scope in policy.permissionscopes}
            for policy in policies_by_member[local_user.azure_ad_object_id]
        ]
        self.assertCountEqual([{"account"}, {"contact"}], conflict_scopes)
        self.assertEqual([{"account", "contact"}], local_scopes)
        self.assertEqual(0, report["skipped_role_count"])
        self.assertEqual(1, report["suppressed_redundant_scoped_grant_count"])
        self.assertEqual(
            "suppressed_redundant_scoped_grants",
            report["constraint_composition_conflicts"][0]["resolution"],
        )

    def test_global_suppression_is_removed_when_dominator_leaves_final_set(
        self,
    ) -> None:
        user = _user()
        environment = DataverseEnvironment(
            users=[user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-account-local", "Alpha Account Local"),
                _role("role-mixed", "Beta Mixed Global"),
                _role("role-contact-local", "Gamma Contact Local"),
                _role("role-contact-global", "Zulu Contact Global"),
            ],
            role_privileges=[
                _privilege("role-account-local", "account", depth="Local"),
                _privilege("role-mixed", "account", depth="Global"),
                _privilege("role-mixed", "contact", depth="Local"),
                _privilege("role-contact-local", "contact", depth="Local"),
                _privilege("role-contact-global", "contact", depth="Global"),
            ],
            user_role_assignments={
                user.id: [
                    "role-account-local",
                    "role-mixed",
                    "role-contact-local",
                    "role-contact-global",
                ]
            },
            table_metadata=[
                _secured_metadata("account"),
                _secured_metadata("contact"),
            ],
        )
        client = _client(environment, _config(role_limit=1))

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertIn("Alpha Account Local", export.policies[0].name)
        self.assertEqual(
            {"account"},
            {scope.table for scope in export.policies[0].permissionscopes},
        )
        self.assertEqual(
            {"account"},
            {constraint.table_name for constraint in export.policies[0].rowconstraints},
        )
        self.assertEqual(0, report["suppressed_redundant_scoped_grant_count"])
        skipped_by_name = {
            role["role_name"]: role["reasons"] for role in report["skipped_roles"]
        }
        self.assertIn("onelake_role_capacity", skipped_by_name["Zulu Contact Global"])
        self.assertIn(
            "unsupported_multi_role_rls_cls",
            skipped_by_name["Beta Mixed Global"],
        )
        self.assertIn(
            "unsupported_multi_role_rls_cls",
            skipped_by_name["Gamma Contact Local"],
        )

    def test_capacity_selection_counts_suppression_residual_roles(self) -> None:
        account_user = _user("account-user")
        contact_user = _user("contact-user")
        environment = DataverseEnvironment(
            users=[account_user, contact_user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-local", "Zulu Shared Local"),
                _role("role-account-global", "Alpha Account Global"),
                _role("role-contact-global", "Beta Contact Global"),
            ],
            role_privileges=[
                _privilege("role-local", "account", depth="Local"),
                _privilege("role-local", "contact", depth="Local"),
                _privilege("role-account-global", "account", depth="Global"),
                _privilege("role-contact-global", "contact", depth="Global"),
            ],
            user_role_assignments={
                account_user.id: ["role-local", "role-account-global"],
                contact_user.id: ["role-local", "role-contact-global"],
            },
            table_metadata=[
                _secured_metadata("account"),
                _secured_metadata("contact"),
            ],
        )
        client = _client(environment, _config(role_limit=3))

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(2, len(export.policies))
        self.assertLessEqual(report["projected_onelake_role_count"], 3)
        skipped_by_name = {
            role["role_name"]: role["reasons"] for role in report["skipped_roles"]
        }
        self.assertIn("onelake_role_capacity", skipped_by_name["Zulu Shared Local"])

    def test_fully_suppressed_basic_split_driver_coalesces_residual_role(
        self,
    ) -> None:
        users = [_user("first-user"), _user("second-user")]
        environment = DataverseEnvironment(
            users=users,
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-residual", "Residual Reader"),
                _role("role-global", "Global Reader"),
            ],
            role_privileges=[
                _privilege("role-residual", "account", depth="Basic"),
                _privilege("role-residual", "contact", depth="Global"),
                _privilege("role-global", "account", depth="Global"),
            ],
            user_role_assignments={
                user.id: ["role-residual", "role-global"] for user in users
            },
            table_metadata=[_secured_metadata("account"), _metadata("contact")],
        )
        client = _client(environment, _config(role_limit=2))

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(2, len(export.policies))
        residual_policy = next(
            policy
            for policy in export.policies
            if {scope.table for scope in policy.permissionscopes} == {"contact"}
        )
        self.assertEqual(
            {user.azure_ad_object_id for user in users},
            {
                permission_object.entra_object_id
                for permission_object in residual_policy.permissionobjects
            },
        )
        self.assertEqual(2, report["included_role_count"])
        self.assertEqual(2, report["projected_onelake_role_count"])
        self.assertEqual(0, report["skipped_role_count"])
        self.assertEqual(2, report["suppressed_redundant_scoped_grant_count"])

    def test_fully_suppressed_ownership_split_driver_coalesces_residual_role(
        self,
    ) -> None:
        users = [_user("first-user"), _user("second-user")]
        owner_teams = [
            DataverseTeam(
                id=f"owner-team-{user.id}",
                team_type=0,
                business_unit_id="bu-child",
                member_ids=[user.id],
            )
            for user in users
        ]
        environment = DataverseEnvironment(
            users=users,
            teams=owner_teams,
            business_units=[
                DataverseBusinessUnit(id="bu-root", name="Root"),
                DataverseBusinessUnit(
                    id="bu-child",
                    name="Child",
                    parent_business_unit_id="bu-root",
                ),
            ],
            security_roles=[
                _role("role-residual", "Residual Reader"),
                _role("role-global", "Global Reader"),
            ],
            role_privileges=[
                _privilege("role-residual", "account", depth="Local"),
                _privilege("role-residual", "contact", depth="Global"),
                _privilege("role-global", "account", depth="Global"),
            ],
            user_role_assignments={
                user.id: ["role-residual", "role-global"] for user in users
            },
            table_metadata=[_secured_metadata("account"), _metadata("contact")],
        )
        client = _client(environment, _config(role_limit=2))

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(2, len(export.policies))
        residual_policy = next(
            policy
            for policy in export.policies
            if {scope.table for scope in policy.permissionscopes} == {"contact"}
        )
        self.assertEqual(
            {user.azure_ad_object_id for user in users},
            {
                permission_object.entra_object_id
                for permission_object in residual_policy.permissionobjects
            },
        )
        self.assertIsNone(residual_policy.rowconstraints)
        self.assertEqual(2, report["projected_onelake_role_count"])
        self.assertEqual(0, report["skipped_role_count"])

    def test_fully_suppressed_cls_split_driver_coalesces_residual_role(
        self,
    ) -> None:
        first_user = _user("first-user")
        second_user = _user("second-user")
        users = [first_user, second_user]
        environment = DataverseEnvironment(
            users=users,
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-residual", "Residual Reader"),
                _role("role-first-global", "First Global Reader"),
                _role("role-second-global", "Second Global Reader"),
            ],
            role_privileges=[
                _privilege("role-residual", "account", depth="Local"),
                _privilege("role-residual", "contact", depth="Global"),
                _privilege("role-first-global", "account", depth="Global"),
                _privilege("role-second-global", "account", depth="Global"),
            ],
            user_role_assignments={
                first_user.id: ["role-residual", "role-first-global"],
                second_user.id: ["role-residual", "role-second-global"],
            },
            field_security_profiles=[
                DataverseFieldSecurityProfile(
                    id="profile-first",
                    user_ids=[first_user.id],
                    permissions=[
                        DataverseFieldPermission(
                            entity_name="account",
                            attribute_logical_name="secretcolumn",
                            can_read=4,
                        )
                    ],
                )
            ],
            table_metadata=[_secured_metadata("account"), _metadata("contact")],
        )
        client = _client(environment, _config(role_limit=3))

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(3, len(export.policies))
        residual_policy = next(
            policy
            for policy in export.policies
            if {scope.table for scope in policy.permissionscopes} == {"contact"}
        )
        self.assertEqual(
            {user.azure_ad_object_id for user in users},
            {
                permission_object.entra_object_id
                for permission_object in residual_policy.permissionobjects
            },
        )
        self.assertIsNone(residual_policy.columnconstraints)
        self.assertEqual(3, report["projected_onelake_role_count"])
        self.assertEqual(0, report["skipped_role_count"])
        self.assertEqual(2, report["suppressed_redundant_scoped_grant_count"])

    def test_mixed_basic_suppression_keeps_unsuppressed_user_isolated(self) -> None:
        dominated_user = _user("dominated-user")
        scoped_user = _user("scoped-user")
        environment = DataverseEnvironment(
            users=[dominated_user, scoped_user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-residual", "Residual Reader"),
                _role("role-global", "Global Reader"),
            ],
            role_privileges=[
                _privilege("role-residual", "account", depth="Basic"),
                _privilege("role-residual", "contact", depth="Global"),
                _privilege("role-global", "account", depth="Global"),
            ],
            user_role_assignments={
                dominated_user.id: ["role-residual", "role-global"],
                scoped_user.id: ["role-residual"],
            },
            table_metadata=[_secured_metadata("account"), _metadata("contact")],
        )
        client = _client(environment, _config(role_limit=3))

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        residual_policies = [
            policy
            for policy in export.policies
            if "contact" in {scope.table for scope in policy.permissionscopes}
        ]
        self.assertEqual(2, len(residual_policies))
        residual_members_by_tables = {
            frozenset(scope.table for scope in policy.permissionscopes): {
                permission_object.entra_object_id
                for permission_object in policy.permissionobjects
            }
            for policy in residual_policies
        }
        self.assertEqual(
            {dominated_user.azure_ad_object_id},
            residual_members_by_tables[frozenset({"contact"})],
        )
        self.assertEqual(
            {scoped_user.azure_ad_object_id},
            residual_members_by_tables[frozenset({"account", "contact"})],
        )
        scoped_policy = next(
            policy
            for policy in residual_policies
            if any(scope.table == "account" for scope in policy.permissionscopes)
        )
        self.assertEqual(
            {"account"},
            {constraint.table_name for constraint in scoped_policy.rowconstraints},
        )
        self.assertEqual(3, report["projected_onelake_role_count"])
        self.assertEqual(1, report["suppressed_redundant_scoped_grant_count"])

    def test_mixed_basic_table_suppression_keeps_remaining_basic_isolation(
        self,
    ) -> None:
        users = [_user("first-user"), _user("second-user")]
        environment = DataverseEnvironment(
            users=users,
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-residual", "Residual Reader"),
                _role("role-global", "Global Reader"),
            ],
            role_privileges=[
                _privilege("role-residual", "account", depth="Basic"),
                _privilege("role-residual", "incident", depth="Basic"),
                _privilege("role-residual", "contact", depth="Global"),
                _privilege("role-global", "account", depth="Global"),
            ],
            user_role_assignments={
                user.id: ["role-residual", "role-global"] for user in users
            },
            table_metadata=[
                _secured_metadata("account"),
                _metadata("incident"),
                _metadata("contact"),
            ],
        )
        client = _client(environment, _config(role_limit=3))

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        residual_policies = [
            policy
            for policy in export.policies
            if "incident" in {scope.table for scope in policy.permissionscopes}
        ]
        self.assertEqual(2, len(residual_policies))
        for policy in residual_policies:
            self.assertEqual(1, len(policy.permissionobjects))
            self.assertEqual(
                {"contact", "incident"},
                {scope.table for scope in policy.permissionscopes},
            )
            self.assertEqual(
                {"incident"},
                {constraint.table_name for constraint in policy.rowconstraints},
            )
            permission_object = policy.permissionobjects[0]
            user = next(
                user
                for user in users
                if user.azure_ad_object_id == permission_object.entra_object_id
            )
            row_filter = policy.rowconstraints[0].filter_condition
            self.assertIn(user.id, row_filter)
            self.assertNotIn(
                next(other.id for other in users if other.id != user.id),
                row_filter,
            )
        self.assertEqual(3, report["projected_onelake_role_count"])
        self.assertEqual(2, report["suppressed_redundant_scoped_grant_count"])

    def test_mixed_cls_suppression_keeps_unsuppressed_entitlement_isolated(
        self,
    ) -> None:
        dominated_user = _user("dominated-user")
        scoped_user = _user("scoped-user")
        environment = DataverseEnvironment(
            users=[dominated_user, scoped_user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-residual", "Residual Reader"),
                _role("role-global", "Global Reader"),
            ],
            role_privileges=[
                _privilege("role-residual", "account", depth="Local"),
                _privilege("role-residual", "contact", depth="Global"),
                _privilege("role-global", "account", depth="Global"),
            ],
            user_role_assignments={
                dominated_user.id: ["role-residual", "role-global"],
                scoped_user.id: ["role-residual"],
            },
            field_security_profiles=[
                DataverseFieldSecurityProfile(
                    id="profile-dominated",
                    user_ids=[dominated_user.id],
                    permissions=[
                        DataverseFieldPermission(
                            entity_name="account",
                            attribute_logical_name="secretcolumn",
                            can_read=4,
                        )
                    ],
                )
            ],
            table_metadata=[_secured_metadata("account"), _metadata("contact")],
        )
        client = _client(environment, _config(role_limit=3))

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        residual_policies = [
            policy
            for policy in export.policies
            if "contact" in {scope.table for scope in policy.permissionscopes}
        ]
        self.assertEqual(2, len(residual_policies))
        contact_only_policy = next(
            policy
            for policy in residual_policies
            if {scope.table for scope in policy.permissionscopes} == {"contact"}
        )
        scoped_policy = next(
            policy
            for policy in residual_policies
            if {scope.table for scope in policy.permissionscopes}
            == {"account", "contact"}
        )
        self.assertEqual(
            [dominated_user.azure_ad_object_id],
            [
                permission_object.entra_object_id
                for permission_object in contact_only_policy.permissionobjects
            ],
        )
        self.assertEqual(
            [scoped_user.azure_ad_object_id],
            [
                permission_object.entra_object_id
                for permission_object in scoped_policy.permissionobjects
            ],
        )
        self.assertEqual(["accountid"], scoped_policy.columnconstraints[0].column_names)
        self.assertEqual(
            {"account"},
            {constraint.table_name for constraint in scoped_policy.rowconstraints},
        )
        self.assertEqual(3, report["projected_onelake_role_count"])
        self.assertEqual(1, report["suppressed_redundant_scoped_grant_count"])

    def test_global_dominance_precedes_safe_chunked_rls_cls_quarantine(self) -> None:
        users = [_user("first-user"), _user("second-user")]
        business_units = [DataverseBusinessUnit(id="bu-root", name="Root")]
        business_units.extend(
            DataverseBusinessUnit(
                id=f"bu-child-{index:02d}",
                parent_business_unit_id="bu-root",
            )
            for index in range(30)
        )
        environment = DataverseEnvironment(
            users=users,
            business_units=business_units,
            security_roles=[
                _role("role-scoped", "Scoped Reader"),
                _role("role-global", "Global Reader"),
            ],
            role_privileges=[
                _privilege("role-scoped", "account", depth="Deep"),
                _privilege("role-scoped", "contact", depth="Global"),
                _privilege("role-global", "account", depth="Global"),
            ],
            user_role_assignments={
                user.id: ["role-scoped", "role-global"] for user in users
            },
            table_metadata=[_secured_metadata("account"), _metadata("contact")],
        )
        config = _config()
        config.dataverse.row_constraint_chunk_length = 120
        client = _client(environment, config)

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(2, len(export.policies))
        self.assertEqual(0, report["skipped_role_count"])
        self.assertEqual(2, report["suppressed_redundant_scoped_grant_count"])
        policies_by_name = {policy.name: policy for policy in export.policies}
        scoped_policy = next(
            policy
            for name, policy in policies_by_name.items()
            if "Scoped Reader" in name
        )
        self.assertEqual(
            {"contact"}, {scope.table for scope in scoped_policy.permissionscopes}
        )

    def test_partially_dominated_chunked_rls_cls_role_remains_quarantined(
        self,
    ) -> None:
        dominated_user = _user("dominated-user")
        scoped_user = _user("scoped-user")
        business_units = [DataverseBusinessUnit(id="bu-root", name="Root")]
        business_units.extend(
            DataverseBusinessUnit(
                id=f"bu-child-{index:02d}",
                parent_business_unit_id="bu-root",
            )
            for index in range(30)
        )
        environment = DataverseEnvironment(
            users=[dominated_user, scoped_user],
            business_units=business_units,
            security_roles=[
                _role("role-scoped", "Scoped Reader"),
                _role("role-global", "Global Reader"),
            ],
            role_privileges=[
                _privilege("role-scoped", "account", depth="Deep"),
                _privilege("role-global", "account", depth="Global"),
            ],
            user_role_assignments={
                dominated_user.id: ["role-scoped", "role-global"],
                scoped_user.id: ["role-scoped"],
            },
            table_metadata=[_secured_metadata("account")],
        )
        config = _config()
        config.dataverse.row_constraint_chunk_length = 120
        client = _client(environment, config)

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertIn("Global Reader", export.policies[0].name)
        skipped = next(
            role
            for role in report["skipped_roles"]
            if role["role_name"] == "Scoped Reader"
        )
        self.assertIn("unsupported_multi_role_rls_cls", skipped["reasons"])
        self.assertEqual(0, report["suppressed_redundant_scoped_grant_count"])

    def test_rls_overlap_on_unsecured_table_does_not_create_cls_conflict(
        self,
    ) -> None:
        user = _user()
        environment = DataverseEnvironment(
            users=[user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-local", "Local Reader"),
                _role("role-global", "Global Reader"),
            ],
            role_privileges=[
                _privilege("role-local", "account", depth="Local"),
                _privilege("role-global", "account", depth="Global"),
            ],
            user_role_assignments={user.id: ["role-local", "role-global"]},
            table_metadata=[
                DataverseTableMetadata(
                    logical_name="account",
                    ownership_type="UserOwned",
                    has_secured_columns=False,
                    columns=[
                        DataverseColumnMetadata(
                            metadata_id="account-id",
                            logical_name="accountid",
                            is_secured=False,
                        )
                    ],
                )
            ],
        )
        client = _client(environment, _config(column_security=True))

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(2, len(export.policies))
        self.assertEqual(0, report["skipped_role_count"])
        self.assertNotIn(
            "unsupported_multi_role_rls_cls",
            report["reason_counts"],
        )

    def test_dynamic_group_fsp_table_roles_are_quarantined(self) -> None:
        user = _user()
        group_team = DataverseTeam(
            id="group-team",
            team_type=2,
            azure_ad_object_id="entra-group",
            business_unit_id="bu-root",
            member_ids=[user.id],
        )
        environment = DataverseEnvironment(
            users=[user],
            teams=[group_team],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-account", "Account Reader")],
            role_privileges=[_privilege("role-account", "account")],
            user_role_assignments={user.id: ["role-account"]},
            field_security_profiles=[
                DataverseFieldSecurityProfile(
                    id="profile-group",
                    team_ids=[group_team.id],
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
                    has_secured_columns=True,
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
        client = _client(environment, _config())

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual([], export.policies)
        self.assertIn(
            "dynamic_group_field_security",
            report["skipped_roles"][0]["reasons"],
        )

    def test_table_permissions_dynamic_group_principal_is_quarantined(self) -> None:
        member = _user("group-member")
        group_team = DataverseTeam(
            id="dynamic-team",
            team_type=2,
            azure_ad_object_id="entra-dynamic-team",
            business_unit_id="bu-root",
            member_ids=[member.id],
        )
        environment = DataverseEnvironment(
            users=[member],
            teams=[group_team],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    has_read=True,
                    depth="Global",
                    principal_id=group_team.id,
                    principal_type=IamType.GROUP,
                    role_id="role-dynamic",
                    role_name="Dynamic Reader",
                    role_business_unit_id="bu-root",
                )
            ],
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual([], export.policies)
        self.assertIn(
            "dynamic_group_team_role",
            report["skipped_roles"][0]["reasons"],
        )

    def test_dynamic_group_owner_team_basic_overlay_quarantines_only_affected_role(
        self,
    ) -> None:
        for team_type in (2, 3):
            with self.subTest(team_type=team_type):
                user = _user(f"basic-owner-{team_type}")
                dynamic_team = DataverseTeam(
                    id=f"dynamic-owner-team-{team_type}",
                    team_type=team_type,
                    azure_ad_object_id=f"entra-dynamic-owner-team-{team_type}",
                    business_unit_id="bu-root",
                    member_ids=[user.id],
                )
                environment = DataverseEnvironment(
                    users=[user],
                    teams=[dynamic_team],
                    business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
                    security_roles=[
                        _role("role-good", "Good Reader"),
                        _role("role-basic", "Basic Reader"),
                    ],
                    role_privileges=[
                        _privilege("role-good", "contact"),
                        _privilege("role-basic", "account", depth="Basic"),
                    ],
                    user_role_assignments={
                        user.id: ["role-good", "role-basic"],
                    },
                    table_metadata=[_metadata("account"), _metadata("contact")],
                )
                client = _client(environment, _config())

                export = client.__build_role_based_export__()
                report = client.get_partial_sync_report()

                self.assertEqual(1, len(export.policies))
                self.assertIn("Good Reader", export.policies[0].name)
                self.assertEqual(1, report["included_role_count"])
                self.assertEqual(1, report["skipped_role_count"])
                self.assertEqual(
                    ["dynamic_group_team_ownership"],
                    report["skipped_roles"][0]["reasons"],
                )
                self.assertEqual(["account"], report["skipped_roles"][0]["tables"])

    def test_dynamic_group_owner_team_local_role_requires_actual_overlay(
        self,
    ) -> None:
        for team_business_unit_id, should_quarantine in (
            ("bu-child", True),
            ("bu-root", False),
        ):
            with self.subTest(
                team_business_unit_id=team_business_unit_id,
                should_quarantine=should_quarantine,
            ):
                user = _user("local-owner")
                dynamic_team = DataverseTeam(
                    id=f"dynamic-local-team-{team_business_unit_id}",
                    team_type=2,
                    azure_ad_object_id=(
                        f"entra-dynamic-local-team-{team_business_unit_id}"
                    ),
                    business_unit_id=team_business_unit_id,
                    member_ids=[user.id],
                )
                environment = DataverseEnvironment(
                    users=[user],
                    teams=[dynamic_team],
                    business_units=[
                        DataverseBusinessUnit(id="bu-root", name="Root"),
                        DataverseBusinessUnit(
                            id="bu-child",
                            name="Child",
                            parent_business_unit_id="bu-root",
                        ),
                    ],
                    security_roles=[_role("role-local", "Local Reader")],
                    role_privileges=[
                        _privilege("role-local", "account", depth="Local")
                    ],
                    user_role_assignments={user.id: ["role-local"]},
                    table_metadata=[_metadata("account")],
                )
                client = _client(environment, _config())

                export = client.__build_role_based_export__()
                report = client.get_partial_sync_report()

                if should_quarantine:
                    self.assertEqual([], export.policies)
                    self.assertEqual(1, report["skipped_role_count"])
                    self.assertEqual(
                        ["dynamic_group_team_ownership"],
                        report["skipped_roles"][0]["reasons"],
                    )
                    self.assertEqual(["account"], report["skipped_roles"][0]["tables"])
                else:
                    self.assertEqual(1, len(export.policies))
                    self.assertEqual(0, report["skipped_role_count"])
                    self.assertNotIn(
                        "dynamic_group_team_ownership", report["reason_counts"]
                    )

    def test_strict_security_coverage_marker_tracks_latest_validation(self) -> None:
        config = _config()
        config.dataverse.partial_sync = False
        config.dataverse.strict_access_parity = True
        config.dataverse.poa_read_access_status = "verified_empty"
        client = _client(
            DataverseEnvironment(
                business_units=[DataverseBusinessUnit(id="bu-root", name="Root")]
            ),
            config,
        )

        client.__validate_security_coverage__()

        self.assertTrue(client._strict_security_coverage_validated)

        config.dataverse.poa_read_access_status = "unverified"
        with self.assertRaisesRegex(
            ValueError, "POA read-share coverage is unverified"
        ):
            client.__validate_security_coverage__()

        self.assertFalse(client._strict_security_coverage_validated)

    def test_strict_mode_rejects_dynamic_group_owner_team_overlay(self) -> None:
        user = _user("strict-basic-owner")
        dynamic_team = DataverseTeam(
            id="strict-dynamic-owner-team",
            team_type=3,
            azure_ad_object_id="entra-strict-dynamic-owner-team",
            business_unit_id="bu-root",
            member_ids=[user.id],
        )
        environment = DataverseEnvironment(
            users=[user],
            teams=[dynamic_team],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-basic", "Basic Reader")],
            role_privileges=[_privilege("role-basic", "account", depth="Basic")],
            user_role_assignments={user.id: ["role-basic"]},
            table_metadata=[_metadata("account")],
        )
        config = _config()
        config.dataverse.partial_sync = False
        config.dataverse.strict_access_parity = True
        config.dataverse.poa_read_access_status = "verified_empty"
        client = _client(environment, config)

        client.__validate_security_coverage__()
        with self.assertRaisesRegex(
            ValueError,
            "dynamic Entra group-team ownership membership used by generated "
            "ownership overrides",
        ):
            client.__build_role_based_export__()

    def test_global_role_ignores_dynamic_group_owner_team_membership(self) -> None:
        user = _user("global-owner")
        dynamic_team = DataverseTeam(
            id="dynamic-global-owner-team",
            team_type=2,
            azure_ad_object_id="entra-dynamic-global-owner-team",
            business_unit_id="bu-root",
            member_ids=[user.id],
        )
        environment = DataverseEnvironment(
            users=[user],
            teams=[dynamic_team],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-global", "Global Reader")],
            role_privileges=[_privilege("role-global", "account")],
            user_role_assignments={user.id: ["role-global"]},
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertEqual(0, report["skipped_role_count"])
        self.assertNotIn("dynamic_group_team_ownership", report["reason_counts"])

    def test_table_permissions_role_map_respects_configured_scope(self) -> None:
        in_scope_user = _user("in-scope-user")
        out_of_scope_application = DataverseUser(
            id="out-of-scope-application",
            application_id="out-of-scope-application-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[in_scope_user, out_of_scope_application],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    has_read=True,
                    depth="Global",
                    principal_id=in_scope_user.id,
                    principal_type=IamType.USER,
                    role_id="role-account",
                    role_name="Account Reader",
                    role_business_unit_id="bu-root",
                ),
                DataverseTablePermission(
                    table_name="contact",
                    has_read=True,
                    depth="Global",
                    principal_id=out_of_scope_application.id,
                    principal_type=IamType.USER,
                    role_id="role-contact",
                    role_name="Contact Reader",
                    role_business_unit_id="bu-root",
                ),
            ],
            table_metadata=[_metadata("account"), _metadata("contact")],
        )
        config = _config()
        config.source.schemas[0].tables = ["account"]
        client = _client(environment, config)

        role_map = client.__build_role_map__()
        export = client.__build_role_based_export__()

        self.assertEqual(
            {"account"},
            {table for data in role_map.values() for table in data["tables"]},
        )
        self.assertNotIn(
            out_of_scope_application.id,
            {
                principal_id
                for data in role_map.values()
                for principal_id, _ in data["principals"]
            },
        )
        self.assertEqual(set(), client.get_partial_application_ids_to_validate())
        self.assertEqual(
            {"account"},
            {
                scope.table
                for policy in export.policies
                for scope in policy.permissionscopes
            },
        )
        self.assertNotIn(
            out_of_scope_application.application_id,
            {
                permission_object.app_id
                for policy in export.policies
                for permission_object in policy.permissionobjects
            },
        )

    def test_out_of_scope_table_permissions_preserve_compact_fallback(self) -> None:
        in_scope_user = _user("compact-user")
        out_of_scope_application = DataverseUser(
            id="compact-out-of-scope-application",
            application_id="compact-out-of-scope-application-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[in_scope_user, out_of_scope_application],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-account", "Account Reader")],
            role_privileges=[_privilege("role-account", "account")],
            user_role_assignments={in_scope_user.id: ["role-account"]},
            table_permissions=[
                DataverseTablePermission(
                    table_name="contact",
                    has_read=True,
                    depth="Global",
                    principal_id=out_of_scope_application.id,
                    principal_type=IamType.USER,
                    role_id="role-contact",
                    role_name="Contact Reader",
                    role_business_unit_id="bu-root",
                )
            ],
            table_metadata=[_metadata("account"), _metadata("contact")],
        )
        config = _config()
        config.source.schemas[0].tables = ["account"]
        client = _client(environment, config)

        role_map = client.__build_role_map__()

        self.assertEqual({("role-account", "bu-root")}, set(role_map))
        self.assertEqual({"account"}, role_map[("role-account", "bu-root")]["tables"])
        self.assertEqual(set(), client.get_partial_application_ids_to_validate())

    def test_table_permissions_cross_bu_principal_is_quarantined(self) -> None:
        principal = DataverseUser(
            id="cross-bu-principal",
            azure_ad_object_id="entra-cross-bu-principal",
            business_unit_id="bu-other",
            access_mode=0,
            is_licensed=True,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[principal],
            business_units=[
                DataverseBusinessUnit(id="bu-root", name="Root"),
                DataverseBusinessUnit(id="bu-other", name="Other"),
            ],
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    has_read=True,
                    depth="Global",
                    principal_id=principal.id,
                    principal_type=IamType.USER,
                    role_id="role-root",
                    role_name="Root Reader",
                    role_business_unit_id="bu-root",
                )
            ],
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual([], export.policies)
        self.assertIn(
            "invalid_assignment_context",
            report["skipped_roles"][0]["reasons"],
        )

    def test_table_permissions_owner_access_unknown_inheritance_quarantines_role(
        self,
    ) -> None:
        for team_type in (0, 1):
            with self.subTest(team_type=team_type):
                member = _user(f"unknown-inheritance-member-{team_type}")
                team = DataverseTeam(
                    id=f"unknown-inheritance-team-{team_type}",
                    team_type=team_type,
                    business_unit_id="bu-root",
                    member_ids=[member.id],
                )
                role = DataverseSecurityRole(
                    id="role-unknown-inheritance",
                    name="Unknown Inheritance Reader",
                    business_unit_id="bu-root",
                    is_inherited=None,
                )
                environment = DataverseEnvironment(
                    users=[member],
                    teams=[team],
                    business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
                    security_roles=[role],
                    table_permissions=[
                        DataverseTablePermission(
                            table_name=table_name,
                            has_read=True,
                            depth="Basic",
                            principal_id=team.id,
                            principal_type=IamType.GROUP,
                            role_id=role.id,
                            role_name=role.name,
                            role_business_unit_id="bu-root",
                        )
                        for table_name in ("account", "contact")
                    ],
                    table_metadata=[_metadata("account"), _metadata("contact")],
                )
                client = _client(environment, _config())

                export = client.__build_role_based_export__()
                report = client.get_partial_sync_report()

                self.assertEqual([], export.policies)
                self.assertEqual(1, report["skipped_role_count"])
                self.assertEqual(
                    ["unknown_team_role_inheritance"],
                    report["skipped_roles"][0]["reasons"],
                )

    def test_table_permissions_missing_role_id_unknown_inheritance_quarantines_role(
        self,
    ) -> None:
        for team_type, role_id in ((0, None), (1, "")):
            with self.subTest(team_type=team_type, role_id=role_id):
                member = _user(f"missing-role-id-member-{team_type}")
                team = DataverseTeam(
                    id=f"missing-role-id-team-{team_type}",
                    team_type=team_type,
                    business_unit_id="bu-root",
                    member_ids=[member.id],
                )
                role_name = f"Fallback Reader {team_type}"
                environment = DataverseEnvironment(
                    users=[member],
                    teams=[team],
                    business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
                    table_permissions=[
                        DataverseTablePermission(
                            table_name="account",
                            has_read=True,
                            depth="Basic",
                            principal_id=team.id,
                            principal_type=IamType.GROUP,
                            role_id=role_id,
                            role_name=role_name,
                            role_business_unit_id="bu-root",
                        )
                    ],
                    table_metadata=[_metadata("account")],
                )
                client = _client(environment, _config())

                export = client.__build_role_based_export__()
                report = client.get_partial_sync_report()

                self.assertEqual([], export.policies)
                self.assertEqual(1, report["skipped_role_count"])
                self.assertEqual(1, len(report["skipped_roles"]))
                self.assertEqual(
                    ["unknown_team_role_inheritance"],
                    report["skipped_roles"][0]["reasons"],
                )

    def test_table_permissions_missing_user_role_ids_are_quarantined_per_bu(
        self,
    ) -> None:
        user_a = _user("missing-role-user-a")
        user_b = DataverseUser(
            id="missing-role-user-b",
            azure_ad_object_id="entra-missing-role-user-b",
            business_unit_id="bu-other",
            access_mode=0,
            is_licensed=True,
            azure_state=0,
        )
        role_name = "Missing Identifier Reader"
        environment = DataverseEnvironment(
            users=[user_a, user_b],
            business_units=[
                DataverseBusinessUnit(id="bu-root", name="Root"),
                DataverseBusinessUnit(id="bu-other", name="Other"),
            ],
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    has_read=True,
                    depth="Global",
                    principal_id=user_a.id,
                    principal_type=IamType.USER,
                    role_id=None,
                    role_name=role_name,
                    role_business_unit_id="bu-root",
                ),
                DataverseTablePermission(
                    table_name="contact",
                    has_read=True,
                    depth="Global",
                    principal_id=user_b.id,
                    principal_type=IamType.USER,
                    role_id="",
                    role_name=role_name,
                    role_business_unit_id="bu-other",
                ),
            ],
            table_metadata=[_metadata("account"), _metadata("contact")],
        )
        client = _client(environment, _config())

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual([], export.policies)
        self.assertEqual(2, report["skipped_role_count"])
        self.assertTrue(
            all(
                role["reasons"] == ["invalid_assignment_context"]
                for role in report["skipped_roles"]
            )
        )
        self.assertEqual(
            {
                f"missing-role-id:{role_name}:bu-root",
                f"missing-role-id:{role_name}:bu-other",
            },
            {role["role_id"] for role in report["skipped_roles"]},
        )

    def test_table_permissions_known_inheritance_role_is_publishable_in_partial(
        self,
    ) -> None:
        member = _user("known-inheritance-member")
        team = DataverseTeam(
            id="known-inheritance-team",
            team_type=0,
            business_unit_id="bu-root",
            member_ids=[member.id],
        )
        role = _role("role-known-inheritance", "Known Inheritance Reader")
        environment = DataverseEnvironment(
            users=[member],
            teams=[team],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[role],
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    has_read=True,
                    depth="Basic",
                    principal_id=team.id,
                    principal_type=IamType.GROUP,
                    role_id=role.id,
                    role_name=role.name,
                    role_business_unit_id="bu-root",
                )
            ],
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertEqual(0, report["skipped_role_count"])

    def test_unknown_inheritance_fallback_is_permissive_legacy_only(self) -> None:
        member = _user("unknown-inheritance-member")
        team = DataverseTeam(
            id="unknown-inheritance-team",
            team_type=0,
            business_unit_id="bu-root",
            member_ids=[member.id],
        )
        role = DataverseSecurityRole(
            id="role-unknown-inheritance",
            name="Unknown Inheritance Reader",
            business_unit_id="bu-root",
            is_inherited=None,
        )
        permission = DataverseTablePermission(
            table_name="account",
            has_read=True,
            depth="Basic",
            principal_id=team.id,
            principal_type=IamType.GROUP,
            role_id=role.id,
            role_name=role.name,
            role_business_unit_id="bu-root",
        )
        environment = DataverseEnvironment(
            users=[member],
            teams=[team],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[role],
            table_permissions=[permission],
            table_metadata=[_metadata("account")],
        )
        role_data = {"perms": [permission]}

        legacy_config = _config()
        legacy_config.dataverse.partial_sync = False
        legacy_client = _client(environment, legacy_config)
        self.assertEqual(1, legacy_client.__get_role_inheritance_mode__(role_data))
        legacy_export = legacy_client.__build_role_based_export__()
        legacy_filters = json.dumps(
            [
                constraint.filter_condition
                for constraint in legacy_export.policies[0].rowconstraints or []
            ]
        )
        self.assertIn(member.id, legacy_filters)

        strict_config = _config()
        strict_config.dataverse.partial_sync = False
        strict_config.dataverse.strict_access_parity = True
        strict_client = _client(environment, strict_config)
        self.assertEqual(0, strict_client.__get_role_inheritance_mode__(role_data))
        with self.assertRaisesRegex(
            ValueError,
            "found 1 team-assigned roles with an unknown inheritance mode",
        ):
            strict_client.__validate_security_coverage__()

        partial_client = _client(environment, _config())
        self.assertEqual(0, partial_client.__get_role_inheritance_mode__(role_data))
        partial_export = partial_client.__build_role_based_export__()
        partial_report = partial_client.get_partial_sync_report()
        self.assertEqual([], partial_export.policies)
        self.assertEqual(
            ["unknown_team_role_inheritance"],
            partial_report["skipped_roles"][0]["reasons"],
        )

    def test_strict_unknown_inheritance_uses_table_permissions_and_deduplicates_sources(
        self,
    ) -> None:
        scenarios = (
            (0, False),
            (1, False),
            (0, True),
        )
        for team_type, duplicate_assignment in scenarios:
            with self.subTest(
                team_type=team_type,
                duplicate_assignment=duplicate_assignment,
            ):
                team = DataverseTeam(
                    id=f"strict-unknown-team-{team_type}-{duplicate_assignment}",
                    team_type=team_type,
                    business_unit_id="bu-root",
                )
                role = DataverseSecurityRole(
                    id="role-strict-unknown",
                    name="Strict Unknown Reader",
                    business_unit_id="bu-root",
                    is_inherited=None,
                )
                environment = DataverseEnvironment(
                    teams=[team],
                    business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
                    security_roles=[role],
                    team_role_assignments=(
                        {team.id: [role.id, role.id]} if duplicate_assignment else {}
                    ),
                    table_permissions=[
                        DataverseTablePermission(
                            table_name=table_name,
                            has_read=True,
                            depth="Basic",
                            principal_id=team.id,
                            principal_type=IamType.GROUP,
                            role_id=role.id,
                            role_name=role.name,
                            role_business_unit_id="bu-root",
                        )
                        for table_name in ("account", "contact")
                    ],
                    table_metadata=[_metadata("account"), _metadata("contact")],
                )
                config = _config()
                config.dataverse.partial_sync = False
                config.dataverse.strict_access_parity = True
                client = _client(environment, config)

                with self.assertRaisesRegex(
                    ValueError,
                    "found 1 team-assigned roles with an unknown inheritance mode",
                ):
                    client.__validate_security_coverage__()

    def test_strict_unknown_depth_uses_table_permissions_and_deduplicates_sources(
        self,
    ) -> None:
        for duplicate_source in (False, True):
            with self.subTest(duplicate_source=duplicate_source):
                user = _user("strict-unknown-depth-user")
                environment = DataverseEnvironment(
                    users=[user],
                    business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
                    security_roles=[
                        _role("role-unknown-depth", "Unknown Depth Reader")
                    ],
                    role_privileges=(
                        [_privilege("role-unknown-depth", "account", depth="Custom")]
                        if duplicate_source
                        else []
                    ),
                    table_permissions=[
                        DataverseTablePermission(
                            table_name="account",
                            has_read=True,
                            depth="Custom",
                            principal_id=user.id,
                            principal_type=IamType.USER,
                            role_id="role-unknown-depth",
                            role_name="Unknown Depth Reader",
                            role_business_unit_id="bu-root",
                        )
                    ],
                    table_metadata=[_metadata("account")],
                )
                config = _config()
                config.source.schemas[0].tables = ["account"]
                config.dataverse.partial_sync = False
                config.dataverse.strict_access_parity = True
                client = _client(environment, config)

                with self.assertRaisesRegex(
                    ValueError,
                    "found 1 read privileges with unknown privilege depth",
                ):
                    client.__validate_security_coverage__()

    def test_table_permissions_basic_ownership_preserves_known_inheritance_modes(
        self,
    ) -> None:
        for inheritance_mode, includes_member in (
            (0, False),
            (1, True),
        ):
            with self.subTest(inheritance_mode=inheritance_mode):
                member = _user(f"basic-member-{inheritance_mode}")
                team = DataverseTeam(
                    id=f"basic-owner-team-{inheritance_mode}",
                    team_type=0,
                    business_unit_id="bu-root",
                    member_ids=[member.id],
                )
                role = DataverseSecurityRole(
                    id=f"role-basic-{inheritance_mode}",
                    name="Basic Reader",
                    business_unit_id="bu-root",
                    is_inherited=inheritance_mode,
                )
                environment = DataverseEnvironment(
                    users=[member],
                    teams=[team],
                    business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
                    security_roles=[role],
                    table_permissions=[
                        DataverseTablePermission(
                            table_name="account",
                            has_read=True,
                            depth="Basic",
                            principal_id=team.id,
                            principal_type=IamType.GROUP,
                            role_id=role.id,
                            role_name=role.name,
                            role_business_unit_id="bu-root",
                        )
                    ],
                    table_metadata=[_metadata("account")],
                )
                config = _config()
                config.dataverse.partial_sync = False
                client = _client(environment, config)

                export = client.__build_role_based_export__()

                self.assertEqual(1, len(export.policies))
                serialized_filters = json.dumps(
                    [
                        constraint.filter_condition
                        for constraint in export.policies[0].rowconstraints or []
                    ]
                )
                self.assertIn(team.id, serialized_filters)
                if includes_member:
                    self.assertIn(member.id, serialized_filters)
                else:
                    self.assertNotIn(member.id, serialized_filters)

    def test_strict_mode_rejects_table_permissions_dynamic_group(self) -> None:
        group_team = DataverseTeam(
            id="strict-dynamic-team",
            team_type=2,
            azure_ad_object_id="entra-strict-dynamic-team",
            business_unit_id="bu-root",
        )
        environment = DataverseEnvironment(
            teams=[group_team],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-dynamic", "Dynamic Reader")],
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    has_read=True,
                    depth="Global",
                    principal_id=group_team.id,
                    principal_type=IamType.GROUP,
                    role_id="role-dynamic",
                    role_name="Dynamic Reader",
                    role_business_unit_id="bu-root",
                )
            ],
            table_metadata=[_metadata("account")],
        )
        config = _config()
        config.dataverse.partial_sync = False
        config.dataverse.strict_access_parity = True
        client = _client(environment, config)

        with self.assertRaisesRegex(
            ValueError, "found 1 role-assigned Entra group-team record"
        ):
            client.__validate_security_coverage__()

    def test_strict_dynamic_group_count_deduplicates_assignment_sources(
        self,
    ) -> None:
        group_team = DataverseTeam(
            id="strict-duplicate-team",
            team_type=2,
            azure_ad_object_id="entra-strict-duplicate-team",
            business_unit_id="bu-root",
        )
        environment = DataverseEnvironment(
            teams=[group_team],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-dynamic", "Dynamic Reader")],
            team_role_assignments={group_team.id: ["role-dynamic", "role-dynamic"]},
            table_permissions=[
                DataverseTablePermission(
                    table_name=table_name,
                    has_read=True,
                    depth="Global",
                    principal_id=group_team.id,
                    principal_type=IamType.GROUP,
                    role_id="role-dynamic",
                    role_name="Dynamic Reader",
                    role_business_unit_id="bu-root",
                )
                for table_name in ("account", "contact")
            ],
            table_metadata=[_metadata("account"), _metadata("contact")],
        )
        config = _config()
        config.dataverse.partial_sync = False
        config.dataverse.strict_access_parity = True
        client = _client(environment, config)

        with self.assertRaisesRegex(
            ValueError, "found 1 role-assigned Entra group-team record"
        ):
            client.__validate_security_coverage__()

    def test_strict_mode_rejects_table_permissions_cross_bu_principals(
        self,
    ) -> None:
        for principal_type, principal_label in (
            (IamType.USER, "user"),
            (IamType.GROUP, "team"),
        ):
            with self.subTest(principal_type=principal_type):
                principal_id = f"strict-cross-bu-{principal_label}"
                users = []
                teams = []
                if principal_type == IamType.USER:
                    users.append(
                        DataverseUser(
                            id=principal_id,
                            azure_ad_object_id=f"entra-{principal_id}",
                            business_unit_id="bu-other",
                            access_mode=0,
                            is_licensed=True,
                            azure_state=0,
                        )
                    )
                else:
                    teams.append(
                        DataverseTeam(
                            id=principal_id,
                            team_type=0,
                            business_unit_id="bu-other",
                        )
                    )
                environment = DataverseEnvironment(
                    users=users,
                    teams=teams,
                    business_units=[
                        DataverseBusinessUnit(id="bu-root", name="Root"),
                        DataverseBusinessUnit(id="bu-other", name="Other"),
                    ],
                    security_roles=[_role("role-root", "Root Reader")],
                    table_permissions=[
                        DataverseTablePermission(
                            table_name=table_name,
                            has_read=True,
                            depth="Global",
                            principal_id=principal_id,
                            principal_type=principal_type,
                            role_id="role-root",
                            role_name="Root Reader",
                            role_business_unit_id="bu-root",
                        )
                        for table_name in ("account", "contact")
                    ],
                    table_metadata=[_metadata("account"), _metadata("contact")],
                )
                config = _config()
                config.dataverse.partial_sync = False
                config.dataverse.strict_access_parity = True
                client = _client(environment, config)

                with self.assertRaisesRegex(
                    ValueError, "found 1 invalid role assignment context"
                ):
                    client.__validate_security_coverage__()

    def test_strict_assignment_context_deduplicates_both_sources(self) -> None:
        principal = DataverseUser(
            id="strict-duplicate-principal",
            azure_ad_object_id="entra-strict-duplicate-principal",
            business_unit_id="bu-other",
            access_mode=0,
            is_licensed=True,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[principal],
            business_units=[
                DataverseBusinessUnit(id="bu-root", name="Root"),
                DataverseBusinessUnit(id="bu-other", name="Other"),
            ],
            security_roles=[_role("role-root", "Root Reader")],
            user_role_assignments={principal.id: ["role-root", "role-root"]},
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    has_read=True,
                    depth="Global",
                    principal_id=principal.id,
                    principal_type=IamType.USER,
                    role_id="role-root",
                    role_name="Root Reader",
                    role_business_unit_id="bu-root",
                )
            ],
            table_metadata=[_metadata("account")],
        )
        config = _config()
        config.dataverse.partial_sync = False
        config.dataverse.strict_access_parity = True
        client = _client(environment, config)

        with self.assertRaisesRegex(
            ValueError, "found 1 invalid role assignment context"
        ):
            client.__validate_security_coverage__()

    def test_row_filter_chunks_are_included_in_capacity_quarantine(self) -> None:
        user = _user()
        business_units = [DataverseBusinessUnit(id="bu-root", name="Root")]
        business_units.extend(
            DataverseBusinessUnit(
                id=f"bu-child-{index:02d}",
                parent_business_unit_id="bu-root",
            )
            for index in range(30)
        )
        environment = DataverseEnvironment(
            users=[user],
            business_units=business_units,
            security_roles=[_role("role-deep", "Deep Reader")],
            role_privileges=[_privilege("role-deep", "account", depth="Deep")],
            user_role_assignments={user.id: ["role-deep"]},
            table_metadata=[_metadata("account")],
        )
        config = _config(role_limit=1)
        config.dataverse.row_constraint_chunk_length = 120
        client = _client(environment, config)

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual([], export.policies)
        self.assertIn("onelake_role_capacity", report["skipped_roles"][0]["reasons"])

    def test_chunked_rls_with_cls_quarantines_only_unsafe_source_role(self) -> None:
        valid_user = _user("valid-user")
        unsafe_user = _user("unsafe-user")
        business_units = [DataverseBusinessUnit(id="bu-root", name="Root")]
        business_units.extend(
            DataverseBusinessUnit(
                id=f"bu-child-{index:02d}",
                parent_business_unit_id="bu-root",
            )
            for index in range(30)
        )
        environment = DataverseEnvironment(
            users=[valid_user, unsafe_user],
            business_units=business_units,
            security_roles=[
                _role("role-good", "Good Reader"),
                _role("role-unsafe", "Chunked Secure Reader"),
            ],
            role_privileges=[
                _privilege("role-good", "contact"),
                _privilege("role-unsafe", "account", depth="Deep"),
            ],
            user_role_assignments={
                valid_user.id: ["role-good"],
                unsafe_user.id: ["role-unsafe"],
            },
            field_security_profiles=[
                DataverseFieldSecurityProfile(
                    id="profile-secure",
                    user_ids=[unsafe_user.id],
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
                _metadata("contact"),
                DataverseTableMetadata(
                    logical_name="account",
                    ownership_type="UserOwned",
                    has_secured_columns=True,
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
                ),
            ],
        )
        config = _config()
        config.dataverse.row_constraint_chunk_length = 120
        client = _client(environment, config)

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertIn("Good Reader", export.policies[0].name)
        self.assertEqual(
            {"contact"}, {scope.table for scope in export.policies[0].permissionscopes}
        )
        skipped = report["skipped_roles"][0]
        self.assertEqual("Chunked Secure Reader", skipped["role_name"])
        self.assertIn("unsupported_multi_role_rls_cls", skipped["reasons"])
        self.assertEqual(["account"], skipped["tables"])

    def test_basic_ownership_chunks_with_cls_quarantine_only_unsafe_role(
        self,
    ) -> None:
        valid_user = _user("valid-user")
        unsafe_user = _user("unsafe-user")
        owner_teams = _owner_teams(unsafe_user.id)
        environment = DataverseEnvironment(
            users=[valid_user, unsafe_user],
            teams=owner_teams,
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-good", "Good Reader"),
                _role("role-unsafe", "Basic Secure Reader"),
            ],
            role_privileges=[
                _privilege("role-good", "contact"),
                _privilege("role-unsafe", "account", depth="Basic"),
            ],
            user_role_assignments={
                valid_user.id: ["role-good"],
                unsafe_user.id: ["role-unsafe"],
            },
            field_security_profiles=[
                DataverseFieldSecurityProfile(
                    id="profile-secure",
                    user_ids=[unsafe_user.id],
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
                _metadata("contact"),
                _secured_metadata(),
            ],
        )
        config = _config()
        config.dataverse.row_constraint_chunk_length = 80
        client = _client(environment, config)

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertIn("Good Reader", export.policies[0].name)
        self.assertEqual(
            {"contact"}, {scope.table for scope in export.policies[0].permissionscopes}
        )
        skipped = report["skipped_roles"][0]
        self.assertEqual("Basic Secure Reader", skipped["role_name"])
        self.assertIn("unsupported_multi_role_rls_cls", skipped["reasons"])
        self.assertEqual(["account"], skipped["tables"])

        strict_config = _config()
        strict_config.dataverse.partial_sync = False
        strict_config.dataverse.strict_access_parity = True
        strict_config.dataverse.row_constraint_chunk_length = 80
        strict_client = _client(environment, strict_config)
        with self.assertRaisesRegex(
            ValueError,
            "unsupported OneLake RLS/CLS multi-role combination",
        ):
            strict_client.__build_role_based_export__()

    def test_local_ownership_overlay_chunks_with_cls_quarantine_only_unsafe_role(
        self,
    ) -> None:
        valid_user = _user("valid-user")
        unsafe_user = _user("unsafe-user")
        owner_teams = _owner_teams(unsafe_user.id, business_unit_id="bu-child")
        environment = DataverseEnvironment(
            users=[valid_user, unsafe_user],
            teams=owner_teams,
            business_units=[
                DataverseBusinessUnit(id="bu-root", name="Root"),
                DataverseBusinessUnit(
                    id="bu-child",
                    name="Child",
                    parent_business_unit_id="bu-root",
                ),
            ],
            security_roles=[
                _role("role-good", "Good Reader"),
                _role("role-unsafe", "Local Secure Reader"),
            ],
            role_privileges=[
                _privilege("role-good", "contact"),
                _privilege("role-unsafe", "account", depth="Local"),
            ],
            user_role_assignments={
                valid_user.id: ["role-good"],
                unsafe_user.id: ["role-unsafe"],
            },
            field_security_profiles=[
                DataverseFieldSecurityProfile(
                    id="profile-secure",
                    user_ids=[unsafe_user.id],
                    permissions=[
                        DataverseFieldPermission(
                            entity_name="account",
                            attribute_logical_name="secretcolumn",
                            can_read=4,
                        )
                    ],
                )
            ],
            table_metadata=[_metadata("contact"), _secured_metadata()],
        )
        config = _config()
        config.dataverse.row_constraint_chunk_length = 80
        client = _client(environment, config)

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertIn("Good Reader", export.policies[0].name)
        skipped = report["skipped_roles"][0]
        self.assertEqual("Local Secure Reader", skipped["role_name"])
        self.assertIn("unsupported_multi_role_rls_cls", skipped["reasons"])
        self.assertEqual(["account"], skipped["tables"])

    def test_basic_ownership_chunks_without_cls_remain_publishable(self) -> None:
        user = _user("owner-user")
        environment = DataverseEnvironment(
            users=[user],
            teams=_owner_teams(user.id),
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-basic", "Basic Reader")],
            role_privileges=[_privilege("role-basic", "account", depth="Basic")],
            user_role_assignments={user.id: ["role-basic"]},
            table_metadata=[_metadata("account")],
        )
        config = _config()
        config.dataverse.row_constraint_chunk_length = 80
        client = _client(environment, config)

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertGreater(len(export.policies), 1)
        self.assertEqual(0, report["skipped_role_count"])
        self.assertNotIn(
            "unsupported_multi_role_rls_cls",
            report["reason_counts"],
        )
        self.assertTrue(
            all(policy.columnconstraints is None for policy in export.policies)
        )
        self.assertEqual(
            {"account"},
            {
                scope.table
                for policy in export.policies
                for scope in policy.permissionscopes
            },
        )
        self.assertGreater(
            len(
                [
                    constraint
                    for policy in export.policies
                    for constraint in policy.rowconstraints or []
                ]
            ),
            1,
        )

    def test_unrepresentable_row_constraint_quarantines_role_with_sibling(self) -> None:
        user = _user()
        environment = DataverseEnvironment(
            users=[user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-good", "Good Reader"),
                _role("role-bad", "Bad Reader"),
            ],
            role_privileges=[
                _privilege("role-good", "account"),
                _privilege("role-bad", "account", depth="Deep"),
                _privilege("role-bad", "contact"),
            ],
            user_role_assignments={user.id: ["role-good", "role-bad"]},
            field_security_profiles=[
                DataverseFieldSecurityProfile(
                    id="profile-1",
                    user_ids=[user.id],
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
                    has_secured_columns=True,
                    columns=[
                        DataverseColumnMetadata(
                            metadata_id="name-id",
                            logical_name="name",
                            is_secured=False,
                        ),
                        DataverseColumnMetadata(
                            metadata_id="secret-id",
                            logical_name="secretcolumn",
                            is_secured=True,
                        ),
                    ],
                ),
                _metadata("contact"),
            ],
        )
        config = _config()
        config.dataverse.row_constraint_chunk_length = 40
        client = _client(environment, config)

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertIn("Good Reader", export.policies[0].name)
        self.assertNotIn(
            "contact",
            {
                scope.table
                for policy in export.policies
                for scope in policy.permissionscopes
            },
        )
        skipped = report["skipped_roles"][0]
        self.assertIn("unrepresentable_row_constraint", skipped["reasons"])
        self.assertIn("account", skipped["tables"])

    def test_no_readable_columns_quarantines_role_with_sibling(self) -> None:
        user = _user()
        environment = DataverseEnvironment(
            users=[user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-good", "Good Reader"),
                _role("role-bad", "Bad Reader"),
            ],
            role_privileges=[
                _privilege("role-good", "lead"),
                _privilege("role-bad", "account"),
                _privilege("role-bad", "contact"),
            ],
            user_role_assignments={user.id: ["role-good", "role-bad"]},
            table_metadata=[
                _metadata("lead"),
                DataverseTableMetadata(
                    logical_name="account",
                    ownership_type="UserOwned",
                    has_secured_columns=True,
                    columns=[
                        DataverseColumnMetadata(
                            metadata_id="secret-id",
                            logical_name="secretcolumn",
                            is_secured=True,
                        )
                    ],
                ),
                _metadata("contact"),
            ],
        )
        client = _client(environment, _config())

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertIn("Good Reader", export.policies[0].name)
        self.assertNotIn(
            "contact",
            {
                scope.table
                for policy in export.policies
                for scope in policy.permissionscopes
            },
        )
        skipped = report["skipped_roles"][0]
        self.assertIn("no_readable_columns", skipped["reasons"])
        self.assertIn("account", skipped["tables"])

    def test_map_policy_requires_graph_finalization_before_publication(self) -> None:
        config = _config()
        environment = _two_role_environment(
            bad_depth="Unknown", bad_record_filter_id="filter-1"
        )
        client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        client.config = config
        client.logger = logging.getLogger("test_dataverse_partial_sync")
        client.partial_sync_report = {}
        client.api_client = type(
            "Stub",
            (),
            {"get_environment_security_map": lambda self, source: environment},
        )()

        export = client.map_policy("role_based")

        self.assertFalse(is_dataverse_export_validated(export, config))
        self.assertFalse(is_strict_dataverse_export_validated(export, config))
        self.assertEqual(1, len(export.policies))

        finalized = client.rebuild_partial_export_after_graph_validation(set(), set())

        self.assertTrue(is_dataverse_export_validated(finalized, config))

    def test_graph_finalization_requires_every_discovered_application_id(
        self,
    ) -> None:
        application_user = DataverseUser(
            id="application-user",
            application_id="application-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[application_user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-app", "Application Reader")],
            role_privileges=[_privilege("role-app", "account")],
            user_role_assignments={application_user.id: ["role-app"]},
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        with self.assertRaisesRegex(ValueError, "every discovered application ID"):
            client.rebuild_partial_export_after_graph_validation(set(), set())

    def test_table_permissions_application_user_requires_graph_quarantine(
        self,
    ) -> None:
        application_user = DataverseUser(
            id="table-application-user",
            application_id="table-application-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[application_user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    has_read=True,
                    depth="Global",
                    principal_id=application_user.id,
                    principal_type=IamType.USER,
                    role_id="role-application",
                    role_name="Application Reader",
                    role_business_unit_id="bu-root",
                )
            ],
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        self.assertEqual(
            {"table-application-id"},
            client.get_partial_application_ids_to_validate(),
        )
        with self.assertRaisesRegex(ValueError, "every discovered application ID"):
            client.rebuild_partial_export_after_graph_validation(set(), set())

        export = client.rebuild_partial_export_after_graph_validation(
            {"table-application-id"}, {"table-application-id"}
        )
        report = client.get_partial_sync_report()

        self.assertEqual([], export.policies)
        self.assertEqual(
            [
                {
                    "assignment_context": "direct_role",
                    "principal_id": "table-application-user",
                    "principal_type": "USER",
                    "reason": "unresolved_graph_service_principal",
                    "role_id": "role-application",
                    "role_name": "Application Reader",
                }
            ],
            report["skipped_principal_assignments"],
        )

    def test_table_permissions_owner_access_member_requires_graph_quarantine(
        self,
    ) -> None:
        for team_type in (0, 1):
            with self.subTest(team_type=team_type):
                application_user = DataverseUser(
                    id=f"team-application-user-{team_type}",
                    application_id=f"team-application-id-{team_type}",
                    business_unit_id="bu-root",
                    access_mode=4,
                    is_licensed=False,
                    azure_state=0,
                )
                team = DataverseTeam(
                    id=f"role-team-{team_type}",
                    team_type=team_type,
                    business_unit_id="bu-root",
                    member_ids=[application_user.id],
                )
                environment = DataverseEnvironment(
                    users=[application_user],
                    teams=[team],
                    business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
                    table_permissions=[
                        DataverseTablePermission(
                            table_name="account",
                            has_read=True,
                            depth="Global",
                            principal_id=team.id,
                            principal_type=IamType.GROUP,
                            role_id="role-team",
                            role_name="Team Reader",
                            role_business_unit_id="bu-root",
                        )
                    ],
                    table_metadata=[_metadata("account")],
                )
                client = _client(environment, _config())
                application_id = application_user.application_id

                self.assertEqual(
                    {application_id},
                    client.get_partial_application_ids_to_validate(),
                )
                with self.assertRaisesRegex(
                    ValueError, "every discovered application ID"
                ):
                    client.rebuild_partial_export_after_graph_validation(set(), set())

                export = client.rebuild_partial_export_after_graph_validation(
                    {application_id}, {application_id}
                )
                report = client.get_partial_sync_report()

                self.assertEqual([], export.policies)
                self.assertEqual(
                    [
                        {
                            "assignment_context": "team_member",
                            "principal_id": team.id,
                            "principal_type": "GROUP",
                            "reason": "unresolved_graph_service_principal",
                            "role_id": "role-team",
                            "role_name": "Team Reader",
                            "team_member_id": application_user.id,
                            "team_type": team_type,
                        }
                    ],
                    report["skipped_principal_assignments"],
                )

    def _strict_app_only_environment(self) -> DataverseEnvironment:
        application_user = DataverseUser(
            id="strict-app-user",
            application_id="strict-app-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        return DataverseEnvironment(
            users=[application_user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-app", "Application Reader")],
            role_privileges=[_privilege("role-app", "account")],
            user_role_assignments={application_user.id: ["role-app"]},
            table_metadata=[_metadata("account")],
        )

    def _strict_config(self) -> DataverseSourceMap:
        config = _config()
        config.dataverse.partial_sync = False
        config.dataverse.strict_access_parity = True
        config.dataverse.poa_read_access_status = "verified_empty"
        return config

    def _strict_map_client(
        self, environment: DataverseEnvironment, config: DataverseSourceMap
    ) -> DataversePolicyWeaver:
        client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        client.config = config
        client.logger = logging.getLogger("test_dataverse_partial_sync")
        client.partial_sync_report = {}
        client.api_client = type(
            "Stub",
            (),
            {"get_environment_security_map": lambda self, source: environment},
        )()
        return client

    def test_strict_direct_app_only_role_requires_graph_finalization(self) -> None:
        config = self._strict_config()
        environment = self._strict_app_only_environment()
        client = self._strict_map_client(environment, config)

        export = client.map_policy("role_based")

        self.assertEqual(
            {"strict-app-id"}, client.get_strict_application_ids_to_validate()
        )
        self.assertFalse(is_dataverse_export_validated(export, config))
        self.assertFalse(is_strict_dataverse_export_validated(export, config))

        finalized = client.rebuild_strict_export_after_graph_validation(
            {"strict-app-id"}, set()
        )

        self.assertTrue(is_strict_dataverse_export_validated(finalized, config))
        self.assertIn(
            "strict-app-id",
            {
                permission_object.app_id
                for policy in finalized.policies
                for permission_object in policy.permissionobjects
            },
        )

    def test_strict_unresolved_app_only_identity_fails_finalization(self) -> None:
        config = self._strict_config()
        environment = self._strict_app_only_environment()
        client = self._strict_map_client(environment, config)

        export = client.map_policy("role_based")

        self.assertFalse(is_strict_dataverse_export_validated(export, config))
        self.assertEqual(
            {"strict-app-id"}, client.get_strict_application_ids_to_validate()
        )
        with self.assertRaisesRegex(ValueError, "unresolvable Entra identities"):
            client.rebuild_strict_export_after_graph_validation(
                {"strict-app-id"}, {"strict-app-id"}
            )
        self.assertFalse(is_strict_dataverse_export_validated(export, config))

    def test_strict_graph_finalization_rejects_mismatched_checked_sets(self) -> None:
        config = self._strict_config()
        environment = self._strict_app_only_environment()
        client = _client(environment, config)

        # Deterministic order: the checked/unresolved-set validation is only reached
        # after strict security coverage passes, so complete coverage first to
        # exercise the set-mismatch guards rather than the coverage gate.
        client.__validate_security_coverage__()
        self.assertTrue(client._strict_security_coverage_validated)

        with self.assertRaisesRegex(ValueError, "every discovered application ID"):
            client.rebuild_strict_export_after_graph_validation(set(), set())
        with self.assertRaisesRegex(ValueError, "every discovered application ID"):
            client.rebuild_strict_export_after_graph_validation(
                {"strict-app-id", "unexpected-app-id"}, set()
            )
        with self.assertRaisesRegex(ValueError, "subset of checked"):
            client.rebuild_strict_export_after_graph_validation(
                {"strict-app-id"}, {"other-app-id"}
            )

    def test_strict_graph_finalization_requires_prior_coverage(self) -> None:
        config = self._strict_config()
        environment = self._strict_app_only_environment()
        client = _client(environment, config)

        # A directly constructed client never ran strict coverage, so the marker is
        # absent and finalization must be rejected fail-closed.
        self.assertFalse(getattr(client, "_strict_security_coverage_validated", False))

        # Deterministic order: the coverage gate precedes the checked/unresolved-set
        # validation, so even a malformed checked set is rejected for missing
        # coverage first and never reaches the set-mismatch guards.
        with self.assertRaisesRegex(ValueError, "[Ss]trict security coverage"):
            client.rebuild_strict_export_after_graph_validation(
                {"strict-app-id", "unexpected-app-id"}, set()
            )
        # A well-formed checked set is likewise rejected without prior coverage.
        with self.assertRaisesRegex(ValueError, "[Ss]trict security coverage"):
            client.rebuild_strict_export_after_graph_validation(
                {"strict-app-id"}, set()
            )
        # Finalization never sets the marker and never produces a validated export.
        self.assertFalse(getattr(client, "_strict_security_coverage_validated", False))

        # Failed coverage also never permits finalization: a RecordFilter-backed read
        # privilege makes __validate_security_coverage__ raise, leaving the marker
        # False so the finalization gate still refuses.
        failing_client = _client(
            DataverseEnvironment(
                users=[
                    DataverseUser(
                        id="strict-app-user",
                        application_id="strict-app-id",
                        business_unit_id="bu-root",
                        access_mode=4,
                        is_licensed=False,
                        azure_state=0,
                    )
                ],
                business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
                security_roles=[_role("role-app", "Application Reader")],
                role_privileges=[
                    _privilege("role-app", "account", record_filter_id="rf-1")
                ],
                user_role_assignments={"strict-app-user": ["role-app"]},
                table_metadata=[_metadata("account")],
            ),
            self._strict_config(),
        )
        with self.assertRaises(ValueError):
            failing_client.__validate_security_coverage__()
        self.assertFalse(
            getattr(failing_client, "_strict_security_coverage_validated", False)
        )
        with self.assertRaisesRegex(ValueError, "[Ss]trict security coverage"):
            failing_client.rebuild_strict_export_after_graph_validation(
                {"strict-app-id"}, set()
            )

    def test_strict_owner_access_team_app_only_member_requires_graph(self) -> None:
        for team_type in (0, 1):
            with self.subTest(team_type=team_type):
                application_user = DataverseUser(
                    id=f"strict-team-app-user-{team_type}",
                    application_id=f"strict-team-app-id-{team_type}",
                    business_unit_id="bu-root",
                    access_mode=4,
                    is_licensed=False,
                    azure_state=0,
                )
                team = DataverseTeam(
                    id=f"strict-role-team-{team_type}",
                    team_type=team_type,
                    business_unit_id="bu-root",
                    member_ids=[application_user.id],
                )
                environment = DataverseEnvironment(
                    users=[application_user],
                    teams=[team],
                    business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
                    security_roles=[_role("role-team", "Team Reader")],
                    role_privileges=[_privilege("role-team", "account")],
                    team_role_assignments={team.id: ["role-team"]},
                    table_metadata=[_metadata("account")],
                )
                config = self._strict_config()
                client = _client(environment, config)
                # Owner/Access team app-only members still require a completed strict
                # coverage pass before Graph finalization is permitted.
                client.__validate_security_coverage__()
                application_id = application_user.application_id

                self.assertEqual(
                    {application_id},
                    client.get_strict_application_ids_to_validate(),
                )
                with self.assertRaisesRegex(
                    ValueError, "unresolvable Entra identities"
                ):
                    client.rebuild_strict_export_after_graph_validation(
                        {application_id}, {application_id}
                    )

                finalized = client.rebuild_strict_export_after_graph_validation(
                    {application_id}, set()
                )

                self.assertTrue(is_strict_dataverse_export_validated(finalized, config))
                self.assertIn(
                    application_id,
                    {
                        permission_object.app_id
                        for policy in finalized.policies
                        for permission_object in policy.permissionobjects
                    },
                )

    def test_assignment_map_out_of_scope_app_user_excluded_from_discovery(
        self,
    ) -> None:
        out_of_scope_app = DataverseUser(
            id="assignment-oos-app",
            application_id="assignment-oos-app-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        in_scope_app = DataverseUser(
            id="assignment-inscope-app",
            application_id="assignment-inscope-app-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[out_of_scope_app, in_scope_app],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[
                _role("role-in", "In Scope Reader"),
                _role("role-out", "Out Of Scope Reader"),
            ],
            role_privileges=[
                _privilege("role-in", "account"),
                _privilege("role-out", "contact"),
            ],
            user_role_assignments={
                in_scope_app.id: ["role-in"],
                out_of_scope_app.id: ["role-out"],
            },
            table_metadata=[_metadata("account"), _metadata("contact")],
        )
        partial_config = _config()
        partial_config.source.schemas[0].tables = ["account"]
        partial_client = _client(environment, partial_config)
        self.assertEqual(
            {"assignment-inscope-app-id"},
            partial_client.get_partial_application_ids_to_validate(),
        )

        strict_config = self._strict_config()
        strict_config.source.schemas[0].tables = ["account"]
        strict_client = _client(environment, strict_config)
        self.assertEqual(
            {"assignment-inscope-app-id"},
            strict_client.get_strict_application_ids_to_validate(),
        )

    def test_table_permissions_precedence_excludes_assignment_only_app_user(
        self,
    ) -> None:
        assignment_only_app = DataverseUser(
            id="tp-assignment-app",
            application_id="tp-assignment-app-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        table_app = DataverseUser(
            id="tp-table-app",
            application_id="tp-table-app-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[assignment_only_app, table_app],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-out", "Out Of Scope Reader")],
            role_privileges=[_privilege("role-out", "contact")],
            user_role_assignments={assignment_only_app.id: ["role-out"]},
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    has_read=True,
                    depth="Global",
                    principal_id=table_app.id,
                    principal_type=IamType.USER,
                    role_id="role-account",
                    role_name="Account Reader",
                    role_business_unit_id="bu-root",
                )
            ],
            table_metadata=[_metadata("account"), _metadata("contact")],
        )
        partial_config = _config()
        partial_config.source.schemas[0].tables = ["account"]
        partial_client = _client(environment, partial_config)
        self.assertEqual(
            {"tp-table-app-id"},
            partial_client.get_partial_application_ids_to_validate(),
        )

        strict_config = self._strict_config()
        strict_config.source.schemas[0].tables = ["account"]
        strict_client = _client(environment, strict_config)
        self.assertEqual(
            {"tp-table-app-id"},
            strict_client.get_strict_application_ids_to_validate(),
        )

    def test_cli_strict_path_finalizes_through_graph_before_apply(self) -> None:
        config = _config()
        config.dataverse.partial_sync = False
        config.dataverse.strict_access_parity = True
        config.service_principal = SimpleNamespace(
            tenant_id="tenant-id",
            client_id="client-id",
            client_secret="client-secret",
        )
        provisional_export = SimpleNamespace(policies=[])
        finalized_export = SimpleNamespace(policies=[])
        mapper = unittest.mock.Mock()
        mapper.environment = _two_role_environment()
        mapper.map_policy.return_value = provisional_export
        mapper.get_strict_application_ids_to_validate.return_value = {
            "strict-cli-app-id"
        }
        mapper.rebuild_strict_export_after_graph_validation.return_value = (
            finalized_export
        )
        agent = unittest.mock.Mock()
        agent.apply_role = AsyncMock()
        resolve_mock = AsyncMock(return_value=set())

        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "strict-apply.json"
            args = Namespace(
                config="unused.yaml",
                output=str(output_path),
                rollback_output=str(Path(directory) / "rollback.json"),
                fabric_dry_run=False,
                apply=True,
                rollback=None,
                assessment_mode=False,
                partial_sync=False,
                confirm_partial_sync=False,
                confirm_item="item-id",
                log_level="ERROR",
            )

            with (
                patch("scripts.dataverse_policy_sync.parse_args", return_value=args),
                patch.object(DataverseSourceMap, "from_yaml", return_value=config),
                patch(
                    "scripts.dataverse_policy_sync.Configuration.configure_environment"
                ),
                patch("scripts.dataverse_policy_sync.ServicePrincipal.initialize"),
                patch(
                    "scripts.dataverse_policy_sync.DataversePolicyWeaver",
                    return_value=mapper,
                ),
                patch(
                    "scripts.dataverse_policy_sync.WeaverAgent",
                    return_value=agent,
                ),
                patch(
                    "scripts.dataverse_policy_sync.resolve_application_ids",
                    new=resolve_mock,
                ),
            ):
                main()

            report = json.loads(output_path.read_text(encoding="utf-8"))

        resolve_mock.assert_awaited_once_with({"strict-cli-app-id"})
        mapper.rebuild_strict_export_after_graph_validation.assert_called_once_with(
            {"strict-cli-app-id"}, set()
        )
        agent.apply_role.assert_awaited_once()
        self.assertIs(finalized_export, agent.apply_role.await_args.args[0])
        self.assertEqual("applied", report["status"])

    def test_fsp_permissions_with_unsecured_metadata_quarantine_role(self) -> None:
        user = _user()
        environment = DataverseEnvironment(
            users=[user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-account", "Account Reader")],
            role_privileges=[_privilege("role-account", "account")],
            user_role_assignments={user.id: ["role-account"]},
            field_security_profiles=[
                DataverseFieldSecurityProfile(
                    id="profile-1",
                    user_ids=[user.id],
                    permissions=[
                        DataverseFieldPermission(
                            entity_name="account",
                            attribute_logical_name="secretcolumn",
                            can_read=4,
                        )
                    ],
                )
            ],
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual([], export.policies)
        self.assertIn(
            "inconsistent_cls_metadata", report["skipped_roles"][0]["reasons"]
        )

    def test_fsp_column_missing_from_secured_metadata_quarantines_role(self) -> None:
        user = _user()
        environment = DataverseEnvironment(
            users=[user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-account", "Account Reader")],
            role_privileges=[_privilege("role-account", "account")],
            user_role_assignments={user.id: ["role-account"]},
            field_security_profiles=[
                DataverseFieldSecurityProfile(
                    id="profile-1",
                    user_ids=[user.id],
                    permissions=[
                        DataverseFieldPermission(
                            entity_name="account",
                            attribute_logical_name="missingcolumn",
                            can_read=4,
                        )
                    ],
                )
            ],
            table_metadata=[
                DataverseTableMetadata(
                    logical_name="account",
                    ownership_type="UserOwned",
                    has_secured_columns=True,
                    columns=[
                        DataverseColumnMetadata(
                            metadata_id="secret-id",
                            logical_name="secretcolumn",
                            is_secured=True,
                        )
                    ],
                )
            ],
        )
        client = _client(environment, _config())

        export = client.__build_role_based_export__()
        report = client.get_partial_sync_report()

        self.assertEqual([], export.policies)
        self.assertIn(
            "inconsistent_cls_metadata", report["skipped_roles"][0]["reasons"]
        )

    def test_app_only_service_principal_is_emitted_for_valid_role(self) -> None:
        application_user = DataverseUser(
            id="application-user",
            application_id="application-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[application_user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-app", "Application Reader")],
            role_privileges=[_privilege("role-app", "account")],
            user_role_assignments={application_user.id: ["role-app"]},
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        export = client.__build_role_based_export__()

        self.assertEqual(1, len(export.policies))
        self.assertEqual(
            "application-id", export.policies[0].permissionobjects[0].app_id
        )

    def test_mixed_direct_role_skips_unresolved_application_only(self) -> None:
        human_user = _user("human-user")
        resolved_application_user = DataverseUser(
            id="resolved-application-user",
            application_id="resolved-application-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        unresolved_application_user = DataverseUser(
            id="unresolved-application-user",
            application_id="missing-application-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[
                human_user,
                resolved_application_user,
                unresolved_application_user,
            ],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-mixed", "Mixed Reader")],
            role_privileges=[_privilege("role-mixed", "account")],
            user_role_assignments={
                human_user.id: ["role-mixed"],
                resolved_application_user.id: ["role-mixed"],
                unresolved_application_user.id: ["role-mixed"],
            },
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        export = client.rebuild_partial_export_after_graph_validation(
            {"resolved-application-id", "missing-application-id"},
            {"missing-application-id"},
        )
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertIn("Mixed Reader", export.policies[0].name)
        self.assertEqual(
            {"entra-human-user", "resolved-application-id"},
            {
                permission_object.entra_object_id or permission_object.app_id
                for permission_object in export.policies[0].permissionobjects
            },
        )
        self.assertEqual(
            {"application_ids_checked": 2, "unresolved_application_ids": 1},
            report["graph_validation"],
        )
        self.assertEqual(0, report["skipped_role_count"])
        self.assertEqual(1, report["skipped_principal_assignment_count"])
        self.assertEqual(
            {"unresolved_graph_service_principal": 1},
            report["principal_reason_counts"],
        )
        self.assertEqual(
            [
                {
                    "assignment_context": "direct_role",
                    "principal_id": "unresolved-application-user",
                    "principal_type": "USER",
                    "reason": "unresolved_graph_service_principal",
                    "role_id": "role-mixed",
                    "role_name": "Mixed Reader",
                }
            ],
            report["skipped_principal_assignments"],
        )

    def test_direct_role_with_only_unresolved_application_is_not_published(
        self,
    ) -> None:
        unresolved_application_user = DataverseUser(
            id="unresolved-application-user",
            application_id="missing-application-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[unresolved_application_user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-application", "Application Reader")],
            role_privileges=[_privilege("role-application", "account")],
            user_role_assignments={
                unresolved_application_user.id: ["role-application"]
            },
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        export = client.rebuild_partial_export_after_graph_validation(
            {"missing-application-id"}, {"missing-application-id"}
        )
        report = client.get_partial_sync_report()

        self.assertEqual([], export.policies)
        self.assertEqual(1, report["skipped_principal_assignment_count"])
        self.assertIn(
            "no_resolvable_members",
            report["skipped_roles"][0]["reasons"],
        )

    def test_unresolved_only_role_preserves_no_member_and_semantic_reasons(
        self,
    ) -> None:
        unresolved_application_user = DataverseUser(
            id="unresolved-application-user",
            application_id="missing-application-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[unresolved_application_user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-unsafe", "Unsafe Reader")],
            role_privileges=[
                _privilege(
                    "role-unsafe",
                    "account",
                    record_filter_id="filter-1",
                )
            ],
            user_role_assignments={unresolved_application_user.id: ["role-unsafe"]},
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        export = client.rebuild_partial_export_after_graph_validation(
            {"missing-application-id"}, {"missing-application-id"}
        )
        report = client.get_partial_sync_report()

        self.assertEqual([], export.policies)
        self.assertEqual(1, report["skipped_role_count"])
        self.assertEqual(
            ["no_resolvable_members", "record_filter_not_supported"],
            report["skipped_roles"][0]["reasons"],
        )
        self.assertEqual(
            {
                "no_resolvable_members": 1,
                "record_filter_not_supported": 1,
            },
            report["reason_counts"],
        )

    def test_owner_team_skips_unresolved_member_only(self) -> None:
        human_user = _user("human-user")
        unresolved_application_user = DataverseUser(
            id="unresolved-application-user",
            application_id="missing-application-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        owner_team = DataverseTeam(
            id="owner-team",
            team_type=0,
            business_unit_id="bu-root",
            member_ids=[
                human_user.id,
                unresolved_application_user.id,
                "missing-snapshot-user",
            ],
        )
        environment = DataverseEnvironment(
            users=[human_user, unresolved_application_user],
            teams=[owner_team],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-team", "Team Reader")],
            role_privileges=[_privilege("role-team", "account")],
            team_role_assignments={owner_team.id: ["role-team"]},
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        export = client.rebuild_partial_export_after_graph_validation(
            {"missing-application-id"}, {"missing-application-id"}
        )
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertEqual(
            ["entra-human-user"],
            [
                permission_object.entra_object_id
                for permission_object in export.policies[0].permissionobjects
            ],
        )
        self.assertEqual(0, report["skipped_role_count"])
        self.assertEqual(
            [
                {
                    "assignment_context": "team_member",
                    "principal_id": "owner-team",
                    "principal_type": "GROUP",
                    "reason": "missing_team_member_snapshot",
                    "role_id": "role-team",
                    "role_name": "Team Reader",
                    "team_member_id": "missing-snapshot-user",
                    "team_type": 0,
                },
                {
                    "assignment_context": "team_member",
                    "principal_id": "owner-team",
                    "principal_type": "GROUP",
                    "reason": "unresolved_graph_service_principal",
                    "role_id": "role-team",
                    "role_name": "Team Reader",
                    "team_member_id": "unresolved-application-user",
                    "team_type": 0,
                },
            ],
            report["skipped_principal_assignments"],
        )

    def test_owner_team_with_only_unresolved_member_is_not_published(self) -> None:
        unresolved_application_user = DataverseUser(
            id="unresolved-application-user",
            application_id="missing-application-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        owner_team = DataverseTeam(
            id="owner-team",
            team_type=0,
            business_unit_id="bu-root",
            member_ids=[unresolved_application_user.id],
        )
        environment = DataverseEnvironment(
            users=[unresolved_application_user],
            teams=[owner_team],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-team", "Team Reader")],
            role_privileges=[_privilege("role-team", "account")],
            team_role_assignments={owner_team.id: ["role-team"]},
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        export = client.rebuild_partial_export_after_graph_validation(
            {"missing-application-id"}, {"missing-application-id"}
        )
        report = client.get_partial_sync_report()

        self.assertEqual([], export.policies)
        self.assertEqual(1, report["skipped_principal_assignment_count"])
        self.assertEqual(
            ["no_resolvable_members"], report["skipped_roles"][0]["reasons"]
        )

    def test_empty_owner_team_fsp_does_not_grant_direct_user_column(self) -> None:
        direct_user = _user("direct-principal")
        owner_team = DataverseTeam(
            id="empty-owner-team",
            team_type=0,
            business_unit_id="bu-root",
            member_ids=[],
        )
        environment = DataverseEnvironment(
            users=[direct_user],
            teams=[owner_team],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-mixed", "Mixed Reader")],
            role_privileges=[_privilege("role-mixed", "account")],
            user_role_assignments={direct_user.id: ["role-mixed"]},
            team_role_assignments={owner_team.id: ["role-mixed"]},
            field_security_profiles=[
                DataverseFieldSecurityProfile(
                    id="profile-owner-team",
                    team_ids=[owner_team.id],
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
                    has_secured_columns=True,
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
        config = _config()
        config.dataverse.partial_sync = False
        client = _client(environment, config)

        export = client.__build_role_based_export__()

        self.assertEqual(1, len(export.policies))
        self.assertEqual(
            ["accountid"], export.policies[0].columnconstraints[0].column_names
        )
        self.assertEqual(
            ["entra-direct-principal"],
            [
                permission_object.entra_object_id
                for permission_object in export.policies[0].permissionobjects
            ],
        )

    def test_excluded_owner_team_member_does_not_affect_basic_filter(self) -> None:
        current_member = _user("current-member")
        excluded_member = DataverseUser(
            id="excluded-member",
            application_id="unresolved-application",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        owner_team = DataverseTeam(
            id="owner-team",
            team_type=0,
            business_unit_id="bu-root",
            member_ids=[excluded_member.id, current_member.id],
        )
        environment = DataverseEnvironment(
            users=[excluded_member, current_member],
            teams=[owner_team],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-basic", "Basic Reader")],
            role_privileges=[_privilege("role-basic", "account", depth="Basic")],
            team_role_assignments={owner_team.id: ["role-basic"]},
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        export = client.rebuild_partial_export_after_graph_validation(
            {"unresolved-application"}, {"unresolved-application"}
        )
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        filter_conditions = [
            constraint.filter_condition
            for constraint in export.policies[0].rowconstraints or []
        ]
        self.assertTrue(filter_conditions)
        serialized_filters = json.dumps(filter_conditions)
        self.assertIn("current-member", serialized_filters)
        self.assertIn("owner-team", serialized_filters)
        self.assertNotIn("excluded-member", serialized_filters)
        self.assertEqual(1, report["skipped_principal_assignment_count"])

    def test_strict_mode_rejects_empty_owner_team_assignment(self) -> None:
        direct_user = _user("strict-principal")
        owner_team = DataverseTeam(
            id="empty-owner-team",
            team_type=0,
            business_unit_id="bu-root",
            member_ids=[],
        )
        environment = DataverseEnvironment(
            users=[direct_user],
            teams=[owner_team],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-strict", "Strict Reader")],
            role_privileges=[_privilege("role-strict", "account")],
            user_role_assignments={direct_user.id: ["role-strict"]},
            team_role_assignments={owner_team.id: ["role-strict"]},
            table_metadata=[_metadata("account")],
        )
        config = _config()
        config.dataverse.partial_sync = False
        config.dataverse.strict_access_parity = True
        client = _client(environment, config)

        with self.assertRaisesRegex(ValueError, "unresolvable Entra identities"):
            client.__build_role_based_export__()

    def test_principal_audit_is_deterministic_and_omits_identity_labels(
        self,
    ) -> None:
        principal_b = DataverseUser(
            id="principal-b",
            azure_ad_object_id="entra-principal-b",
            business_unit_id="bu-root",
            access_mode=3,
            is_licensed=False,
            azure_state=0,
        )
        principal_a = DataverseUser(
            id="principal-a",
            azure_ad_object_id="entra-principal-a",
            business_unit_id="bu-root",
            access_mode=3,
            is_licensed=False,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[principal_b, principal_a],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-audit", "Audit Reader")],
            role_privileges=[_privilege("role-audit", "account")],
            user_role_assignments={
                principal_b.id: ["role-audit"],
                principal_a.id: ["role-audit"],
            },
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        client.__build_role_based_export__()
        audit_entries = client.get_partial_sync_report()[
            "skipped_principal_assignments"
        ]

        self.assertEqual(
            ["principal-a", "principal-b"],
            [entry["principal_id"] for entry in audit_entries],
        )
        serialized_audit = json.dumps(audit_entries, sort_keys=True).casefold()
        self.assertNotIn('"email"', serialized_audit)
        self.assertNotIn('"display_name"', serialized_audit)
        self.assertNotIn('"displayname"', serialized_audit)

    def test_partial_mode_skips_ineligible_direct_user_only(self) -> None:
        human_user = _user("human-user")
        ineligible_user = DataverseUser(
            id="ineligible-user",
            azure_ad_object_id="entra-ineligible-user",
            business_unit_id="bu-root",
            access_mode=3,
            is_licensed=False,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[human_user, ineligible_user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-mixed", "Mixed Reader")],
            role_privileges=[_privilege("role-mixed", "account")],
            user_role_assignments={
                human_user.id: ["role-mixed"],
                ineligible_user.id: ["role-mixed"],
            },
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        export = client.rebuild_partial_export_after_graph_validation(set(), set())
        report = client.get_partial_sync_report()

        self.assertEqual(1, len(export.policies))
        self.assertEqual(
            ["entra-human-user"],
            [
                permission_object.entra_object_id
                for permission_object in export.policies[0].permissionobjects
            ],
        )
        self.assertEqual({"ineligible_user": 1}, report["principal_reason_counts"])

    def test_missing_direct_user_snapshot_does_not_quarantine_valid_peer(self) -> None:
        for permission_source in ("role_privileges", "table_permissions"):
            with self.subTest(permission_source=permission_source):
                valid_user = _user(f"valid-{permission_source}-user")
                missing_user_id = f"missing-{permission_source}-user"
                role = _role("role-mixed-snapshot", "Mixed Snapshot Reader")
                table_permissions = []
                role_privileges = []
                user_role_assignments = {}
                if permission_source == "role_privileges":
                    role_privileges = [_privilege(role.id, "account")]
                    user_role_assignments = {
                        valid_user.id: [role.id],
                        missing_user_id: [role.id],
                    }
                else:
                    table_permissions = [
                        DataverseTablePermission(
                            table_name="account",
                            has_read=True,
                            depth="Global",
                            principal_id=principal_id,
                            principal_type=IamType.USER,
                            role_id=role.id,
                            role_name=role.name,
                            role_business_unit_id="bu-root",
                        )
                        for principal_id in (valid_user.id, missing_user_id)
                    ]
                environment = DataverseEnvironment(
                    users=[valid_user],
                    business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
                    security_roles=[role],
                    role_privileges=role_privileges,
                    user_role_assignments=user_role_assignments,
                    table_permissions=table_permissions,
                    table_metadata=[_metadata("account")],
                )
                client = _client(environment, _config())

                export = client.rebuild_partial_export_after_graph_validation(
                    set(), set()
                )
                report = client.get_partial_sync_report()

                self.assertEqual(1, len(export.policies))
                self.assertEqual(
                    [valid_user.azure_ad_object_id],
                    [
                        permission_object.entra_object_id
                        for permission_object in export.policies[0].permissionobjects
                    ],
                )
                self.assertEqual(0, report["skipped_role_count"])
                self.assertNotIn("invalid_assignment_context", report["reason_counts"])
                self.assertEqual(
                    {"missing_assigned_user_snapshot": 1},
                    report["principal_reason_counts"],
                )
                self.assertEqual(
                    [missing_user_id],
                    [
                        assignment["principal_id"]
                        for assignment in report["skipped_principal_assignments"]
                    ],
                )

    def test_known_excluded_user_with_invalid_bu_context_quarantines_role(
        self,
    ) -> None:
        for permission_source in ("role_privileges", "table_permissions"):
            for identity_failure in ("ineligible", "graph_unresolved"):
                for invalid_business_unit_id in (None, "bu-other"):
                    with self.subTest(
                        permission_source=permission_source,
                        identity_failure=identity_failure,
                        invalid_business_unit_id=invalid_business_unit_id,
                    ):
                        valid_user = _user("valid-context-user")
                        if identity_failure == "ineligible":
                            excluded_user = DataverseUser(
                                id="known-excluded-user",
                                azure_ad_object_id="entra-known-excluded-user",
                                business_unit_id=invalid_business_unit_id,
                                access_mode=3,
                                is_licensed=False,
                                azure_state=0,
                            )
                            checked_application_ids = set()
                            unresolved_application_ids = set()
                            expected_principal_reason = "ineligible_user"
                        else:
                            excluded_user = DataverseUser(
                                id="known-excluded-user",
                                application_id="unresolved-application-id",
                                business_unit_id=invalid_business_unit_id,
                                access_mode=4,
                                is_licensed=False,
                                azure_state=0,
                            )
                            checked_application_ids = {"unresolved-application-id"}
                            unresolved_application_ids = {"unresolved-application-id"}
                            expected_principal_reason = (
                                "unresolved_graph_service_principal"
                            )

                        role = _role("role-invalid-context", "Context Reader")
                        role_privileges = []
                        user_role_assignments = {}
                        table_permissions = []
                        if permission_source == "role_privileges":
                            role_privileges = [_privilege(role.id, "account")]
                            user_role_assignments = {
                                valid_user.id: [role.id],
                                excluded_user.id: [role.id],
                            }
                        else:
                            table_permissions = [
                                DataverseTablePermission(
                                    table_name="account",
                                    has_read=True,
                                    depth="Global",
                                    principal_id=principal_id,
                                    principal_type=IamType.USER,
                                    role_id=role.id,
                                    role_name=role.name,
                                    role_business_unit_id="bu-root",
                                )
                                for principal_id in (
                                    valid_user.id,
                                    excluded_user.id,
                                )
                            ]

                        environment = DataverseEnvironment(
                            users=[valid_user, excluded_user],
                            business_units=[
                                DataverseBusinessUnit(id="bu-root", name="Root"),
                                DataverseBusinessUnit(id="bu-other", name="Other"),
                            ],
                            security_roles=[role],
                            role_privileges=role_privileges,
                            user_role_assignments=user_role_assignments,
                            table_permissions=table_permissions,
                            table_metadata=[_metadata("account")],
                        )
                        client = _client(environment, _config())

                        export = client.rebuild_partial_export_after_graph_validation(
                            checked_application_ids,
                            unresolved_application_ids,
                        )
                        report = client.get_partial_sync_report()

                        self.assertEqual([], export.policies)
                        self.assertEqual(1, report["skipped_role_count"])
                        self.assertIn(
                            "invalid_assignment_context",
                            report["skipped_roles"][0]["reasons"],
                        )
                        self.assertEqual(
                            {expected_principal_reason: 1},
                            report["principal_reason_counts"],
                        )
                        self.assertEqual(
                            [excluded_user.id],
                            [
                                assignment["principal_id"]
                                for assignment in report[
                                    "skipped_principal_assignments"
                                ]
                            ],
                        )

    def test_strict_mode_rejects_unresolvable_assigned_identity(self) -> None:
        ineligible_user = DataverseUser(
            id="ineligible-user",
            azure_ad_object_id="entra-ineligible-user",
            business_unit_id="bu-root",
            access_mode=3,
            is_licensed=False,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[ineligible_user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-strict", "Strict Reader")],
            role_privileges=[_privilege("role-strict", "account")],
            user_role_assignments={ineligible_user.id: ["role-strict"]},
            table_metadata=[_metadata("account")],
        )
        config = _config()
        config.dataverse.partial_sync = False
        config.dataverse.strict_access_parity = True
        client = _client(environment, config)

        with self.assertRaisesRegex(ValueError, "unresolvable Entra identities"):
            client.__build_role_based_export__()

    def test_unsafe_privilege_still_quarantines_role_after_identity_skip(
        self,
    ) -> None:
        human_user = _user("human-user")
        unresolved_application_user = DataverseUser(
            id="unresolved-application-user",
            application_id="missing-application-id",
            business_unit_id="bu-root",
            access_mode=4,
            is_licensed=False,
            azure_state=0,
        )
        environment = DataverseEnvironment(
            users=[human_user, unresolved_application_user],
            business_units=[DataverseBusinessUnit(id="bu-root", name="Root")],
            security_roles=[_role("role-unsafe", "Unsafe Reader")],
            role_privileges=[
                _privilege(
                    "role-unsafe",
                    "account",
                    record_filter_id="record-filter-id",
                )
            ],
            user_role_assignments={
                human_user.id: ["role-unsafe"],
                unresolved_application_user.id: ["role-unsafe"],
            },
            table_metadata=[_metadata("account")],
        )
        client = _client(environment, _config())

        export = client.rebuild_partial_export_after_graph_validation(
            {"missing-application-id"}, {"missing-application-id"}
        )
        report = client.get_partial_sync_report()

        self.assertEqual([], export.policies)
        self.assertIn(
            "record_filter_not_supported",
            report["skipped_roles"][0]["reasons"],
        )
        self.assertEqual(1, report["skipped_principal_assignment_count"])


if __name__ == "__main__":
    unittest.main()
