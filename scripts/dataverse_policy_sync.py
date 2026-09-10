"""Compile and safely synchronize Dataverse security to OneLake roles."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from httpx import HTTPError as HttpxHTTPError
from requests.exceptions import RequestException

from policyweaver.core.auth import ServicePrincipal
from policyweaver.core.api.fabric import FabricAPI
from policyweaver.core.api.microsoftgraph import MicrosoftGraphClient
from policyweaver.core.conf import Configuration
from policyweaver.core.exception import FabricCapacityNotActiveError
from policyweaver.models.config import SourceSchema
from policyweaver.plugins.dataverse.client import DataversePolicyWeaver
from policyweaver.plugins.dataverse.model import DataverseSourceMap
from policyweaver.weaver import WeaverAgent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compile Dataverse policies, optionally validate them with Fabric "
            "dryRun, and apply only after an explicit item confirmation."
        )
    )
    parser.add_argument("--config", default="configdataverse.yaml")
    parser.add_argument(
        "--tables-file",
        help=(
            "Optional UTF-8 file containing one mirrored Dataverse logical table "
            "name per line. Blank lines and lines beginning with # are ignored."
        ),
    )
    parser.add_argument(
        "--output", default="reports/dataverse-policy-sync-preflight.json"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--fabric-dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--rollback", metavar="SNAPSHOT")
    parser.add_argument(
        "--assessment-mode",
        action="store_true",
        help=(
            "Compile with strict parity disabled. This mode can never call Fabric "
            "because POA, POAA, or RecordFilter access may be under-granted."
        ),
    )
    parser.add_argument(
        "--partial-sync",
        action="store_true",
        help=(
            "Quarantine entire noncompliant Dataverse roles, compile the valid "
            "subset, and allow Fabric dry-run/apply without claiming exact parity."
        ),
    )
    parser.add_argument(
        "--confirm-partial-sync",
        action="store_true",
        help=(
            "Required with --partial-sync --apply to acknowledge that quarantined "
            "roles and unsupported environment-wide entitlements will be under-granted."
        ),
    )
    parser.add_argument(
        "--confirm-item",
        help=(
            "Required with --apply/--rollback and partial Fabric dry-run; "
            "must equal fabric.mirror_id."
        ),
    )
    parser.add_argument(
        "--rollback-output",
        default="reports/dataverse-policy-rollback.json",
        help="Pre-apply snapshot written before --apply.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser.parse_args()


def configure_sync_mode(config: DataverseSourceMap, args: argparse.Namespace) -> None:
    if args.assessment_mode and (args.fabric_dry_run or args.apply or args.rollback):
        raise ValueError(
            "--assessment-mode cannot be combined with a Fabric operation."
        )
    if args.assessment_mode and args.partial_sync:
        raise ValueError("--assessment-mode cannot be combined with --partial-sync.")
    if config.dataverse.partial_sync and not args.partial_sync:
        raise ValueError(
            "Configuration enables dataverse.partial_sync; pass --partial-sync "
            "explicitly for every partial operation."
        )
    if args.confirm_partial_sync and not (args.partial_sync and args.apply):
        raise ValueError(
            "--confirm-partial-sync is only valid with --partial-sync --apply."
        )
    if args.partial_sync and args.apply and not args.confirm_partial_sync:
        raise ValueError(
            "Partial apply requires --confirm-partial-sync to acknowledge known "
            "under-grants."
        )

    if args.assessment_mode:
        config.dataverse.strict_access_parity = False
        config.dataverse.partial_sync = False
    elif args.partial_sync:
        config.dataverse.strict_access_parity = False
        config.dataverse.partial_sync = True
    elif (args.fabric_dry_run or args.apply) and not (
        config.dataverse.strict_access_parity
    ):
        raise ValueError(
            "Fabric operations require dataverse.strict_access_parity=true."
        )

    item_confirmation_required = bool(
        args.apply or args.rollback or (args.partial_sync and args.fabric_dry_run)
    )
    if item_confirmation_required and args.confirm_item != config.fabric.mirror_id:
        raise ValueError(
            "--confirm-item must exactly match fabric.mirror_id for this operation."
        )


def validate_apply_output_paths(args: argparse.Namespace) -> None:
    if not args.apply:
        return
    output_path = Path(args.output).expanduser()
    rollback_path = Path(args.rollback_output).expanduser()
    paths_collide = os.path.normcase(str(output_path.resolve())) == os.path.normcase(
        str(rollback_path.resolve())
    )
    if not paths_collide and output_path.exists() and rollback_path.exists():
        try:
            paths_collide = os.path.samefile(output_path, rollback_path)
        except FileNotFoundError:
            paths_collide = False
    if paths_collide:
        raise ValueError(
            "--output and --rollback-output must identify different files for --apply."
        )


def configure_source_tables(
    config: DataverseSourceMap, tables_file: str | None
) -> dict[str, Any] | None:
    if not tables_file:
        return None

    path = Path(tables_file).expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"Dataverse table scope file does not exist: {path}")

    tables_by_key: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8-sig").splitlines(), start=1
    ):
        table_name = raw_line.strip()
        if not table_name or table_name.startswith("#"):
            continue
        if not re.fullmatch(r"[A-Za-z0-9_]+", table_name):
            raise ValueError(
                f"Invalid Dataverse logical table name on line {line_number}: "
                f"{table_name!r}"
            )
        tables_by_key.setdefault(table_name.casefold(), table_name)

    if not tables_by_key:
        raise ValueError("Dataverse table scope file contains no table names.")

    configured_schemas = config.source.schemas or []
    schema_name = next(
        (schema.name for schema in configured_schemas if schema.name), "dbo"
    )
    configured_table_keys = {
        table_name.casefold()
        for schema in configured_schemas
        for table_name in schema.tables or []
    }
    effective_keys = set(tables_by_key)
    if configured_table_keys:
        effective_keys.intersection_update(configured_table_keys)
        if not effective_keys:
            raise ValueError(
                "Dataverse table scope file has no tables in common with the "
                "configured table allowlist."
            )
    tables = [tables_by_key[key] for key in sorted(effective_keys)]
    config.source.schemas = [SourceSchema(name=schema_name, tables=tables)]
    return {"path": str(path), "schema": schema_name, "table_count": len(tables)}


def build_summary(mapper: DataversePolicyWeaver, export=None) -> dict[str, Any]:
    environment = mapper.environment
    policies = export.policies or [] if export else []
    role_by_id = {role.id: role for role in environment.security_roles or [] if role.id}
    team_role_ids = {
        role_id
        for role_ids in (environment.team_role_assignments or {}).values()
        for role_id in role_ids or []
    }
    return {
        "business_units": len(environment.business_units or []),
        "users": len(environment.users or []),
        "teams": len(environment.teams or []),
        "security_role_instances": len(environment.security_roles or []),
        "read_privileges": len(environment.role_privileges or []),
        "field_security_profiles": len(environment.field_security_profiles or []),
        "active_attribute_masking_rules": (
            len(environment.attribute_masking_rules)
            if environment.attribute_masking_rules is not None
            else None
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
        "role_assigned_entra_group_teams": sum(
            team.team_type in {2, 3}
            and bool((environment.team_role_assignments or {}).get(team.id))
            for team in environment.teams or []
        ),
        "unknown_read_depths": sum(
            (privilege.depth or "Unknown").title()
            not in {"Basic", "Local", "Deep", "Global"}
            for privilege in environment.role_privileges or []
            if privilege.can_read and privilege.entity_name
        ),
        "unknown_team_role_inheritance": sum(
            role_by_id.get(role_id) is None
            or role_by_id[role_id].is_inherited not in {0, 1}
            for role_id in team_role_ids
        ),
        "poaa_read_grants": len(environment.principal_object_attribute_accesses or []),
        "record_filter_read_privileges": sum(
            bool(privilege.record_filter_id)
            for privilege in environment.role_privileges or []
            if privilege.can_read
        ),
        "generated_role_policies": len(policies),
        "generated_memberships": sum(
            len(policy.permissionobjects or []) for policy in policies
        ),
        "generated_table_scopes": sum(
            len(policy.permissionscopes or []) for policy in policies
        ),
        "generated_row_constraints": sum(
            len(policy.rowconstraints or []) for policy in policies
        ),
        "generated_column_constraints": sum(
            len(policy.columnconstraints or []) for policy in policies
        ),
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def sanitize_role_for_put(role: dict[str, Any]) -> dict[str, Any]:
    allowed = {"id", "name", "kind", "decisionRules", "members"}
    return {key: deepcopy(value) for key, value in role.items() if key in allowed}


def canonical_roles(roles: list[dict[str, Any]]) -> list[str]:
    canonical = []
    for role in roles:
        value = sanitize_role_for_put(role)
        members = value.get("members")
        if isinstance(members, dict):
            entra_members = members.get("microsoftEntraMembers")
            if isinstance(entra_members, list):
                for member in entra_members:
                    if isinstance(member, dict):
                        member.pop("objectType", None)
        canonical.append(json.dumps(value, sort_keys=True))
    return sorted(canonical)


async def resolve_application_ids(
    application_ids: set[str], max_concurrency: int = 10
) -> set[str]:
    if not application_ids:
        return set()
    graph_client = MicrosoftGraphClient()
    semaphore = asyncio.Semaphore(max_concurrency)

    async def resolve(application_id: str) -> tuple[str, str | None]:
        async with semaphore:
            try:
                object_id = await graph_client.get_service_principal_by_id(
                    application_id
                )
            except HttpxHTTPError as error:
                logging.getLogger("POLICY_WEAVER").warning(
                    "Microsoft Graph lookup for application ID %s failed with %s; "
                    "treating the identity as unresolved for fail-closed quarantine.",
                    application_id,
                    type(error).__name__,
                )
                object_id = None
            return application_id, object_id

    results = await asyncio.gather(
        *(resolve(application_id) for application_id in sorted(application_ids))
    )
    return {application_id for application_id, object_id in results if not object_id}


def restore_snapshot(
    config: DataverseSourceMap, snapshot_path: Path, output_path: Path
) -> dict[str, Any]:
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    if snapshot.get("workspace_id") != config.fabric.workspace_id:
        raise ValueError("Rollback snapshot workspace_id doesn't match configuration.")
    if snapshot.get("item_id") != config.fabric.mirror_id:
        raise ValueError("Rollback snapshot item_id doesn't match configuration.")
    roles = snapshot.get("value")
    if not isinstance(roles, list):
        raise ValueError("Rollback snapshot is missing a role collection.")

    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "rollback",
        "status": "started",
        "workspace_id": config.fabric.workspace_id,
        "fabric_item_id": config.fabric.mirror_id,
        "restored_roles": len(roles),
        "snapshot": str(snapshot_path),
        "fabric_operation_stage": "rollback-readiness",
        "fabric_operation_status": "started",
    }
    try:
        fabric_api = FabricAPI(config.fabric.workspace_id, config.type)
        fabric_api.list_data_access_policy(config.fabric.mirror_id)
        etag = fabric_api.data_access_roles_etag
        if not etag:
            raise ValueError("Fabric didn't return an ETag for rollback.")
        payload = json.dumps({"value": roles})
        report["fabric_operation_stage"] = "rollback-dry-run"
        fabric_api.put_data_access_policy(
            config.fabric.mirror_id, payload, dry_run=True, if_match=etag
        )
        report["fabric_operation_stage"] = "rollback-apply"
        verified = None
        try:
            fabric_api.put_data_access_policy(
                config.fabric.mirror_id, payload, dry_run=False, if_match=etag
            )
        except (RequestException, FabricCapacityNotActiveError):
            verified = fabric_api.list_data_access_policy(config.fabric.mirror_id)[
                "value"
            ]
            if canonical_roles(verified) != canonical_roles(roles):
                raise
        report["fabric_operation_stage"] = "rollback-verification"
        if verified is None:
            verified = fabric_api.list_data_access_policy(config.fabric.mirror_id)[
                "value"
            ]
        if canonical_roles(verified) != canonical_roles(roles):
            raise RuntimeError(
                "Fabric rollback verification didn't match the snapshot."
            )
    except Exception as error:
        report["status"] = "failed"
        report["fabric_operation_status"] = "failed"
        report["error_type"] = type(error).__name__
        report["error"] = str(error)
        if isinstance(error, FabricCapacityNotActiveError):
            report["fabric_capacity_id"] = error.capacity_id
            report["fabric_operation_status"] = "blocked-capacity-not-active"
        write_report(output_path, report)
        raise

    report.update(
        {
            "status": "restored-and-verified",
            "fabric_operation_status": "completed",
        }
    )
    write_report(output_path, report)
    return report


def main() -> None:
    args = parse_args()
    validate_apply_output_paths(args)
    logging.basicConfig(level=getattr(logging, args.log_level))
    config = DataverseSourceMap.from_yaml(args.config)
    if not config.service_principal:
        raise ValueError("service_principal configuration is required.")
    if not config.fabric or not config.fabric.mirror_id:
        raise ValueError("fabric.mirror_id configuration is required.")
    configure_sync_mode(config, args)
    source_table_scope = configure_source_tables(
        config, getattr(args, "tables_file", None)
    )
    Configuration.configure_environment(config)
    ServicePrincipal.initialize(
        tenant_id=config.service_principal.tenant_id,
        client_id=config.service_principal.client_id,
        client_secret=config.service_principal.client_secret,
    )

    output_path = Path(args.output)
    if args.rollback:
        report = restore_snapshot(config, Path(args.rollback), output_path)
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": (
            "partial-apply"
            if args.partial_sync and args.apply
            else "partial-fabric-dry-run"
            if args.partial_sync and args.fabric_dry_run
            else "partial-compile"
            if args.partial_sync
            else "apply"
            if args.apply
            else "fabric-dry-run"
            if args.fabric_dry_run
            else "assessment"
            if args.assessment_mode
            else "strict-compile"
        ),
        "strict_access_parity": config.dataverse.strict_access_parity,
        "partial_sync": config.dataverse.partial_sync,
        "exact_access_parity": bool(config.dataverse.strict_access_parity),
        "poa_read_access_status": config.dataverse.poa_read_access_status,
        "fabric_item_id": config.fabric.mirror_id,
        "status": "started",
    }
    if source_table_scope:
        report["source_table_scope"] = source_table_scope
    mapper = DataversePolicyWeaver(config)
    agent = WeaverAgent(config) if args.fabric_dry_run or args.apply else None

    try:
        if agent:
            report["fabric_operation_stage"] = "readiness"
            report["fabric_operation_status"] = "started"
            report["fabric_write_preflight"] = "started"
            agent.validate_role_target_write_ready()
            report["fabric_write_preflight"] = "validated"
            report["fabric_operation_status"] = "validated"
        report["fabric_operation_stage"] = "extraction"
        report["fabric_operation_status"] = "started"
        export = mapper.map_policy("role_based")
        if config.dataverse.partial_sync:
            application_ids = mapper.get_partial_application_ids_to_validate()
            unresolved_application_ids = asyncio.run(
                resolve_application_ids(application_ids)
            )
            export = mapper.rebuild_partial_export_after_graph_validation(
                application_ids,
                unresolved_application_ids,
            )
        elif config.dataverse.strict_access_parity:
            strict_application_ids = mapper.get_strict_application_ids_to_validate()
            if strict_application_ids:
                unresolved_strict_application_ids = asyncio.run(
                    resolve_application_ids(strict_application_ids)
                )
                export = mapper.rebuild_strict_export_after_graph_validation(
                    strict_application_ids,
                    unresolved_strict_application_ids,
                )
        report["summary"] = build_summary(mapper, export)
        if config.dataverse.partial_sync:
            report["quarantine"] = mapper.get_partial_sync_report()
            if not export.policies:
                raise ValueError(
                    "Partial sync quarantined every Dataverse role. Refusing to "
                    "publish an empty managed role collection."
                )
        report["status"] = "compiled"
        report["fabric_operation_status"] = "completed"
        write_report(output_path, report)

        if args.fabric_dry_run or args.apply:
            report["fabric_operation_stage"] = (
                "candidate-apply" if args.apply else "candidate-dry-run"
            )
            report["fabric_operation_status"] = "started"
            if args.apply:
                rollback_path = Path(args.rollback_output)

                def persist_rollback_snapshot(
                    current: list[dict[str, Any]], prepared_etag: str
                ) -> None:
                    write_report(
                        rollback_path,
                        {
                            "captured_at": datetime.now(timezone.utc).isoformat(),
                            "workspace_id": config.fabric.workspace_id,
                            "item_id": config.fabric.mirror_id,
                            "etag": prepared_etag,
                            "value": [sanitize_role_for_put(role) for role in current],
                        },
                    )

                agent.prepare_role_apply(
                    args.confirm_item,
                    rollback_snapshot_handler=persist_rollback_snapshot,
                    partial_sync_acknowledged=args.confirm_partial_sync,
                )
                report["rollback_snapshot"] = str(rollback_path)
            asyncio.run(
                agent.apply_role(
                    export,
                    dry_run_only=not args.apply,
                    partial_sync_acknowledged=args.confirm_partial_sync,
                )
            )
            report["status"] = "applied" if args.apply else "dry-run-validated"
            report["fabric_operation_status"] = "completed"
            write_report(output_path, report)
    except Exception as error:
        if mapper.environment is not None:
            report["summary"] = build_summary(mapper)
        if isinstance(error, FabricCapacityNotActiveError):
            report["fabric_capacity_id"] = error.capacity_id
            if report.get("fabric_operation_stage") == "readiness":
                report["fabric_write_preflight"] = "blocked-capacity-not-active"
            report["fabric_operation_status"] = "blocked-capacity-not-active"
        else:
            report["fabric_operation_status"] = "failed"
        report["status"] = "failed"
        report["error_type"] = type(error).__name__
        report["error"] = str(error)
        write_report(output_path, report)
        raise

    print(json.dumps(report, indent=2, sort_keys=True))


def run_cli() -> None:
    try:
        main()
    except FabricCapacityNotActiveError as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    run_cli()
