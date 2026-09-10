"""Probe OneLake RowConstraint.value lengths without mutating roles by default.

Dry-run probes use the bulk PUT API with ``dryRun=true``. A real PUT is allowed
only for one length at a time and requires explicit confirmation that the item is
disposable. The script snapshots all current roles, preserves them in the PUT,
GETs the probe role to detect truncation, and deletes it unless told to keep it
for an enforcement query.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from policyweaver.core.auth import ServicePrincipal
from policyweaver.core.conf import Configuration
from policyweaver.plugins.dataverse.model import DataverseSourceMap


DEFAULT_LENGTHS = [999, 1000, 1001, 4095, 4096, 4097]


def build_predicate(
    target_length: int,
    table_reference: str,
    column_name: str,
    probe_value: str,
) -> str:
    """Build a static IN-list predicate of exactly ``target_length`` characters."""
    escaped_value = probe_value.replace("'", "''")
    quoted_value = f"'{escaped_value}'"
    prefix = f"SELECT * FROM {table_reference} WHERE {column_name} in ("
    suffix = ")"
    values = quoted_value
    value = f"{prefix}{values}{suffix}"
    if len(value) > target_length:
        raise ValueError(
            f"Base predicate is {len(value)} characters and cannot fit in "
            f"target length {target_length}."
        )
    repeated_value = f",{quoted_value}"
    while (
        len(prefix) + len(values) + len(repeated_value) + len(suffix) <= target_length
    ):
        values += repeated_value
    padding = " " * (target_length - len(prefix) - len(values) - len(suffix))
    value = f"{prefix}{values}{padding}{suffix}"
    if len(value) != target_length:
        raise AssertionError("Generated predicate length does not match target")
    return value


def role_payload(
    role_name: str,
    table_path: str,
    predicate: str,
    workspace_id: str,
    item_id: str,
    tenant_id: str,
    member_object_id: str | None = None,
    member_object_type: str = "User",
) -> dict[str, Any]:
    if member_object_id:
        members = {
            "microsoftEntraMembers": [
                {
                    "tenantId": tenant_id,
                    "objectId": member_object_id,
                    "objectType": member_object_type,
                }
            ]
        }
    else:
        members = {
            "fabricItemMembers": [
                {
                    "sourcePath": f"{workspace_id}/{item_id}",
                    "itemAccess": ["ReadAll"],
                }
            ]
        }

    return {
        "name": role_name,
        "kind": "Policy",
        "decisionRules": [
            {
                "effect": "Permit",
                "permission": [
                    {
                        "attributeName": "Path",
                        "attributeValueIncludedIn": [table_path],
                    },
                    {
                        "attributeName": "Action",
                        "attributeValueIncludedIn": ["Read"],
                    },
                ],
                "constraints": {
                    "rows": [{"tablePath": table_path, "value": predicate}]
                },
            }
        ],
        "members": members,
    }


def sanitize_role_for_put(role: dict[str, Any]) -> dict[str, Any]:
    """Remove list-only fields before sending a bulk PUT."""
    allowed = {"id", "name", "kind", "decisionRules", "members"}
    return {key: value for key, value in role.items() if key in allowed}


def extract_row_value(role: dict[str, Any], table_path: str) -> str | None:
    for decision_rule in role.get("decisionRules", []):
        for row in decision_rule.get("constraints", {}).get("rows", []):
            if row.get("tablePath") == table_path:
                return row.get("value")
    return None


def response_evidence(response: requests.Response) -> dict[str, Any]:
    try:
        body: Any = response.json()
    except requests.JSONDecodeError:
        body = response.text
    return {
        "status_code": response.status_code,
        "success": 200 <= response.status_code < 300,
        "headers": {
            key: value
            for key, value in response.headers.items()
            if key.lower()
            in {"etag", "location", "request-id", "retry-after", "x-ms-request-id"}
        },
        "body": body,
    }


class OneLakeRoleProbe:
    def __init__(self, workspace_id: str, item_id: str) -> None:
        self.workspace_id = workspace_id
        self.item_id = item_id
        self.base_url = (
            "https://api.fabric.microsoft.com/v1/"
            f"workspaces/{workspace_id}/items/{item_id}/dataAccessRoles"
        )
        retry = Retry(
            total=5,
            connect=5,
            read=5,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(["GET", "PUT", "DELETE"]),
        )
        self.session = requests.Session()
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.timeout = (10, 120)

    @property
    def headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {ServicePrincipal.get_token()}",
            "Content-Type": "application/json",
        }

    def list_roles(self) -> tuple[list[dict[str, Any]], str | None]:
        roles: list[dict[str, Any]] = []
        url: str | None = self.base_url
        etag: str | None = None
        while url:
            response = self.session.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            if etag is None:
                etag = response.headers.get("ETag")
            data = response.json()
            roles.extend(data.get("value", []))
            url = data.get("continuationUri")
        return roles, etag

    def bulk_put(
        self,
        roles: list[dict[str, Any]],
        dry_run: bool,
        etag: str | None,
    ) -> requests.Response:
        headers = self.headers
        if etag:
            headers["If-Match"] = etag
        return self.session.put(
            self.base_url,
            params={"dryRun": str(dry_run).lower()},
            headers=headers,
            json={"value": roles},
            timeout=self.timeout,
        )

    def get_role(self, role_name: str) -> requests.Response:
        return self.session.get(
            f"{self.base_url}/{quote(role_name, safe='')}",
            params={"preview": "true"},
            headers=self.headers,
            timeout=self.timeout,
        )

    def delete_role(self, role_name: str) -> requests.Response:
        return self.session.delete(
            f"{self.base_url}/{quote(role_name, safe='')}",
            params={"preview": "true"},
            headers=self.headers,
            timeout=self.timeout,
        )


def roles_with_probe(
    current_roles: list[dict[str, Any]], probe_role: dict[str, Any]
) -> list[dict[str, Any]]:
    probe_name = probe_role["name"].casefold()
    roles = [
        sanitize_role_for_put(role)
        for role in current_roles
        if str(role.get("name", "")).casefold() != probe_name
    ]
    roles.append(probe_role)
    return roles


def probe_length(
    client: OneLakeRoleProbe,
    current_roles: list[dict[str, Any]],
    etag: str | None,
    length: int,
    args: argparse.Namespace,
    dry_run: bool,
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    predicate = build_predicate(
        length,
        args.table_reference,
        args.column_name,
        args.probe_value,
    )
    name = f"{args.role_prefix}{length}"
    role = role_payload(
        role_name=name,
        table_path=args.table_path,
        predicate=predicate,
        workspace_id=client.workspace_id,
        item_id=client.item_id,
        tenant_id=args.tenant_id,
        member_object_id=args.member_object_id,
        member_object_type=args.member_object_type,
    )
    response = client.bulk_put(
        (
            roles_with_probe(current_roles, role)
            if not dry_run or args.include_existing_roles_in_dry_run
            else [role]
        ),
        dry_run=dry_run,
        etag=etag,
    )
    evidence = {
        "requested_length": length,
        "role_name": name,
        "dry_run": dry_run,
        "response": response_evidence(response),
    }
    return evidence, predicate, role


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configdataverse.yaml")
    parser.add_argument("--workspace-id")
    parser.add_argument("--item-id")
    parser.add_argument("--tenant-id")
    parser.add_argument("--table-path", required=True)
    parser.add_argument("--table-reference", required=True)
    parser.add_argument("--column-name", required=True)
    parser.add_argument("--probe-value", default="00000000-0000-0000-0000-000000000000")
    parser.add_argument("--lengths", nargs="+", type=int, default=DEFAULT_LENGTHS)
    parser.add_argument("--discover-max", action="store_true")
    parser.add_argument("--search-low", type=int, default=4098)
    parser.add_argument("--search-high", type=int, default=65536)
    parser.add_argument("--apply-length", type=int)
    parser.add_argument("--confirm-disposable-item")
    parser.add_argument("--member-object-id")
    parser.add_argument(
        "--member-object-type",
        choices=["User", "Group", "ServicePrincipal", "ManagedIdentity"],
        default="User",
    )
    parser.add_argument("--keep-role-for-query", action="store_true")
    parser.add_argument(
        "--include-existing-roles-in-dry-run",
        action="store_true",
        help="Validate the probe together with all current roles.",
    )
    parser.add_argument("--cleanup-role-name")
    parser.add_argument("--role-prefix", default="PWRLSBoundary")
    parser.add_argument("--output", default="reports/onelake-rls-boundary-probe.json")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", args.role_prefix):
        raise ValueError(
            "--role-prefix must start with a letter and contain only letters and numbers"
        )
    config = DataverseSourceMap.from_yaml(args.config)
    Configuration.configure_environment(config)
    if not config.service_principal or not config.fabric:
        raise ValueError("service_principal and fabric configuration are required")
    ServicePrincipal.initialize(
        tenant_id=config.service_principal.tenant_id,
        client_id=config.service_principal.client_id,
        client_secret=config.service_principal.client_secret,
    )

    workspace_id = args.workspace_id or config.fabric.workspace_id
    item_id = args.item_id or config.fabric.mirror_id
    args.tenant_id = args.tenant_id or config.fabric.tenant_id
    if not workspace_id or not item_id or not args.tenant_id:
        raise ValueError("workspace ID, item ID, and tenant ID are required")
    client = OneLakeRoleProbe(workspace_id, item_id)

    if args.cleanup_role_name:
        if args.confirm_disposable_item != item_id:
            raise ValueError(
                "--confirm-disposable-item must exactly match the target item ID"
            )
        response = client.delete_role(args.cleanup_role_name)
        report = {
            "mode": "cleanup",
            "workspace_id": workspace_id,
            "item_id": item_id,
            "role_name": args.cleanup_role_name,
            "response": response_evidence(response),
        }
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    current_roles, etag = client.list_roles()
    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workspace_id": workspace_id,
        "item_id": item_id,
        "table_path": args.table_path,
        "table_reference": args.table_reference,
        "column_name": args.column_name,
        "probe_value": args.probe_value,
        "existing_role_count": len(current_roles),
        "dry_run_probes": [],
    }

    for length in sorted(set(args.lengths)):
        evidence, _, _ = probe_length(
            client, current_roles, etag, length, args, dry_run=True
        )
        report["dry_run_probes"].append(evidence)

    if args.discover_max:
        low = args.search_low
        high = args.search_high
        largest_success: int | None = None
        smallest_failure: int | None = None
        binary_probes = []
        while low <= high:
            midpoint = (low + high) // 2
            evidence, _, _ = probe_length(
                client, current_roles, etag, midpoint, args, dry_run=True
            )
            binary_probes.append(evidence)
            if evidence["response"]["success"]:
                largest_success = midpoint
                low = midpoint + 1
            else:
                smallest_failure = midpoint
                high = midpoint - 1
        report["binary_search"] = {
            "largest_success": largest_success,
            "smallest_failure": smallest_failure,
            "probes": binary_probes,
        }

    if args.apply_length is not None:
        if args.confirm_disposable_item != item_id:
            raise ValueError(
                "A real PUT requires --confirm-disposable-item equal to the item ID."
            )
        if not args.member_object_id:
            raise ValueError(
                "A real PUT requires --member-object-id for enforcement testing."
            )
        dry_evidence, predicate, role = probe_length(
            client, current_roles, etag, args.apply_length, args, dry_run=True
        )
        if not dry_evidence["response"]["success"]:
            report["actual_probe"] = {
                "status": "skipped_after_failed_dry_run",
                "dry_run": dry_evidence,
            }
        else:
            put_response = client.bulk_put(
                roles_with_probe(current_roles, role), dry_run=False, etag=etag
            )
            actual: dict[str, Any] = {
                "requested_length": args.apply_length,
                "role_name": role["name"],
                "put": response_evidence(put_response),
            }
            if 200 <= put_response.status_code < 300:
                get_response = client.get_role(role["name"])
                actual["get"] = response_evidence(get_response)
                if 200 <= get_response.status_code < 300:
                    retrieved_value = extract_row_value(
                        get_response.json(), args.table_path
                    )
                    actual["retrieved_length"] = (
                        len(retrieved_value) if retrieved_value is not None else None
                    )
                    actual["predicate_exact_match"] = retrieved_value == predicate
                if args.keep_role_for_query:
                    actual["cleanup_pending"] = True
                    actual["query_expectation"] = (
                        "Query the table as the configured member and confirm the "
                        "configured base predicate is enforced."
                    )
                else:
                    delete_response = client.delete_role(role["name"])
                    actual["delete"] = response_evidence(delete_response)
            report["actual_probe"] = actual

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    summary = {
        "dry_run": [
            {
                "length": probe["requested_length"],
                "status": probe["response"]["status_code"],
                "success": probe["response"]["success"],
            }
            for probe in report["dry_run_probes"]
        ],
        "binary_search": report.get("binary_search", {}),
        "actual_probe": report.get("actual_probe"),
        "output": str(output_path),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
