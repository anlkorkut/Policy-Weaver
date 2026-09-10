import pytest

from scripts.onelake_rls_boundary_probe import (
    build_predicate,
    extract_row_value,
    role_payload,
    sanitize_role_for_put,
)


@pytest.mark.parametrize("length", [99, 100, 101, 999, 1000, 1001, 4096])
def test_build_predicate_produces_exact_requested_length(length: int) -> None:
    value = build_predicate(length, "account", "ownerid", "missing")

    assert len(value) == length
    assert value.startswith("SELECT * FROM account WHERE ownerid in ('missing'")


def test_build_predicate_rejects_too_small_length() -> None:
    with pytest.raises(ValueError, match="cannot fit"):
        build_predicate(10, "account", "ownerid", "missing")


def test_role_payload_and_extract_row_value_round_trip() -> None:
    predicate = build_predicate(200, "account", "ownerid", "missing")
    role = role_payload(
        role_name="Probe",
        table_path="/Tables/dbo/account",
        predicate=predicate,
        workspace_id="workspace-id",
        item_id="item-id",
        tenant_id="tenant-id",
    )

    assert extract_row_value(role, "/Tables/dbo/account") == predicate


def test_sanitize_role_for_put_removes_list_only_etag() -> None:
    result = sanitize_role_for_put(
        {
            "id": "role-id",
            "name": "Probe",
            "kind": "Policy",
            "decisionRules": [],
            "members": {},
            "eTag": "etag",
        }
    )

    assert "eTag" not in result
    assert result["id"] == "role-id"
