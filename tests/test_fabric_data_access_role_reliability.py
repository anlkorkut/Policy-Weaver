import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from requests.exceptions import HTTPError, Timeout

from policyweaver.core.api.fabric import FabricAPI
from policyweaver.core.api.rest import RestAPIProxy
from policyweaver.core.auth import ServicePrincipal
from policyweaver.core.enum import (
    IamType,
    PermissionState,
    PermissionType,
    PolicyWeaverConnectorType,
)
from policyweaver.core.exception import (
    FabricCapacityNotActiveError,
    PolicyWeaverError,
)
from policyweaver.models.config import FabricConfig, Source
from policyweaver.models.export import (
    PermissionObject,
    PermissionScope,
    PolicyExport,
    RolePolicy,
    RolePolicyExport,
)
from policyweaver.models.fabric import DataAccessPolicy, PolicyMembers
from policyweaver.plugins.dataverse.client import (
    DataversePolicyWeaver,
    _mark_strict_dataverse_export_validated,
    is_strict_dataverse_export_validated,
)
from policyweaver.plugins.dataverse.model import (
    DataverseEnvironment,
    DataverseSourceConfig,
    DataverseSourceMap,
)
from policyweaver.weaver import WeaverAgent
from scripts.dataverse_policy_sync import restore_snapshot


class _FakeResponse:
    def __init__(self, payload: dict, headers: dict | None = None) -> None:
        self._payload = payload
        self.headers = headers or {}

    def json(self) -> dict:
        return self._payload


class _FakeRestProxy:
    def __init__(self) -> None:
        self.get_calls = []
        self.put_calls = []

    def get(self, endpoint: str, params: dict | None = None) -> _FakeResponse:
        self.get_calls.append((endpoint, params))
        if len(self.get_calls) == 1:
            return _FakeResponse(
                {
                    "value": [{"name": "Role1", "decisionRules": [], "members": {}}],
                    "continuationToken": "next-token",
                },
                {"ETag": '"collection-etag"'},
            )
        return _FakeResponse(
            {"value": [{"name": "Role2", "decisionRules": [], "members": {}}]}
        )

    def put(
        self,
        endpoint: str,
        data: str | None = None,
        headers: dict | None = None,
        params: dict | None = None,
    ) -> _FakeResponse:
        self.put_calls.append((endpoint, data, headers, params))
        return _FakeResponse({}, {"ETag": '"new-etag"'})


def _fabric_api() -> tuple[FabricAPI, _FakeRestProxy]:
    api = FabricAPI.__new__(FabricAPI)
    api.workspace_id = "workspace-id"
    api.logger = SimpleNamespace(debug=lambda *args, **kwargs: None)
    proxy = _FakeRestProxy()
    api.rest_api_proxy = proxy
    api.data_access_roles_etag = None
    return api, proxy


def test_list_data_access_roles_follows_continuation_token() -> None:
    api, proxy = _fabric_api()

    result = api.list_data_access_policy("item-id")

    assert [role["name"] for role in result["value"]] == ["Role1", "Role2"]
    assert proxy.get_calls[1][1] == {"continuationToken": "next-token"}
    assert api.data_access_roles_etag == '"collection-etag"'


def test_list_data_access_roles_rejects_missing_value_collection() -> None:
    api, _ = _fabric_api()
    api.rest_api_proxy = SimpleNamespace(
        get=lambda endpoint, params=None: _FakeResponse(
            {"unexpected": "response"}, {"ETag": '"collection-etag"'}
        )
    )

    try:
        api.list_data_access_policy("item-id")
    except ValueError as error:
        assert "value collection" in str(error)
    else:
        raise AssertionError("Malformed Fabric role response was treated as empty")


def test_put_data_access_roles_supports_dry_run_and_if_match() -> None:
    api, proxy = _fabric_api()

    api.put_data_access_policy(
        "item-id",
        '{"value": []}',
        dry_run=True,
        if_match='"collection-etag"',
    )

    _, _, headers, params = proxy.put_calls[0]
    assert headers == {"If-Match": '"collection-etag"'}
    assert params == {"dryRun": "true"}


def test_put_data_access_roles_translates_inactive_capacity() -> None:
    api, _ = _fabric_api()
    response = Mock()
    response.json.return_value = {
        "errorCode": "EntityNotFound",
        "moreDetails": [
            {
                "errorCode": "NotFound",
                "message": (
                    "Internal error CapacityNotActive.Capacity "
                    "d551fcf8-08c1-4fc1-ab74-b83e9875b7ca is not active"
                ),
            }
        ],
    }
    api.rest_api_proxy = SimpleNamespace(
        put=Mock(side_effect=HTTPError(response=response))
    )

    try:
        api.put_data_access_policy(
            "item-id", '{"value": []}', dry_run=True, if_match='"etag"'
        )
    except FabricCapacityNotActiveError as error:
        assert error.capacity_id == "d551fcf8-08c1-4fc1-ab74-b83e9875b7ca"
        assert error.workspace_id == "workspace-id"
        assert error.item_id == "item-id"
        assert "Resume the capacity" in str(error)
        assert "No roles were changed" in str(error)
    else:
        raise AssertionError("Inactive Fabric capacity was reported as a generic 404")


def test_put_data_access_roles_preserves_unrelated_404() -> None:
    api, _ = _fabric_api()
    response = Mock(status_code=404)
    response.json.return_value = {
        "errorCode": "EntityNotFound",
        "moreDetails": [{"message": "Item was not found"}],
    }
    original = HTTPError("404", response=response)
    api.rest_api_proxy = SimpleNamespace(put=Mock(side_effect=original))

    try:
        api.put_data_access_policy(
            "item-id", '{"value": []}', dry_run=True, if_match='"etag"'
        )
    except HTTPError as error:
        assert error is original
    else:
        raise AssertionError("Unrelated Fabric 404 was translated")


def test_put_data_access_roles_preserves_malformed_404() -> None:
    api, _ = _fabric_api()
    response = Mock(status_code=404)
    response.json.side_effect = ValueError("invalid JSON")
    original = HTTPError("404", response=response)
    api.rest_api_proxy = SimpleNamespace(put=Mock(side_effect=original))

    try:
        api.put_data_access_policy(
            "item-id", '{"value": []}', dry_run=True, if_match='"etag"'
        )
    except HTTPError as error:
        assert error is original
    else:
        raise AssertionError("Malformed Fabric 404 was translated")


def test_rest_proxy_put_merges_headers_uses_timeout_and_omits_payload_from_logs() -> (
    None
):
    proxy = RestAPIProxy(
        "https://api.fabric.microsoft.com/v1",
        headers={
            "Authorization": "Bearer secret-token",
            "Content-Type": "application/json",
        },
        weaver_type="DATAVERSE",
    )
    response = Mock(status_code=200)
    proxy.session.put = Mock(return_value=response)
    proxy.logger = Mock()

    proxy.put(
        "workspaces/w/items/i/dataAccessRoles",
        data='{"members":"sensitive-member"}',
        headers={"If-Match": '"etag"'},
        params={"dryRun": "true"},
    )

    call = proxy.session.put.call_args
    assert call.kwargs["timeout"] == proxy.timeout
    assert call.kwargs["headers"]["Authorization"] == "Bearer secret-token"
    assert call.kwargs["headers"]["If-Match"] == '"etag"'
    assert call.kwargs["params"] == {"dryRun": "true"}
    log_text = " ".join(str(call) for call in proxy.logger.debug.call_args_list)
    assert "secret-token" not in log_text
    assert "sensitive-member" not in log_text


def test_rest_proxy_retries_idempotent_fabric_operations() -> None:
    proxy = RestAPIProxy("https://api.fabric.microsoft.com/v1")
    adapter = proxy.session.get_adapter("https://")

    assert adapter.max_retries.total == 5
    assert adapter.max_retries.respect_retry_after_header
    assert {"GET", "PUT"}.issubset(adapter.max_retries.allowed_methods)
    assert 429 in adapter.max_retries.status_forcelist


def test_service_principal_reuses_unexpired_token() -> None:
    credential = Mock()
    credential.get_token.return_value = SimpleNamespace(
        token="cached-token", expires_on=int(time.time()) + 3600
    )
    ServicePrincipal._credential = credential
    ServicePrincipal._tokens = {}

    first = ServicePrincipal.get_token("scope")
    second = ServicePrincipal.get_token("scope")

    assert first == second == "cached-token"
    credential.get_token.assert_called_once_with("scope")


def test_rest_proxy_refreshes_auth_once_after_401() -> None:
    tokens = iter(["stale-token", "fresh-token"])
    provider_calls = []

    def auth_provider(force_refresh: bool = False) -> dict:
        provider_calls.append(force_refresh)
        return {"Authorization": f"Bearer {next(tokens)}"}

    proxy = RestAPIProxy(
        "https://api.fabric.microsoft.com/v1",
        auth_header_provider=auth_provider,
    )
    unauthorized = Mock(status_code=401)
    success = Mock(status_code=200)
    proxy.session.get = Mock(side_effect=[unauthorized, success])

    proxy.get("workspaces/w")

    assert provider_calls == [False, True]
    assert (
        proxy.session.get.call_args_list[1].kwargs["headers"]["Authorization"]
        == "Bearer fresh-token"
    )


def test_fabric_auth_provider_binds_force_refresh_by_keyword() -> None:
    with patch.object(ServicePrincipal, "get_token", return_value="token") as get_token:
        api = FabricAPI("workspace-id")

        headers = api.rest_api_proxy._build_headers(force_refresh=True)

    assert headers["Authorization"] == "Bearer token"
    get_token.assert_called_once_with("https://api.fabric.microsoft.com/.default", True)


class _ReconciliationFabricAPI:
    def __init__(self, roles: list[dict]) -> None:
        self.roles = roles
        self.workspace_id = "workspace-id"
        self.data_access_roles_etag = '"collection-etag"'
        self.put_calls = []
        self.list_calls = 0

    def put_data_access_policy(
        self,
        item_id: str,
        access_policy: str,
        dry_run: bool = False,
        if_match: str | None = None,
    ) -> _FakeResponse:
        self.put_calls.append((item_id, access_policy, dry_run, if_match))
        if not dry_run:
            self.roles = json.loads(access_policy)["value"]
        return _FakeResponse({}, {"ETag": '"new-etag"'})

    def list_data_access_policy(self, item_id: str) -> dict:
        self.list_calls += 1
        return {"value": self.roles}


class _AmbiguousReconciliationFabricAPI(_ReconciliationFabricAPI):
    def put_data_access_policy(
        self,
        item_id: str,
        access_policy: str,
        dry_run: bool = False,
        if_match: str | None = None,
    ) -> _FakeResponse:
        response = super().put_data_access_policy(
            item_id, access_policy, dry_run=dry_run, if_match=if_match
        )
        if not dry_run:
            raise HTTPError("response lost after apply")
        return response


class _ServerAssignedIdFabricAPI(_ReconciliationFabricAPI):
    def put_data_access_policy(
        self,
        item_id: str,
        access_policy: str,
        dry_run: bool = False,
        if_match: str | None = None,
    ) -> _FakeResponse:
        self.put_calls.append((item_id, access_policy, dry_run, if_match))
        if not dry_run:
            self.roles = json.loads(access_policy)["value"]
            for index, role in enumerate(self.roles, start=1):
                role["id"] = f"server-role-{index}"
        return _FakeResponse({}, {"ETag": '"new-etag"'})


class _ObjectTypeOmittingFabricAPI(_ReconciliationFabricAPI):
    def __init__(self, roles: list[dict], *, replace_member_id: str | None = None):
        super().__init__(roles)
        self.replace_member_id = replace_member_id

    def put_data_access_policy(
        self,
        item_id: str,
        access_policy: str,
        dry_run: bool = False,
        if_match: str | None = None,
    ) -> _FakeResponse:
        response = super().put_data_access_policy(
            item_id, access_policy, dry_run=dry_run, if_match=if_match
        )
        if not dry_run:
            for role in self.roles:
                for member in role["members"]["microsoftEntraMembers"]:
                    member.pop("objectType", None)
                    if self.replace_member_id:
                        member["objectId"] = self.replace_member_id
        return response


class _TimeoutObjectTypeOmittingFabricAPI(_ObjectTypeOmittingFabricAPI):
    def __init__(self, roles: list[dict], *, replace_member_id: str | None = None):
        super().__init__(roles, replace_member_id=replace_member_id)
        self.error = Timeout("response lost after apply")

    def put_data_access_policy(
        self,
        item_id: str,
        access_policy: str,
        dry_run: bool = False,
        if_match: str | None = None,
    ) -> _FakeResponse:
        response = super().put_data_access_policy(
            item_id, access_policy, dry_run=dry_run, if_match=if_match
        )
        if not dry_run:
            raise self.error
        return response


class _TimeoutReconciliationFabricAPI(_ReconciliationFabricAPI):
    def put_data_access_policy(
        self,
        item_id: str,
        access_policy: str,
        dry_run: bool = False,
        if_match: str | None = None,
    ) -> _FakeResponse:
        response = super().put_data_access_policy(
            item_id, access_policy, dry_run=dry_run, if_match=if_match
        )
        if not dry_run:
            raise Timeout("response lost after apply")
        return response


class _CapacityFailureReconciliationFabricAPI(_ReconciliationFabricAPI):
    def __init__(
        self,
        roles: list[dict],
        *,
        fail_dry_run: bool = False,
        commit_before_error: bool = False,
    ) -> None:
        super().__init__(roles)
        self.fail_dry_run = fail_dry_run
        self.commit_before_error = commit_before_error
        self.error = FabricCapacityNotActiveError(
            "capacity-id", "workspace-id", "item-id"
        )

    def put_data_access_policy(
        self,
        item_id: str,
        access_policy: str,
        dry_run: bool = False,
        if_match: str | None = None,
    ) -> _FakeResponse:
        self.put_calls.append((item_id, access_policy, dry_run, if_match))
        if dry_run:
            if self.fail_dry_run:
                raise self.error
            return _FakeResponse({}, {"ETag": '"new-etag"'})
        if self.commit_before_error:
            self.roles = json.loads(access_policy)["value"]
        raise self.error


class _MutatingDryRunFabricAPI(_ReconciliationFabricAPI):
    def __init__(self, roles: list[dict], export: RolePolicyExport) -> None:
        super().__init__(roles)
        self.export = export

    def put_data_access_policy(
        self,
        item_id: str,
        access_policy: str,
        dry_run: bool = False,
        if_match: str | None = None,
    ) -> _FakeResponse:
        response = super().put_data_access_policy(
            item_id, access_policy, dry_run=dry_run, if_match=if_match
        )
        if dry_run:
            self.export.policies.append(
                RolePolicy(name="InjectedAfterDryRun", permissionscopes=[])
            )
        return response


class _MutatingConfigDryRunFabricAPI(_ReconciliationFabricAPI):
    def __init__(self, roles: list[dict], config: DataverseSourceMap) -> None:
        super().__init__(roles)
        self.config = config

    def put_data_access_policy(
        self,
        item_id: str,
        access_policy: str,
        dry_run: bool = False,
        if_match: str | None = None,
    ) -> _FakeResponse:
        response = super().put_data_access_policy(
            item_id, access_policy, dry_run=dry_run, if_match=if_match
        )
        if dry_run:
            self.config.fabric.mirror_id = "mutated-item-id"
        return response


def _data_access_policy(name: str, member_id: str) -> DataAccessPolicy:
    return DataAccessPolicy(
        name=name,
        decision_rules=[],
        members=PolicyMembers(
            entra_members=[
                {
                    "objectId": member_id,
                    "objectType": "User",
                    "tenantId": "tenant-id",
                }
            ]
        ),
    )


def _reconciliation_weaver(
    current: DataAccessPolicy,
) -> tuple[WeaverAgent, _ReconciliationFabricAPI]:
    weaver = WeaverAgent.__new__(WeaverAgent)
    weaver.config = SimpleNamespace(
        type=PolicyWeaverConnectorType.SNOWFLAKE,
        fabric=SimpleNamespace(
            mirror_id="item-id",
            fabric_role_suffix="PWPolicy",
            delete_default_reader_role=True,
        ),
        dataverse=SimpleNamespace(onelake_role_limit=1000),
    )
    weaver.logger = Mock()
    weaver.current_fabric_policies = [current]
    weaver.used_role_names = []
    weaver._fabric_snapshot_handler = None
    fabric_api = _ReconciliationFabricAPI(
        [current.model_dump(exclude_none=True, exclude_unset=True)]
    )
    weaver.fabric_api = fabric_api
    return weaver, fabric_api


def _strict_reconciliation_config() -> DataverseSourceMap:
    return DataverseSourceMap(
        type=PolicyWeaverConnectorType.DATAVERSE,
        source=Source(name="Dataverse"),
        fabric=FabricConfig(
            tenant_id="tenant-id",
            workspace_id="workspace-id",
            mirror_id="item-id",
            fabric_role_suffix="PWPolicy",
            delete_default_reader_role=True,
            policy_mapping="role_based",
        ),
        dataverse=DataverseSourceConfig(
            environment_url="https://example.crm.dynamics.com",
            strict_access_parity=True,
            poa_read_access_status="verified_empty",
        ),
    )


def test_role_reconciliation_skips_identical_payload() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, fabric_api = _reconciliation_weaver(current)

    async def build_policy(policy, access_type):
        return _data_access_policy("ReaderPWPolicy", "member-1")

    weaver.__build_data_access_role_policy__ = build_policy
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])

    asyncio.run(weaver.__apply_role_policies__(export))

    assert fabric_api.put_calls == []


def test_role_reconciliation_skips_put_when_fabric_omits_member_object_type() -> None:
    current_payload = _data_access_policy("ReaderPWPolicy", "member-1").model_dump(
        exclude_none=True, exclude_unset=True
    )
    current_payload["members"]["microsoftEntraMembers"][0].pop("objectType")
    current = DataAccessPolicy.model_validate(current_payload)
    weaver, fabric_api = _reconciliation_weaver(current)

    async def build_policy(policy, access_type):
        return _data_access_policy("ReaderPWPolicy", "member-1")

    weaver.__build_data_access_role_policy__ = build_policy
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])

    asyncio.run(weaver.__apply_role_policies__(export))

    assert (
        "objectType" not in fabric_api.roles[0]["members"]["microsoftEntraMembers"][0]
    )
    assert fabric_api.put_calls == []


def test_role_reconciliation_dry_runs_applies_and_verifies_change() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, fabric_api = _reconciliation_weaver(current)

    async def build_policy(policy, access_type):
        return _data_access_policy("ReaderPWPolicy", "member-2")

    weaver.__build_data_access_role_policy__ = build_policy
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])

    asyncio.run(weaver.__apply_role_policies__(export))

    assert [call[2] for call in fabric_api.put_calls] == [True, False]
    assert all(call[3] == '"collection-etag"' for call in fabric_api.put_calls)


def test_role_reconciliation_accepts_fabric_omitted_member_object_type() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, _ = _reconciliation_weaver(current)
    fabric_api = _ObjectTypeOmittingFabricAPI(
        [current.model_dump(exclude_none=True, exclude_unset=True)]
    )
    weaver.fabric_api = fabric_api

    async def build_policy(policy, access_type):
        return _data_access_policy("ReaderPWPolicy", "member-2")

    weaver.__build_data_access_role_policy__ = build_policy
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])

    asyncio.run(weaver.__apply_role_policies__(export))

    assert [call[2] for call in fabric_api.put_calls] == [True, False]
    assert (
        "objectType" not in fabric_api.roles[0]["members"]["microsoftEntraMembers"][0]
    )


def test_role_reconciliation_rejects_changed_member_when_object_type_omitted() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, _ = _reconciliation_weaver(current)
    fabric_api = _ObjectTypeOmittingFabricAPI(
        [current.model_dump(exclude_none=True, exclude_unset=True)],
        replace_member_id="different-member",
    )
    weaver.fabric_api = fabric_api

    async def build_policy(policy, access_type):
        return _data_access_policy("ReaderPWPolicy", "member-2")

    weaver.__build_data_access_role_policy__ = build_policy
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])

    try:
        asyncio.run(weaver.__apply_role_policies__(export))
    except PolicyWeaverError as error:
        assert "verification did not match" in str(error)
    else:
        raise AssertionError("Changed member ID passed semantic verification")


def test_role_reconciliation_dry_run_only_never_applies_change() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, fabric_api = _reconciliation_weaver(current)

    async def build_policy(policy, access_type):
        return _data_access_policy("ReaderPWPolicy", "member-2")

    weaver.__build_data_access_role_policy__ = build_policy
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])

    asyncio.run(weaver.__apply_role_policies__(export, dry_run_only=True))

    assert [call[2] for call in fabric_api.put_calls] == [True]
    assert (
        fabric_api.roles[0]["members"]["microsoftEntraMembers"][0]["objectId"]
        == "member-1"
    )


def test_role_reconciliation_verifies_ambiguous_apply_before_succeeding() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, _ = _reconciliation_weaver(current)
    fabric_api = _AmbiguousReconciliationFabricAPI(
        [current.model_dump(exclude_none=True, exclude_unset=True)]
    )
    weaver.fabric_api = fabric_api

    async def build_policy(policy, access_type):
        return _data_access_policy("ReaderPWPolicy", "member-2")

    weaver.__build_data_access_role_policy__ = build_policy
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])

    asyncio.run(weaver.__apply_role_policies__(export))

    assert len(fabric_api.put_calls) == 2
    assert (
        fabric_api.roles[0]["members"]["microsoftEntraMembers"][0]["objectId"]
        == "member-2"
    )


def test_role_reconciliation_verifies_timeout_after_apply() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, _ = _reconciliation_weaver(current)
    fabric_api = _TimeoutReconciliationFabricAPI(
        [current.model_dump(exclude_none=True, exclude_unset=True)]
    )
    weaver.fabric_api = fabric_api

    async def build_policy(policy, access_type):
        return _data_access_policy("ReaderPWPolicy", "member-2")

    weaver.__build_data_access_role_policy__ = build_policy
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])

    asyncio.run(weaver.__apply_role_policies__(export))

    assert len(fabric_api.put_calls) == 2
    assert fabric_api.list_calls == 1


def test_role_reconciliation_verifies_capacity_error_after_apply() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, _ = _reconciliation_weaver(current)
    fabric_api = _CapacityFailureReconciliationFabricAPI(
        [current.model_dump(exclude_none=True, exclude_unset=True)],
        commit_before_error=True,
    )
    weaver.fabric_api = fabric_api

    async def build_policy(policy, access_type):
        return _data_access_policy("ReaderPWPolicy", "member-2")

    weaver.__build_data_access_role_policy__ = build_policy
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])

    asyncio.run(weaver.__apply_role_policies__(export))

    assert len(fabric_api.put_calls) == 2
    assert fabric_api.list_calls == 1


def test_role_reconciliation_reraises_capacity_error_when_readback_mismatches() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, _ = _reconciliation_weaver(current)
    fabric_api = _CapacityFailureReconciliationFabricAPI(
        [current.model_dump(exclude_none=True, exclude_unset=True)]
    )
    weaver.fabric_api = fabric_api

    async def build_policy(policy, access_type):
        return _data_access_policy("ReaderPWPolicy", "member-2")

    weaver.__build_data_access_role_policy__ = build_policy
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])

    try:
        asyncio.run(weaver.__apply_role_policies__(export))
    except FabricCapacityNotActiveError as error:
        assert error is fabric_api.error
    else:
        raise AssertionError("Mismatched readback swallowed the capacity error")

    assert len(fabric_api.put_calls) == 2
    assert fabric_api.list_calls == 1


def test_role_reconciliation_does_not_verify_capacity_error_from_dry_run() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, _ = _reconciliation_weaver(current)
    fabric_api = _CapacityFailureReconciliationFabricAPI(
        [current.model_dump(exclude_none=True, exclude_unset=True)],
        fail_dry_run=True,
    )
    weaver.fabric_api = fabric_api

    async def build_policy(policy, access_type):
        return _data_access_policy("ReaderPWPolicy", "member-2")

    weaver.__build_data_access_role_policy__ = build_policy
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])

    try:
        asyncio.run(weaver.__apply_role_policies__(export))
    except FabricCapacityNotActiveError as error:
        assert error is fabric_api.error
    else:
        raise AssertionError("Dry-run capacity failure was swallowed")

    assert [call[2] for call in fabric_api.put_calls] == [True]
    assert fabric_api.list_calls == 0


def test_rollback_verifies_timeout_after_apply(tmp_path: Path) -> None:
    original = _data_access_policy("OriginalPWPolicy", "member-1")
    replacement = _data_access_policy("ReplacementPWPolicy", "member-2")
    fabric_api = _TimeoutReconciliationFabricAPI(
        [replacement.model_dump(exclude_none=True, exclude_unset=True)]
    )
    config = _strict_reconciliation_config()
    snapshot_path = tmp_path / "rollback.json"
    output_path = tmp_path / "rollback-result.json"
    snapshot_path.write_text(
        json.dumps(
            {
                "workspace_id": "workspace-id",
                "item_id": "item-id",
                "value": [original.model_dump(exclude_none=True, exclude_unset=True)],
            }
        ),
        encoding="utf-8",
    )

    with patch("scripts.dataverse_policy_sync.FabricAPI", return_value=fabric_api):
        report = restore_snapshot(config, snapshot_path, output_path)

    assert report["status"] == "restored-and-verified"
    assert [call[2] for call in fabric_api.put_calls] == [True, False]
    assert output_path.exists()


def test_rollback_accepts_omitted_member_object_type_after_timeout(
    tmp_path: Path,
) -> None:
    original = _data_access_policy("OriginalPWPolicy", "member-1")
    replacement = _data_access_policy("ReplacementPWPolicy", "member-2")
    fabric_api = _TimeoutObjectTypeOmittingFabricAPI(
        [replacement.model_dump(exclude_none=True, exclude_unset=True)]
    )
    config = _strict_reconciliation_config()
    snapshot_path = tmp_path / "rollback.json"
    output_path = tmp_path / "rollback-result.json"
    snapshot_path.write_text(
        json.dumps(
            {
                "workspace_id": "workspace-id",
                "item_id": "item-id",
                "value": [original.model_dump(exclude_none=True, exclude_unset=True)],
            }
        ),
        encoding="utf-8",
    )

    with patch("scripts.dataverse_policy_sync.FabricAPI", return_value=fabric_api):
        report = restore_snapshot(config, snapshot_path, output_path)

    assert report["status"] == "restored-and-verified"
    assert (
        "objectType" not in fabric_api.roles[0]["members"]["microsoftEntraMembers"][0]
    )


def test_rollback_reraises_timeout_when_member_id_changes_and_object_type_omitted(
    tmp_path: Path,
) -> None:
    original = _data_access_policy("OriginalPWPolicy", "member-1")
    replacement = _data_access_policy("ReplacementPWPolicy", "member-2")
    fabric_api = _TimeoutObjectTypeOmittingFabricAPI(
        [replacement.model_dump(exclude_none=True, exclude_unset=True)],
        replace_member_id="different-member",
    )
    config = _strict_reconciliation_config()
    snapshot_path = tmp_path / "rollback.json"
    output_path = tmp_path / "rollback-result.json"
    snapshot_path.write_text(
        json.dumps(
            {
                "workspace_id": "workspace-id",
                "item_id": "item-id",
                "value": [original.model_dump(exclude_none=True, exclude_unset=True)],
            }
        ),
        encoding="utf-8",
    )

    with patch("scripts.dataverse_policy_sync.FabricAPI", return_value=fabric_api):
        try:
            restore_snapshot(config, snapshot_path, output_path)
        except Timeout as error:
            assert error is fabric_api.error
        else:
            raise AssertionError("Changed member ID swallowed the rollback timeout")

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["status"] == "failed"
    assert report["fabric_operation_stage"] == "rollback-apply"


def test_rollback_verifies_capacity_error_after_apply(tmp_path: Path) -> None:
    original = _data_access_policy("OriginalPWPolicy", "member-1")
    replacement = _data_access_policy("ReplacementPWPolicy", "member-2")
    fabric_api = _CapacityFailureReconciliationFabricAPI(
        [replacement.model_dump(exclude_none=True, exclude_unset=True)],
        commit_before_error=True,
    )
    config = _strict_reconciliation_config()
    snapshot_path = tmp_path / "rollback.json"
    output_path = tmp_path / "rollback-result.json"
    snapshot_path.write_text(
        json.dumps(
            {
                "workspace_id": "workspace-id",
                "item_id": "item-id",
                "value": [original.model_dump(exclude_none=True, exclude_unset=True)],
            }
        ),
        encoding="utf-8",
    )

    with patch("scripts.dataverse_policy_sync.FabricAPI", return_value=fabric_api):
        report = restore_snapshot(config, snapshot_path, output_path)

    assert report["status"] == "restored-and-verified"
    assert report["fabric_operation_stage"] == "rollback-verification"
    assert report["fabric_operation_status"] == "completed"


def test_rollback_reraises_capacity_error_when_readback_mismatches(
    tmp_path: Path,
) -> None:
    original = _data_access_policy("OriginalPWPolicy", "member-1")
    replacement = _data_access_policy("ReplacementPWPolicy", "member-2")
    fabric_api = _CapacityFailureReconciliationFabricAPI(
        [replacement.model_dump(exclude_none=True, exclude_unset=True)]
    )
    config = _strict_reconciliation_config()
    snapshot_path = tmp_path / "rollback.json"
    output_path = tmp_path / "rollback-result.json"
    snapshot_path.write_text(
        json.dumps(
            {
                "workspace_id": "workspace-id",
                "item_id": "item-id",
                "value": [original.model_dump(exclude_none=True, exclude_unset=True)],
            }
        ),
        encoding="utf-8",
    )

    with patch("scripts.dataverse_policy_sync.FabricAPI", return_value=fabric_api):
        try:
            restore_snapshot(config, snapshot_path, output_path)
        except FabricCapacityNotActiveError as error:
            assert error is fabric_api.error
        else:
            raise AssertionError(
                "Mismatched rollback readback swallowed capacity error"
            )

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["status"] == "failed"
    assert report["fabric_operation_stage"] == "rollback-apply"
    assert report["fabric_operation_status"] == "blocked-capacity-not-active"


def test_role_reconciliation_ignores_server_ids_and_list_order() -> None:
    current = DataAccessPolicy(
        id="server-role-id",
        name="ReaderPWPolicy",
        decision_rules=[],
        members=PolicyMembers(
            entra_members=[
                {
                    "objectId": "member-2",
                    "objectType": "User",
                    "tenantId": "tenant-id",
                },
                {
                    "objectId": "member-1",
                    "objectType": "User",
                    "tenantId": "tenant-id",
                },
            ]
        ),
    )
    weaver, fabric_api = _reconciliation_weaver(current)

    async def build_policy(policy, access_type):
        return DataAccessPolicy(
            name="ReaderPWPolicy",
            decision_rules=[],
            members=PolicyMembers(
                entra_members=[
                    {
                        "objectId": "member-1",
                        "objectType": "User",
                        "tenantId": "tenant-id",
                    },
                    {
                        "objectId": "member-2",
                        "objectType": "User",
                        "tenantId": "tenant-id",
                    },
                ]
            ),
        )

    weaver.__build_data_access_role_policy__ = build_policy
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])

    asyncio.run(weaver.__apply_role_policies__(export))

    assert fabric_api.put_calls == []


def test_role_reconciliation_verifies_new_server_assigned_role_id() -> None:
    current = _data_access_policy("OldPWPolicy", "member-1")
    weaver, _ = _reconciliation_weaver(current)
    fabric_api = _ServerAssignedIdFabricAPI(
        [current.model_dump(exclude_none=True, exclude_unset=True)]
    )
    weaver.fabric_api = fabric_api

    async def build_policy(policy, access_type):
        return _data_access_policy("NewPWPolicy", "member-2")

    weaver.__build_data_access_role_policy__ = build_policy
    export = RolePolicyExport(policies=[RolePolicy(name="New", permissionscopes=[])])

    asyncio.run(weaver.__apply_role_policies__(export))

    assert [call[2] for call in fabric_api.put_calls] == [True, False]
    assert fabric_api.roles[0]["id"] == "server-role-1"


def test_empty_dataverse_environment_returns_authoritative_empty_export() -> None:
    config = DataverseSourceMap(
        source=Source(name="Dataverse"),
        fabric=FabricConfig(policy_mapping="role_based"),
        dataverse=DataverseSourceConfig(
            environment_url="https://example.crm.dynamics.com",
            strict_access_parity=False,
        ),
    )
    client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
    client.config = config
    client.environment = DataverseEnvironment()
    client.logger = Mock()

    export = client.__build_role_based_export__()

    assert export is not None
    assert export.policies == []


def test_map_policy_preserves_authoritative_empty_dataverse_result() -> None:
    config = DataverseSourceMap(
        source=Source(name="Dataverse"),
        fabric=FabricConfig(policy_mapping="role_based"),
        dataverse=DataverseSourceConfig(
            environment_url="https://example.crm.dynamics.com",
            strict_access_parity=False,
        ),
    )
    client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
    client.config = config
    client.logger = Mock()
    client.api_client = SimpleNamespace(
        get_environment_security_map=lambda source: DataverseEnvironment()
    )

    export = client.map_policy("role_based")

    assert export is not None
    assert export.policies == []


def test_apply_role_rejects_non_strict_dataverse_before_fabric_call() -> None:
    weaver = WeaverAgent.__new__(WeaverAgent)
    weaver.config = SimpleNamespace(
        type=PolicyWeaverConnectorType.DATAVERSE,
        dataverse=SimpleNamespace(strict_access_parity=False),
        fabric=SimpleNamespace(),
    )
    weaver.fabric_api = Mock()
    export = RolePolicyExport(policies=[])

    try:
        asyncio.run(weaver.apply_role(export))
    except PolicyWeaverError as error:
        assert "strict_access_parity" in str(error)
    else:
        raise AssertionError("Non-strict Dataverse export reached Fabric apply")

    assert weaver.fabric_api.mock_calls == []


def test_table_based_apply_rejects_dataverse_before_fabric_call() -> None:
    weaver = WeaverAgent.__new__(WeaverAgent)
    weaver.config = SimpleNamespace(
        type=PolicyWeaverConnectorType.DATAVERSE,
        fabric=SimpleNamespace(),
    )
    weaver.fabric_api = Mock()

    try:
        asyncio.run(weaver.apply(PolicyExport(policies=[])))
    except PolicyWeaverError as error:
        assert "role_based" in str(error)
    else:
        raise AssertionError("Dataverse table-based payload reached Fabric")

    assert weaver.fabric_api.mock_calls == []


def test_apply_role_rejects_empty_partial_export_before_fabric_call() -> None:
    weaver = WeaverAgent.__new__(WeaverAgent)
    weaver.config = SimpleNamespace(
        type=PolicyWeaverConnectorType.DATAVERSE,
        dataverse=SimpleNamespace(
            strict_access_parity=False,
            partial_sync=True,
        ),
        fabric=SimpleNamespace(),
    )
    weaver.fabric_api = Mock()

    try:
        asyncio.run(weaver.apply_role(RolePolicyExport(policies=[])))
    except PolicyWeaverError as error:
        assert "no valid policies" in str(error)
    else:
        raise AssertionError("Empty partial export reached Fabric")

    assert weaver.fabric_api.mock_calls == []


def test_partial_apply_requires_prepared_before_image() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, fabric_api = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()
    weaver.config.fabric.workspace_name = "Workspace"
    weaver.config.fabric.mirror_name = "Mirror"
    weaver.config.dataverse.strict_access_parity = False
    weaver.config.dataverse.partial_sync = True
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])
    _mark_strict_dataverse_export_validated(export, weaver.config)

    try:
        asyncio.run(weaver.apply_role(export, dry_run_only=False))
    except PolicyWeaverError as error:
        assert "prepare_role_apply" in str(error)
    else:
        raise AssertionError("Unprepared partial apply reached Fabric")

    assert fabric_api.put_calls == []


def test_prepared_apply_reuses_exact_before_image_and_etag() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, fabric_api = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()
    weaver.config.fabric.workspace_name = "Workspace"
    weaver.config.fabric.mirror_name = "Mirror"
    weaver.config.dataverse.strict_access_parity = False
    weaver.config.dataverse.partial_sync = True
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])
    _mark_strict_dataverse_export_validated(export, weaver.config)

    async def build_policy(policy, access_type):
        return _data_access_policy("ReaderPWPolicy", "member-2")

    weaver.__build_data_access_role_policy__ = build_policy

    snapshots = []
    before_image, etag = weaver.prepare_role_apply(
        "item-id",
        rollback_snapshot_handler=lambda roles, snapshot_etag: snapshots.append(
            (roles, snapshot_etag)
        ),
        partial_sync_acknowledged=True,
    )
    asyncio.run(
        weaver.apply_role(
            export,
            dry_run_only=False,
            partial_sync_acknowledged=True,
        )
    )

    assert before_image[0]["name"] == "ReaderPWPolicy"
    assert etag == '"collection-etag"'
    assert snapshots == [(before_image, etag)]
    assert fabric_api.list_calls == 2
    assert [call[2] for call in fabric_api.put_calls] == [True, False]
    assert all(call[3] == etag for call in fabric_api.put_calls)


def test_prepared_apply_binds_connector_mode_workspace_item_and_acknowledgement() -> (
    None
):
    def mutate_mode(config: DataverseSourceMap) -> None:
        config.dataverse.strict_access_parity = False
        config.dataverse.partial_sync = True

    cases = [
        (
            "connector",
            lambda config: setattr(
                config, "type", PolicyWeaverConnectorType.UNITY_CATALOG
            ),
            False,
        ),
        (
            "mode",
            mutate_mode,
            True,
        ),
        (
            "workspace",
            lambda config: setattr(config.fabric, "workspace_id", "other-workspace"),
            False,
        ),
        (
            "item",
            lambda config: setattr(config.fabric, "mirror_id", "other-item"),
            False,
        ),
        (
            "acknowledgement",
            lambda config: None,
            True,
        ),
    ]

    for name, mutate, apply_acknowledgement in cases:
        current = _data_access_policy("ReaderPWPolicy", "member-1")
        weaver, fabric_api = _reconciliation_weaver(current)
        weaver.config = _strict_reconciliation_config()
        export = RolePolicyExport(
            policies=[RolePolicy(name="Reader", permissionscopes=[])]
        )
        _mark_strict_dataverse_export_validated(export, weaver.config)
        weaver.prepare_role_apply("item-id", rollback_snapshot_handler=lambda *_: None)
        mutate(weaver.config)

        try:
            asyncio.run(
                weaver.apply_role(
                    export,
                    partial_sync_acknowledged=apply_acknowledgement,
                )
            )
        except PolicyWeaverError as error:
            assert "context" in str(error), name
        else:
            raise AssertionError(f"Prepared apply ignored mutated {name}")

        assert fabric_api.put_calls == [], name
        assert weaver._prepared_role_context is None, name


def test_prepare_role_apply_rejects_mismatched_fabric_client_workspace() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, fabric_api = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()
    fabric_api.workspace_id = "other-workspace"

    try:
        weaver.prepare_role_apply("item-id", rollback_snapshot_handler=lambda *_: None)
    except PolicyWeaverError as error:
        assert "client workspace" in str(error)
    else:
        raise AssertionError("Preparation read roles from a mismatched workspace")

    assert fabric_api.list_calls == 0


def test_prepared_apply_rechecks_context_after_dry_run() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, _ = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()
    weaver.config.fabric.workspace_name = "Workspace"
    weaver.config.fabric.mirror_name = "Mirror"
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])
    _mark_strict_dataverse_export_validated(export, weaver.config)
    fabric_api = _MutatingConfigDryRunFabricAPI(
        [current.model_dump(exclude_none=True, exclude_unset=True)], weaver.config
    )
    weaver.fabric_api = fabric_api

    async def build_policy(policy, access_type):
        return _data_access_policy("ReaderPWPolicy", "member-2")

    weaver.__build_data_access_role_policy__ = build_policy
    weaver.prepare_role_apply("item-id", rollback_snapshot_handler=lambda *_: None)

    try:
        asyncio.run(weaver.apply_role(export))
    except PolicyWeaverError as error:
        assert "context" in str(error)
    else:
        raise AssertionError("Mutated target reached authoritative Fabric PUT")

    assert [call[2] for call in fabric_api.put_calls] == [True]


def test_prepared_apply_rejects_changed_etag_and_consumes_context() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, fabric_api = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])
    _mark_strict_dataverse_export_validated(export, weaver.config)
    weaver.prepare_role_apply("item-id", rollback_snapshot_handler=lambda *_: None)
    fabric_api.data_access_roles_etag = '"changed-etag"'

    try:
        asyncio.run(weaver.apply_role(export))
    except PolicyWeaverError as error:
        assert "ETag changed" in str(error)
    else:
        raise AssertionError("Changed collection ETag reached Fabric apply")

    assert fabric_api.put_calls == []
    assert weaver._prepared_role_context is None


def test_prepare_role_apply_preserves_sanitized_raw_before_image() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, fabric_api = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()
    raw_role = current.model_dump(exclude_none=True, exclude_unset=True)
    raw_role["kind"] = "CustomRoleKind"
    raw_role["readOnlyServerField"] = "not-put-relevant"
    fabric_api.roles = [raw_role]
    snapshots = []

    before_image, _ = weaver.prepare_role_apply(
        "item-id",
        rollback_snapshot_handler=lambda roles, etag: snapshots.append(roles),
    )

    assert before_image[0]["kind"] == "CustomRoleKind"
    assert snapshots[0][0]["kind"] == "CustomRoleKind"
    assert "readOnlyServerField" not in before_image[0]


def test_role_target_write_readiness_dry_runs_sanitized_current_roles() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, fabric_api = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()
    raw_role = current.model_dump(exclude_none=True, exclude_unset=True)
    raw_role["kind"] = "CustomRoleKind"
    raw_role["readOnlyServerField"] = "not-put-relevant"
    fabric_api.roles = [raw_role]

    weaver.validate_role_target_write_ready()

    assert fabric_api.list_calls == 1
    assert len(fabric_api.put_calls) == 1
    item_id, payload, dry_run, etag = fabric_api.put_calls[0]
    replayed_role = json.loads(payload)["value"][0]
    assert item_id == "item-id"
    assert dry_run is True
    assert etag == '"collection-etag"'
    assert replayed_role["kind"] == "CustomRoleKind"
    assert "readOnlyServerField" not in replayed_role


def test_prepare_role_apply_rejects_malformed_raw_before_image() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, fabric_api = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()
    fabric_api.roles = [None]
    snapshot_handler = Mock()

    try:
        weaver.prepare_role_apply("item-id", rollback_snapshot_handler=snapshot_handler)
    except PolicyWeaverError as error:
        assert "malformed" in str(error)
    else:
        raise AssertionError("Malformed raw role collection armed an apply")

    snapshot_handler.assert_not_called()
    assert weaver._prepared_role_context is None


def test_failed_snapshot_handler_does_not_arm_apply() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, fabric_api = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()
    weaver.config.fabric.workspace_name = "Workspace"
    weaver.config.fabric.mirror_name = "Mirror"
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])
    _mark_strict_dataverse_export_validated(export, weaver.config)

    def fail_snapshot(roles: list[dict], etag: str) -> None:
        raise OSError("snapshot disk unavailable")

    try:
        weaver.prepare_role_apply("item-id", rollback_snapshot_handler=fail_snapshot)
    except OSError as error:
        assert "snapshot disk unavailable" in str(error)
    else:
        raise AssertionError("Failed rollback snapshot armed an apply")

    try:
        asyncio.run(weaver.apply_role(export, dry_run_only=False))
    except PolicyWeaverError as error:
        assert "prepare_role_apply" in str(error)
    else:
        raise AssertionError("Apply proceeded without a persisted rollback snapshot")

    assert fabric_api.put_calls == []


def test_internal_dataverse_apply_requires_prepared_context() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, fabric_api = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])
    _mark_strict_dataverse_export_validated(export, weaver.config)

    async def build_policy(policy, access_type):
        return _data_access_policy("ReaderPWPolicy", "member-2")

    weaver.__build_data_access_role_policy__ = build_policy

    try:
        asyncio.run(weaver.__apply_role_policies__(export))
    except PolicyWeaverError as error:
        assert "prepare_role_apply" in str(error)
    else:
        raise AssertionError("Internal Dataverse apply bypassed preparation")

    assert fabric_api.put_calls == []


def test_generic_run_rejects_partial_dataverse_publication() -> None:
    config = _strict_reconciliation_config()
    config.dataverse.strict_access_parity = False
    config.dataverse.partial_sync = True

    try:
        asyncio.run(WeaverAgent.run(config))
    except PolicyWeaverError as error:
        assert "dataverse_policy_sync.py" in str(error)
    else:
        raise AssertionError("Generic run published partial Dataverse policies")


def test_partial_conversion_rejects_empty_fabric_payload() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, fabric_api = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()
    weaver.config.dataverse.strict_access_parity = False
    weaver.config.dataverse.partial_sync = True
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])

    async def build_policy(policy, access_type):
        return None

    weaver.__build_data_access_role_policy__ = build_policy

    try:
        asyncio.run(weaver.__apply_role_policies__(export, dry_run_only=True))
    except PolicyWeaverError as error:
        assert "no publishable" in str(error)
    else:
        raise AssertionError("Empty converted payload reached Fabric")

    assert fabric_api.put_calls == []


def test_apply_role_rejects_unvalidated_strict_dataverse_export() -> None:
    weaver = WeaverAgent.__new__(WeaverAgent)
    weaver.config = SimpleNamespace(
        type=PolicyWeaverConnectorType.DATAVERSE,
        dataverse=SimpleNamespace(strict_access_parity=True),
        fabric=SimpleNamespace(),
    )
    weaver.fabric_api = Mock()

    try:
        asyncio.run(weaver.apply_role(RolePolicyExport(policies=[])))
    except PolicyWeaverError as error:
        assert "strict source validation" in str(error)
    else:
        raise AssertionError("Unvalidated strict Dataverse export reached Fabric")

    assert weaver.fabric_api.mock_calls == []


def test_strict_provenance_is_rechecked_before_dry_run() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, fabric_api = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])
    _mark_strict_dataverse_export_validated(export, weaver.config)

    async def build_policy(policy, access_type):
        export.policies.append(RolePolicy(name="Injected", permissionscopes=[]))
        return _data_access_policy("ReaderPWPolicy", "member-2")

    weaver.__build_data_access_role_policy__ = build_policy

    try:
        asyncio.run(weaver.__apply_role_policies__(export, dry_run_only=True))
    except PolicyWeaverError as error:
        assert "unchanged export" in str(error)
    else:
        raise AssertionError("Mutated strict export reached Fabric dry-run")

    assert fabric_api.put_calls == []


def test_strict_provenance_is_rechecked_after_dry_run() -> None:
    current = _data_access_policy("ReaderPWPolicy", "member-1")
    weaver, _ = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()
    weaver.config.fabric.workspace_name = "Workspace"
    weaver.config.fabric.mirror_name = "Mirror"
    export = RolePolicyExport(policies=[RolePolicy(name="Reader", permissionscopes=[])])
    _mark_strict_dataverse_export_validated(export, weaver.config)
    fabric_api = _MutatingDryRunFabricAPI(
        [current.model_dump(exclude_none=True, exclude_unset=True)], export
    )
    weaver.fabric_api = fabric_api

    async def build_policy(policy, access_type):
        return _data_access_policy("ReaderPWPolicy", "member-2")

    weaver.__build_data_access_role_policy__ = build_policy
    weaver.prepare_role_apply("item-id", rollback_snapshot_handler=lambda *_: None)

    try:
        asyncio.run(weaver.apply_role(export))
    except PolicyWeaverError as error:
        assert "unchanged export" in str(error)
    else:
        raise AssertionError("Mutated strict export reached Fabric apply")

    assert [call[2] for call in fabric_api.put_calls] == [True]


def test_strict_dataverse_map_marks_validated_export() -> None:
    config = DataverseSourceMap(
        source=Source(name="Dataverse"),
        fabric=FabricConfig(policy_mapping="role_based"),
        constraints={"columns": {"columnlevelsecurity": True}},
        dataverse=DataverseSourceConfig(
            environment_url="https://example.crm.dynamics.com",
            strict_access_parity=True,
            poa_read_access_status="verified_empty",
        ),
    )
    mapper = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
    mapper.config = config
    mapper.logger = Mock()
    mapper.api_client = SimpleNamespace(
        get_environment_security_map=lambda source: DataverseEnvironment()
    )

    export = mapper.map_policy("role_based")

    assert is_strict_dataverse_export_validated(export, config)

    different_target = config.model_copy(deep=True)
    different_target.fabric.mirror_id = "different-item"
    assert not is_strict_dataverse_export_validated(export, different_target)

    export.policies.append(RolePolicy(name="Injected", permissionscopes=[]))
    assert not is_strict_dataverse_export_validated(export, config)


def test_strict_dataverse_role_build_rejects_unresolved_graph_member() -> None:
    weaver = WeaverAgent.__new__(WeaverAgent)
    weaver.config = SimpleNamespace(
        type=PolicyWeaverConnectorType.DATAVERSE,
        dataverse=SimpleNamespace(strict_access_parity=True),
        fabric=SimpleNamespace(
            tenant_id="tenant-id",
            fabric_role_suffix="PWPolicy",
        ),
        constraints=None,
        mapped_items=None,
    )
    weaver.logger = Mock()
    weaver.graph_client = SimpleNamespace(
        get_service_principal_by_id=AsyncMock(return_value=None)
    )
    weaver._WeaverAgent__graph_map = {}
    weaver.used_role_names = []
    weaver._unmapped_policy_handler = None
    policy = RolePolicy(
        name="Application Reader",
        permissionobjects=[
            PermissionObject(
                app_id="missing-app-id",
                type=IamType.SERVICE_PRINCIPAL,
            )
        ],
        permissionscopes=[
            PermissionScope(
                catalog="catalog",
                catalog_schema="dbo",
                table="account",
                name=PermissionType.SELECT,
                state=PermissionState.GRANT,
            )
        ],
    )

    try:
        asyncio.run(weaver.__build_data_access_role_policy__(policy, "Read"))
    except PolicyWeaverError as error:
        assert "resolve" in str(error).lower()
    else:
        raise AssertionError("Strict role build silently dropped a member")


def test_partial_dataverse_role_build_rejects_unresolved_graph_member() -> None:
    weaver = WeaverAgent.__new__(WeaverAgent)
    weaver.config = SimpleNamespace(
        type=PolicyWeaverConnectorType.DATAVERSE,
        dataverse=SimpleNamespace(
            strict_access_parity=False,
            partial_sync=True,
        ),
        fabric=SimpleNamespace(
            tenant_id="tenant-id",
            fabric_role_suffix="PWPolicy",
        ),
        constraints=None,
        mapped_items=None,
    )
    weaver.logger = Mock()
    weaver.graph_client = SimpleNamespace(
        get_service_principal_by_id=AsyncMock(return_value=None)
    )
    weaver._WeaverAgent__graph_map = {}
    weaver.used_role_names = []
    weaver._unmapped_policy_handler = None
    policy = RolePolicy(
        name="Application Reader",
        permissionobjects=[
            PermissionObject(
                app_id="missing-app-id",
                type=IamType.SERVICE_PRINCIPAL,
            )
        ],
        permissionscopes=[
            PermissionScope(
                catalog="catalog",
                catalog_schema="dbo",
                table="account",
                name=PermissionType.SELECT,
                state=PermissionState.GRANT,
            )
        ],
    )

    try:
        asyncio.run(weaver.__build_data_access_role_policy__(policy, "Read"))
    except PolicyWeaverError as error:
        assert "resolve" in str(error).lower()
    else:
        raise AssertionError("Partial role silently dropped an unresolved member")


def test_fabric_role_name_is_deterministic_and_capped_at_128_characters() -> None:
    weaver = WeaverAgent.__new__(WeaverAgent)
    weaver.config = SimpleNamespace(
        fabric=SimpleNamespace(fabric_role_suffix="PWPolicy")
    )
    weaver.used_role_names = []
    source_name = "9" + "Very-Long_Dataverse Role!" * 20

    first = weaver.__get_fabric_role_name__(source_name)
    weaver.used_role_names = []
    second = weaver.__get_fabric_role_name__(source_name)

    assert first == second
    assert len(first) <= 128
    assert first[0].isalpha()
    assert first.isalnum()
    assert first.endswith("PWPolicy")


def test_fabric_role_name_resolves_case_insensitive_sanitized_collision() -> None:
    weaver = WeaverAgent.__new__(WeaverAgent)
    weaver.config = SimpleNamespace(
        fabric=SimpleNamespace(fabric_role_suffix="PWPolicy")
    )
    weaver.used_role_names = []

    first = weaver.__get_fabric_role_name__("Case-Reader")
    second = weaver.__get_fabric_role_name__("casereader")

    assert first.casefold() != second.casefold()
    assert len(second) <= 128
    assert second.endswith("PWPolicy")

    forward = {"Case-Reader": first, "casereader": second}
    weaver.used_role_names = []
    reverse = {
        "casereader": weaver.__get_fabric_role_name__("casereader"),
        "Case-Reader": weaver.__get_fabric_role_name__("Case-Reader"),
    }
    assert forward == reverse


def test_fabric_role_name_rejects_suffix_without_hash_budget() -> None:
    weaver = WeaverAgent.__new__(WeaverAgent)
    weaver.config = SimpleNamespace(
        fabric=SimpleNamespace(fabric_role_suffix="S" * 116)
    )
    weaver.used_role_names = []

    try:
        weaver.__get_fabric_role_name__("Reader")
    except ValueError as error:
        assert "suffix is too long" in str(error)
    else:
        raise AssertionError("Oversized Fabric role suffix was accepted")


def test_fabric_role_name_rejects_suffix_without_alphanumeric_characters() -> None:
    weaver = WeaverAgent.__new__(WeaverAgent)
    weaver.config = SimpleNamespace(fabric=SimpleNamespace(fabric_role_suffix="---"))
    weaver.used_role_names = []

    try:
        weaver.__get_fabric_role_name__("Reader")
    except ValueError as error:
        assert "alphanumeric" in str(error)
    else:
        raise AssertionError("Invalid Fabric role suffix was accepted")


def test_fabric_role_name_rejects_partially_non_alphanumeric_suffix() -> None:
    weaver = WeaverAgent.__new__(WeaverAgent)
    weaver.config = SimpleNamespace(
        fabric=SimpleNamespace(fabric_role_suffix="PW-Policy")
    )
    weaver.used_role_names = []

    try:
        weaver.__get_fabric_role_name__("Reader")
    except ValueError as error:
        assert "only alphanumeric" in str(error)
    else:
        raise AssertionError("Partially invalid Fabric role suffix was accepted")


def test_strict_dataverse_target_rejects_unmanaged_roles() -> None:
    current = _data_access_policy("ManualRole", "member-1")
    weaver, _ = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()

    try:
        weaver.__validate_dataverse_target_access_boundary__()
    except PolicyWeaverError as error:
        assert "unmanaged" in str(error).lower()
    else:
        raise AssertionError("Strict Dataverse target accepted an unmanaged role")


def test_partial_dataverse_target_rejects_unmanaged_roles() -> None:
    current = _data_access_policy("ManualRole", "member-1")
    weaver, _ = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()
    weaver.config.dataverse.strict_access_parity = False
    weaver.config.dataverse.partial_sync = True

    try:
        weaver.__validate_dataverse_target_access_boundary__()
    except PolicyWeaverError as error:
        assert "unmanaged" in str(error).lower()
    else:
        raise AssertionError("Partial Dataverse target accepted an unmanaged role")


def test_strict_dataverse_target_requires_default_reader_removal() -> None:
    current = _data_access_policy("DefaultReader", "member-1")
    weaver, _ = _reconciliation_weaver(current)
    weaver.config = _strict_reconciliation_config()
    weaver.config.fabric.delete_default_reader_role = False

    try:
        weaver.__validate_dataverse_target_access_boundary__()
    except PolicyWeaverError as error:
        assert "defaultreader" in str(error).lower()
    else:
        raise AssertionError("Strict Dataverse target retained DefaultReader")
