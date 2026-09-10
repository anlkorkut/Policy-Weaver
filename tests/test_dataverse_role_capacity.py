import logging
import unittest

from policyweaver.models.config import Source, SourceSchema
from policyweaver.plugins.dataverse.client import DataversePolicyWeaver
from policyweaver.plugins.dataverse.model import (
    DataverseEnvironment,
    DataverseRolePrivilege,
    DataverseSecurityRole,
    DataverseSourceConfig,
    DataverseSourceMap,
    DataverseUser,
)


def _build_weaver(
    depth: str, role_limit: int, user_count: int = 3
) -> DataversePolicyWeaver:
    role_id = "role-1"
    users = [
        DataverseUser(
            id=f"user-{index}",
            email=f"user-{index}@example.com",
            azure_ad_object_id=f"entra-{index}",
        )
        for index in range(user_count)
    ]
    environment = DataverseEnvironment(
        users=users,
        security_roles=[
            DataverseSecurityRole(
                id=role_id,
                name="Case Reader",
                business_unit_id="bu-1",
            )
        ],
        role_privileges=[
            DataverseRolePrivilege(
                privilege_id="priv-1",
                role_id=role_id,
                entity_name="incident",
                depth=depth,
                can_read=True,
            )
        ],
        user_role_assignments={user.id: [role_id] for user in users},
    )
    config = DataverseSourceMap(
        source=Source(
            name="Dataverse",
            schemas=[SourceSchema(name="dbo", tables=["incident"])],
        ),
        dataverse=DataverseSourceConfig(
            environment_url="https://example.crm.dynamics.com",
            onelake_role_limit=role_limit,
        ),
    )
    client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
    client.config = config
    client.environment = environment
    client.logger = logging.getLogger("test_dataverse_role_capacity")
    return client


class TestDataverseRoleCapacity(unittest.TestCase):
    def test_basic_role_fails_before_exceeding_limit(self) -> None:
        client = _build_weaver(depth="Basic", role_limit=2)

        with self.assertRaisesRegex(ValueError, "requires at least 3 OneLake roles"):
            client.__build_role_based_export__()

    def test_global_role_with_many_members_remains_one_shared_role(self) -> None:
        client = _build_weaver(depth="Global", role_limit=2)

        export = client.__build_role_based_export__()

        self.assertEqual(1, len(export.policies))
        self.assertEqual(3, len(export.policies[0].permissionobjects))

    def test_shared_role_members_are_split_at_onelake_limit(self) -> None:
        client = _build_weaver(depth="Global", role_limit=2, user_count=501)

        export = client.__build_role_based_export__()

        self.assertEqual(2, len(export.policies))
        self.assertEqual([500, 1], [len(p.permissionobjects) for p in export.policies])
        chunked_member_ids = [
            permission_object.entra_object_id
            for policy in export.policies
            for permission_object in policy.permissionobjects
        ]
        self.assertEqual(sorted(chunked_member_ids), chunked_member_ids)
        self.assertEqual(
            ["incident"],
            [scope.table for scope in export.policies[0].permissionscopes],
        )
        self.assertEqual(
            ["incident"],
            [scope.table for scope in export.policies[1].permissionscopes],
        )

    def test_member_chunks_are_included_in_capacity_preflight(self) -> None:
        client = _build_weaver(depth="Global", role_limit=1, user_count=501)

        with self.assertRaisesRegex(ValueError, "requires at least 2 OneLake roles"):
            client.__build_role_based_export__()


if __name__ == "__main__":
    unittest.main()
