import logging
import unittest

from policyweaver.core.enum import IamType
from policyweaver.models.config import Source, SourceSchema
from policyweaver.plugins.dataverse.client import DataversePolicyWeaver
from policyweaver.plugins.dataverse.model import (
    DataverseEnvironment,
    DataverseRolePrivilege,
    DataverseSecurityRole,
    DataverseSourceConfig,
    DataverseSourceMap,
    DataverseTablePermission,
)


class TestCompactRoleMapping(unittest.TestCase):
    def test_alternate_table_permission_requires_explicit_read_grant(self) -> None:
        environment = DataverseEnvironment(
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    principal_id="user-1",
                    principal_type=IamType.USER,
                    has_read=False,
                    role_id="role-1",
                    role_name="Reader",
                )
            ]
        )
        client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        client.environment = environment

        self.assertEqual({}, client.__build_role_map__())

    def test_principal_count_does_not_multiply_role_table_entries(self) -> None:
        role_id = "role-1"
        user_count = 12_500
        environment = DataverseEnvironment(
            security_roles=[
                DataverseSecurityRole(
                    id=role_id,
                    name="Case Reader",
                    business_unit_id="bu-1",
                )
            ],
            role_privileges=[
                DataverseRolePrivilege(
                    privilege_id="priv-basic",
                    role_id=role_id,
                    entity_name="incident",
                    depth="Basic",
                    can_read=True,
                ),
                DataverseRolePrivilege(
                    privilege_id="priv-global",
                    role_id=role_id,
                    entity_name="incident",
                    depth="Global",
                    can_read=True,
                ),
                DataverseRolePrivilege(
                    privilege_id="priv-contact",
                    role_id=role_id,
                    entity_name="contact",
                    depth="Local",
                    can_read=True,
                ),
            ],
            user_role_assignments={
                f"user-{index}": [role_id] for index in range(user_count)
            },
        )
        config = DataverseSourceMap(
            source=Source(
                name="Dataverse",
                schemas=[SourceSchema(name="dbo", tables=["incident", "contact"])],
            ),
            dataverse=DataverseSourceConfig(
                environment_url="https://example.crm.dynamics.com"
            ),
        )
        client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        client.config = config
        client.environment = environment
        client.logger = logging.getLogger("test_compact_role_mapping")

        role_map = client.__build_role_map__()

        self.assertEqual(1, len(role_map))
        role_data = next(iter(role_map.values()))
        self.assertEqual(user_count, len(role_data["principals"]))
        self.assertEqual(2, len(role_data["perms"]))
        self.assertEqual({"incident", "contact"}, role_data["tables"])
        incident_permission = next(
            permission
            for permission in role_data["perms"]
            if permission.table_name == "incident"
        )
        self.assertEqual("Global", incident_permission.depth)
        self.assertIn(("user-0", IamType.USER), role_data["principals"])


if __name__ == "__main__":
    unittest.main()
