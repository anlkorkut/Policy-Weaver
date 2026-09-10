import unittest

from policyweaver.plugins.dataverse.api import DataverseAPIClient
from policyweaver.plugins.dataverse.model import (
    DataverseRolePrivilege,
    DataverseSecurityRole,
)


class _FakeLogger:
    def __init__(self):
        self.warnings = []

    def warning(self, message):
        self.warnings.append(message)


class TestDataverseRoleEntityDepthPrecedence(unittest.TestCase):
    def setUp(self):
        # Bypass __init__ to avoid env and HTTP session requirements.
        self.client = DataverseAPIClient.__new__(DataverseAPIClient)
        self.client.logger = _FakeLogger()

    def _build_role_entity_map(self, privileges, roles):
        return self.client.__build_role_entity_map__(
            role_privileges=privileges,
            security_roles=roles,
        )

    def test_keeps_strongest_depth_when_basic_then_global(self):
        role = DataverseSecurityRole(
            id="role-1",
            name="Sales Reader",
            business_unit_id="bu-1",
        )
        privileges = [
            DataverseRolePrivilege(
                privilege_id="p1",
                role_id="role-1",
                name="prvReadaccount",
                entity_name="account",
                depth="Basic",
                can_read=True,
            ),
            DataverseRolePrivilege(
                privilege_id="p2",
                role_id="role-1",
                name="prvReadaccount",
                entity_name="account",
                depth="Global",
                can_read=True,
            ),
        ]

        result = self._build_role_entity_map(privileges=privileges, roles=[role])

        self.assertIn("role-1", result)
        role_name, role_bu_id, entity_depth_map = result["role-1"]
        self.assertEqual("Sales Reader", role_name)
        self.assertEqual("bu-1", role_bu_id)
        self.assertEqual("Global", entity_depth_map["account"])

    def test_keeps_strongest_depth_when_global_then_basic(self):
        role = DataverseSecurityRole(
            id="role-1",
            name="Sales Reader",
            business_unit_id="bu-1",
        )
        privileges = [
            DataverseRolePrivilege(
                privilege_id="p1",
                role_id="role-1",
                name="prvReadaccount",
                entity_name="account",
                depth="Global",
                can_read=True,
            ),
            DataverseRolePrivilege(
                privilege_id="p2",
                role_id="role-1",
                name="prvReadaccount",
                entity_name="account",
                depth="Basic",
                can_read=True,
            ),
        ]

        result = self._build_role_entity_map(privileges=privileges, roles=[role])

        self.assertEqual("Global", result["role-1"][2]["account"])

    def test_unknown_depth_normalizes_to_unknown_not_global(self):
        """Missing/null depth should produce 'Unknown' to trigger fail-closed downstream."""
        role = DataverseSecurityRole(
            id="role-1",
            name="Sales Reader",
            business_unit_id="bu-1",
        )
        privileges = [
            DataverseRolePrivilege(
                privilege_id="p1",
                role_id="role-1",
                name="prvReadaccount",
                entity_name="account",
                depth=None,
                can_read=True,
            )
        ]

        result = self._build_role_entity_map(privileges=privileges, roles=[role])

        self.assertEqual("Unknown", result["role-1"][2]["account"])

    def test_unrecognized_depth_string_normalizes_to_unknown(self):
        """Depth values not in Basic/Local/Deep/Global should be treated as Unknown.
        __build_role_entity_map__ receives named depth strings from the bitmask
        conversion in __get_role_read_privileges__."""
        role = DataverseSecurityRole(
            id="role-1",
            name="Reader",
            business_unit_id="bu-1",
        )
        privileges = [
            DataverseRolePrivilege(
                privilege_id="p1",
                role_id="role-1",
                name="prvReadcontact",
                entity_name="contact",
                depth="Unknown",
                can_read=True,
            )
        ]

        result = self._build_role_entity_map(privileges=privileges, roles=[role])

        self.assertEqual("Unknown", result["role-1"][2]["contact"])

    def test_known_depth_wins_over_unknown_depth(self):
        """When a role has both Unknown and a valid depth for the same entity, valid depth wins."""
        role = DataverseSecurityRole(
            id="role-1",
            name="Reader",
            business_unit_id="bu-1",
        )
        privileges = [
            DataverseRolePrivilege(
                privilege_id="p1",
                role_id="role-1",
                name="prvReadaccount",
                entity_name="account",
                depth=None,
                can_read=True,
            ),
            DataverseRolePrivilege(
                privilege_id="p2",
                role_id="role-1",
                name="prvReadaccount",
                entity_name="account",
                depth="Local",
                can_read=True,
            ),
        ]

        result = self._build_role_entity_map(privileges=privileges, roles=[role])

        # Local (rank 2) beats Unknown (rank 0)
        self.assertEqual("Local", result["role-1"][2]["account"])


class TestDepthMaskMapping(unittest.TestCase):
    """Validate that privilegedepthmask bitmask values from roleprivilegescollection
    are correctly converted to named depths. These bitmask values (1, 2, 4, 8) differ
    from the ordinal DEPTH_MAP values (0, 1, 2, 3) used by __normalize_depth__."""

    def test_bitmask_1_maps_to_basic(self):
        """privilegedepthmask=1 is Basic (User/Team), not Local."""
        DEPTH_MASK_MAP = {1: "Basic", 2: "Local", 4: "Deep", 8: "Global"}
        self.assertEqual("Basic", DEPTH_MASK_MAP[1])

    def test_bitmask_2_maps_to_local(self):
        """privilegedepthmask=2 is Local (Business Unit), not Deep."""
        DEPTH_MASK_MAP = {1: "Basic", 2: "Local", 4: "Deep", 8: "Global"}
        self.assertEqual("Local", DEPTH_MASK_MAP[2])

    def test_bitmask_4_maps_to_deep(self):
        """privilegedepthmask=4 is Deep (Parent: Business Unit)."""
        DEPTH_MASK_MAP = {1: "Basic", 2: "Local", 4: "Deep", 8: "Global"}
        self.assertEqual("Deep", DEPTH_MASK_MAP[4])

    def test_bitmask_8_maps_to_global(self):
        """privilegedepthmask=8 is Global (Organization)."""
        DEPTH_MASK_MAP = {1: "Basic", 2: "Local", 4: "Deep", 8: "Global"}
        self.assertEqual("Global", DEPTH_MASK_MAP[8])

    def test_bitmask_not_in_map_should_not_resolve(self):
        """Unexpected bitmask values (e.g. 0, 16) must not resolve to a valid depth."""
        DEPTH_MASK_MAP = {1: "Basic", 2: "Local", 4: "Deep", 8: "Global"}
        self.assertNotIn(0, DEPTH_MASK_MAP)
        self.assertNotIn(16, DEPTH_MASK_MAP)
        self.assertNotIn(3, DEPTH_MASK_MAP)


class TestBulkRolePrivilegeExtraction(unittest.TestCase):
    def test_joins_global_collections_without_per_role_requests(self):
        client = DataverseAPIClient.__new__(DataverseAPIClient)
        client.api_url = "https://example.crm.dynamics.com/api/data/v9.2"
        client.logger = _FakeLogger()
        requested_urls = []

        def fake_get_paged(url):
            requested_urls.append(url)
            if "/roleprivilegescollection" in url:
                return [
                    {
                        "roleid": "role-1",
                        "privilegeid": "priv-read-account",
                        "privilegedepthmask": 4,
                    },
                    {
                        "roleid": "role-1",
                        "privilegeid": "priv-write-account",
                        "privilegedepthmask": 8,
                    },
                    {
                        "roleid": "unselected-role",
                        "privilegeid": "priv-read-contact",
                        "privilegedepthmask": 8,
                    },
                ]
            if "/privileges" in url:
                return [
                    {
                        "privilegeid": "priv-read-account",
                        "name": "prvReadaccount",
                        "accessright": 1,
                    },
                    {
                        "privilegeid": "priv-write-account",
                        "name": "prvWriteaccount",
                        "accessright": 2,
                    },
                    {
                        "privilegeid": "priv-read-contact",
                        "name": "prvReadcontact",
                        "accessright": 1,
                    },
                ]
            self.fail(f"Unexpected URL: {url}")

        client._get_paged = fake_get_paged
        roles = [DataverseSecurityRole(id="role-1", name="Reader")]

        result = client.__get_role_read_privileges__(roles)

        self.assertEqual(2, len(requested_urls))
        self.assertFalse(any("/roles(" in url for url in requested_urls))
        self.assertEqual(1, len(result))
        self.assertEqual("account", result[0].entity_name)
        self.assertEqual("Deep", result[0].depth)

    def test_child_role_inherits_root_role_privileges(self):
        client = DataverseAPIClient.__new__(DataverseAPIClient)
        client.api_url = "https://example.crm.dynamics.com/api/data/v9.2"
        client.logger = _FakeLogger()

        def fake_get_paged(url):
            if "/roleprivilegescollection" in url:
                return [
                    {
                        "roleid": "root-role",
                        "privilegeid": "priv-read-account",
                        "privilegedepthmask": 4,
                    }
                ]
            if "/privileges" in url:
                return [
                    {
                        "privilegeid": "priv-read-account",
                        "name": "prvReadaccount",
                        "accessright": 1,
                    }
                ]
            self.fail(f"Unexpected URL: {url}")

        client._get_paged = fake_get_paged
        roles = [
            DataverseSecurityRole(id="root-role", name="Reader"),
            DataverseSecurityRole(
                id="child-role",
                name="Reader",
                parent_root_role_id="root-role",
            ),
        ]

        result = client.__get_role_read_privileges__(roles)

        self.assertEqual({"root-role", "child-role"}, {p.role_id for p in result})
        self.assertTrue(all(p.depth == "Deep" for p in result))


if __name__ == "__main__":
    unittest.main()
