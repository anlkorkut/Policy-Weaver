import logging
import unittest

from policyweaver.models.config import Source
from policyweaver.plugins.dataverse.api import DataverseAPIClient


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self.payload


class TestDataversePaginationSafety(unittest.TestCase):
    def setUp(self) -> None:
        self.client = DataverseAPIClient.__new__(DataverseAPIClient)
        self.client.api_url = "https://example.crm.dynamics.com/api/data/v9.2"

    def test_repeated_next_link_fails_instead_of_looping(self) -> None:
        first_url = f"{self.client.api_url}/systemusers"
        self.client._request_get = lambda url: _FakeResponse(
            {"value": [], "@odata.nextLink": first_url}
        )

        with self.assertRaisesRegex(ValueError, "pagination cycle"):
            self.client._get_paged(first_url)

    def test_cross_origin_next_link_is_rejected_before_request(self) -> None:
        first_url = f"{self.client.api_url}/systemusers"
        requested_urls = []

        def fake_request_get(url: str) -> _FakeResponse:
            requested_urls.append(url)
            return _FakeResponse(
                {
                    "value": [],
                    "@odata.nextLink": "https://attacker.example/collect",
                }
            )

        self.client._request_get = fake_request_get

        with self.assertRaisesRegex(ValueError, "outside the Dataverse API origin"):
            self.client._get_paged(first_url)

        self.assertEqual([first_url], requested_urls)

    def test_missing_value_collection_is_not_treated_as_empty(self) -> None:
        first_url = f"{self.client.api_url}/systemusers"
        self.client._request_get = lambda url: _FakeResponse({"unexpected": "response"})

        with self.assertRaisesRegex(ValueError, "missing a value collection"):
            self.client._get_paged(first_url)


class TestDataverseTokenRefresh(unittest.TestCase):
    def test_headers_refresh_expiring_cached_token(self) -> None:
        client = DataverseAPIClient.__new__(DataverseAPIClient)
        client._DataverseAPIClient__token = "stale-token"
        refresh_calls = []

        def fake_get_access_token(force_refresh: bool = False) -> str:
            refresh_calls.append(force_refresh)
            client._DataverseAPIClient__token = "fresh-token"
            return "fresh-token"

        client._get_access_token = fake_get_access_token

        headers = client._headers

        self.assertEqual([False], refresh_calls)
        self.assertEqual("Bearer fresh-token", headers["Authorization"])


class TestDataverseExpandedRelationshipPaging(unittest.TestCase):
    def test_expanded_relationship_follows_nested_next_link(self) -> None:
        client = DataverseAPIClient.__new__(DataverseAPIClient)
        next_link = (
            "https://example.crm.dynamics.com/api/data/v9.2/"
            "systemusers(user-1)/systemuserroles_association?$skiptoken=next"
        )
        client._get_paged = lambda url: [{"roleid": "role-2"}]
        record = {
            "systemuserroles_association": [{"roleid": "role-1"}],
            "systemuserroles_association@odata.nextLink": next_link,
        }

        relationships = client._get_expanded_collection(
            record, "systemuserroles_association"
        )

        self.assertEqual([{"roleid": "role-1"}, {"roleid": "role-2"}], relationships)


class TestDataverseSecuredColumnDiscovery(unittest.TestCase):
    def test_secured_table_is_found_without_field_permission_row(self) -> None:
        client = DataverseAPIClient.__new__(DataverseAPIClient)
        client.api_url = "https://example.crm.dynamics.com/api/data/v9.2"
        client._get_paged = lambda url: [
            {
                "LogicalName": "contact",
                "Attributes": [
                    {
                        "MetadataId": "secret-id",
                        "LogicalName": "secretcolumn",
                        "IsSecured": True,
                        "IsValidForRead": True,
                    }
                ],
            }
        ]

        result = client.__get_secured_table_names__({"contact"})

        self.assertEqual({"contact"}, result)


class TestDataverseMaskingAssignmentExtraction(unittest.TestCase):
    def setUp(self) -> None:
        self.client = DataverseAPIClient.__new__(DataverseAPIClient)
        self.client.api_url = "https://example.crm.dynamics.com/api/data/v9.2"

    def test_active_masking_assignments_are_scoped_to_selected_tables(self) -> None:
        self.client._get_paged = lambda url: [
            {
                "attributemaskingruleid": "assignment-account",
                "entityname": "account",
                "attributelogicalname": "secretcolumn",
                "_maskingruleid_value": "mask-account",
            },
            {
                "attributemaskingruleid": "assignment-contact",
                "entityname": "contact",
                "attributelogicalname": "privatecolumn",
                "_maskingruleid_value": "mask-contact",
            },
        ]

        rules = self.client.__get_attribute_masking_rules__({"account"})

        self.assertEqual(1, len(rules))
        self.assertEqual("account", rules[0].entity_name)
        self.assertEqual("secretcolumn", rules[0].attribute_logical_name)

    def test_incomplete_masking_assignment_fails_closed(self) -> None:
        self.client._get_paged = lambda url: [
            {
                "attributemaskingruleid": "assignment-account",
                "entityname": "account",
                "attributelogicalname": "secretcolumn",
            }
        ]

        with self.assertRaisesRegex(ValueError, "masking assignment metadata"):
            self.client.__get_attribute_masking_rules__({"account"})

    def test_missing_expanded_attributes_is_rejected(self) -> None:
        client = DataverseAPIClient.__new__(DataverseAPIClient)
        client.api_url = "https://example.crm.dynamics.com/api/data/v9.2"
        client._get_paged = lambda url: [
            {"LogicalName": "contact", "OwnershipType": "UserOwned"}
        ]

        with self.assertRaisesRegex(ValueError, "omitted.*Attributes"):
            client.__get_table_metadata_overview__({"contact"})

    def test_null_expanded_attributes_is_rejected(self) -> None:
        client = DataverseAPIClient.__new__(DataverseAPIClient)
        client.api_url = "https://example.crm.dynamics.com/api/data/v9.2"
        client._get_paged = lambda url: [
            {
                "LogicalName": "contact",
                "OwnershipType": "UserOwned",
                "Attributes": None,
            }
        ]

        with self.assertRaisesRegex(ValueError, "null.*Attributes"):
            client.__get_table_metadata_overview__({"contact"})

    def test_attribute_without_security_flag_is_rejected(self) -> None:
        client = DataverseAPIClient.__new__(DataverseAPIClient)
        client.api_url = "https://example.crm.dynamics.com/api/data/v9.2"
        client._get_paged = lambda url: [
            {
                "LogicalName": "contact",
                "OwnershipType": "UserOwned",
                "Attributes": [{"LogicalName": "secretcolumn", "IsValidForRead": True}],
            }
        ]

        with self.assertRaisesRegex(ValueError, "incomplete attribute"):
            client.__get_table_metadata_overview__({"contact"})

    def test_attribute_with_null_security_flag_is_rejected(self) -> None:
        client = DataverseAPIClient.__new__(DataverseAPIClient)
        client.api_url = "https://example.crm.dynamics.com/api/data/v9.2"
        client._get_paged = lambda url: [
            {
                "LogicalName": "contact",
                "OwnershipType": "UserOwned",
                "Attributes": [
                    {
                        "MetadataId": "secret-id",
                        "LogicalName": "secretcolumn",
                        "IsSecured": None,
                        "IsValidForRead": True,
                    }
                ],
            }
        ]

        with self.assertRaisesRegex(ValueError, "incomplete attribute"):
            client.__get_table_metadata_overview__({"contact"})

    def test_attribute_with_non_string_metadata_id_is_rejected(self) -> None:
        client = DataverseAPIClient.__new__(DataverseAPIClient)
        client.api_url = "https://example.crm.dynamics.com/api/data/v9.2"
        client._get_paged = lambda url: [
            {
                "LogicalName": "contact",
                "OwnershipType": "UserOwned",
                "Attributes": [
                    {
                        "MetadataId": 123,
                        "LogicalName": "secretcolumn",
                        "IsSecured": True,
                        "IsValidForRead": True,
                    }
                ],
            }
        ]

        with self.assertRaisesRegex(ValueError, "incomplete attribute"):
            client.__get_table_metadata_overview__({"contact"})


class TestBulkRelationshipExtraction(unittest.TestCase):
    def setUp(self) -> None:
        self.client = DataverseAPIClient.__new__(DataverseAPIClient)
        self.client.api_url = "https://example.crm.dynamics.com/api/data/v9.2"
        self.client.logger = logging.getLogger("test_bulk_relationship_extraction")

    def test_environment_uses_collection_queries_without_per_record_urls(self) -> None:
        requested_urls = []

        def fake_get_paged(url):
            requested_urls.append(url)
            if "/businessunits" in url:
                return []
            if "/organizations" in url:
                return [
                    {
                        "organizationid": "organization-1",
                        "ishierarchicalsecuritymodelenabled": False,
                        "usepositionhierarchy": False,
                        "maxdepthforhierarchicalsecuritymodel": 3,
                    }
                ]
            if "/systemusers" in url:
                return [
                    {
                        "systemuserid": "user-1",
                        "fullname": "User One",
                        "internalemailaddress": "one@example.com",
                        "azureactivedirectoryobjectid": "entra-user-1",
                        "applicationid": "00000000-0000-0000-0000-000000000000",
                        "isdisabled": False,
                        "_businessunitid_value": "bu-1",
                        "systemuserroles_association": [{"roleid": "role-1"}],
                        "teammembership_association": [{"teamid": "team-1"}],
                        "systemuserprofiles_association": [
                            {"fieldsecurityprofileid": "profile-1"}
                        ],
                    }
                ]
            if "/teams" in url:
                return [
                    {
                        "teamid": "team-1",
                        "name": "Team One",
                        "teamtype": 0,
                        "_businessunitid_value": "bu-1",
                        "teamroles_association": [{"roleid": "role-1"}],
                        "teamprofiles_association": [
                            {"fieldsecurityprofileid": "profile-1"}
                        ],
                    }
                ]
            if "/roles" in url:
                return [
                    {
                        "roleid": "role-1",
                        "name": "Reader",
                        "_businessunitid_value": "bu-1",
                    }
                ]
            if "/roleprivilegescollection" in url:
                return [
                    {
                        "roleid": "role-1",
                        "privilegeid": "priv-1",
                        "privilegedepthmask": 8,
                    }
                ]
            if "/privileges" in url:
                return [
                    {
                        "privilegeid": "priv-1",
                        "name": "prvReadaccount",
                        "accessright": 1,
                    }
                ]
            if "/fieldsecurityprofiles" in url:
                return [
                    {
                        "fieldsecurityprofileid": "profile-1",
                        "name": "Profile One",
                    }
                ]
            if "/fieldpermissions" in url:
                return [
                    {
                        "fieldpermissionid": "field-perm-1",
                        "_fieldsecurityprofileid_value": "profile-1",
                        "entityname": "account",
                        "attributelogicalname": "secretcolumn",
                        "canread": 4,
                    }
                ]
            if "/attributemaskingrules" in url:
                return []
            if "/EntityDefinitions(LogicalName='account')/Attributes" in url:
                return [
                    {
                        "MetadataId": "column-accountid",
                        "LogicalName": "accountid",
                        "IsSecured": False,
                        "IsValidForRead": True,
                    },
                    {
                        "MetadataId": "column-secret",
                        "LogicalName": "secretcolumn",
                        "IsSecured": True,
                        "IsValidForRead": True,
                    },
                ]
            if "/EntityDefinitions?" in url:
                return [
                    {
                        "LogicalName": "account",
                        "OwnershipType": "UserOwned",
                        "Attributes": [
                            {
                                "MetadataId": "column-secret",
                                "LogicalName": "secretcolumn",
                                "IsSecured": True,
                                "IsValidForRead": True,
                            }
                        ],
                    }
                ]
            if "/principalobjectattributeaccessset" in url:
                return [
                    {
                        "principalobjectattributeaccessid": "poaa-1",
                        "attributeid": "column-secret",
                        "_objectid_value": "account-1",
                        "_objectid_value@Microsoft.Dynamics.CRM.lookuplogicalname": "account",
                        "_principalid_value": "user-1",
                        "_principalid_value@Microsoft.Dynamics.CRM.lookuplogicalname": "systemuser",
                        "readaccess": True,
                    }
                ]
            self.fail(f"Unexpected URL: {url}")

        self.client._get_paged = fake_get_paged

        environment = self.client.get_environment_security_map(Source(name="dv"))

        self.assertEqual(13, len(requested_urls))
        self.assertFalse(any("teams(" in url for url in requested_urls))
        self.assertFalse(any("fieldsecurityprofiles(" in url for url in requested_urls))
        systemusers_url = next(url for url in requested_urls if "/systemusers" in url)
        self.assertIn("systemuserroles_association", systemusers_url)
        self.assertIn("teammembership_association", systemusers_url)
        self.assertIn("systemuserprofiles_association", systemusers_url)
        self.assertEqual(["role-1"], environment.user_role_assignments["user-1"])
        self.assertIsNone(environment.users[0].application_id)
        self.assertEqual(["user-1"], environment.teams[0].member_ids)
        self.assertEqual(["role-1"], environment.team_role_assignments["team-1"])
        profile = environment.field_security_profiles[0]
        self.assertEqual(["user-1"], profile.user_ids)
        self.assertEqual(["team-1"], profile.team_ids)
        self.assertEqual("secretcolumn", profile.permissions[0].attribute_logical_name)
        self.assertEqual("account", environment.table_metadata[0].logical_name)
        self.assertEqual("UserOwned", environment.table_metadata[0].ownership_type)
        self.assertEqual([], environment.attribute_masking_rules)
        self.assertEqual(
            ["accountid", "secretcolumn"],
            [column.logical_name for column in environment.table_metadata[0].columns],
        )
        self.assertEqual(
            "poaa-1",
            environment.principal_object_attribute_accesses[0].id,
        )
        self.assertFalse(environment.hierarchy_security_enabled)
        self.assertEqual(3, environment.hierarchy_security_depth)


if __name__ == "__main__":
    unittest.main()
