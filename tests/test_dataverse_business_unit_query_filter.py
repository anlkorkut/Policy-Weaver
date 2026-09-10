import unittest

from policyweaver.plugins.dataverse.api import DataverseAPIClient


class TestDataverseBusinessUnitQueryFilter(unittest.TestCase):
    def test_business_unit_query_includes_disabled_units(self):
        client = DataverseAPIClient.__new__(DataverseAPIClient)
        client.api_url = "https://example.crm.dynamics.com/api/data/v9.2"

        captured = {"url": None}

        def fake_get_paged(url):
            captured["url"] = url
            return [
                {
                    "businessunitid": "bu-1",
                    "name": "Active BU",
                    "_parentbusinessunitid_value": None,
                    "isdisabled": False,
                    "createdon": "2026-09-08T12:00:00Z",
                    "modifiedon": "2026-09-08T13:00:00Z",
                },
                {
                    "businessunitid": "bu-2",
                    "name": "Disabled Child BU",
                    "_parentbusinessunitid_value": "bu-1",
                    "isdisabled": True,
                },
            ]

        client._get_paged = fake_get_paged

        result = client.__get_business_units__()

        self.assertNotIn("$filter=isdisabled eq false", captured["url"])
        self.assertIn("createdon,modifiedon", captured["url"])
        self.assertEqual(
            ["bu-1", "bu-2"], [business_unit.id for business_unit in result]
        )
        self.assertTrue(result[1].is_disabled)
        self.assertEqual("2026-09-08T12:00:00Z", result[0].created_on)
        self.assertEqual("2026-09-08T13:00:00Z", result[0].modified_on)


if __name__ == "__main__":
    unittest.main()
