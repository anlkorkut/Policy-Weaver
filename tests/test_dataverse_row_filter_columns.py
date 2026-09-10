import unittest

from policyweaver.plugins.dataverse.client import DataversePolicyWeaver


class _FakeLogger:
    def __init__(self):
        self.warnings = []

    def warning(self, message):
        self.warnings.append(message)


class TestDataverseRowFilterColumns(unittest.TestCase):
    def setUp(self):
        # Bypass __init__ so we can unit test pure filter generation logic.
        self.client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        self.client.logger = _FakeLogger()
        self.client.environment = type("Env", (), {})()
        self.client.environment.business_units = []

    def _build_condition(self, effective_depth, role_business_unit_id, principal_ids):
        conditions = self.client.__build_row_filter_conditions__(
            effective_depth=effective_depth,
            role_business_unit_id=role_business_unit_id,
            principal_ids=principal_ids,
            schema_name="dbo",
            table_name="account",
        )
        return conditions[0] if conditions else None

    def test_deep_uses_owningbusinessunit_column(self):
        self.client.environment.business_units = [
            type("BU", (), {"id": "bu-root", "parent_business_unit_id": None})(),
            type("BU", (), {"id": "bu-child", "parent_business_unit_id": "bu-root"})(),
        ]

        condition = self._build_condition(
            effective_depth="Deep",
            role_business_unit_id="bu-root",
            principal_ids=set(),
        )

        self.assertIn("owningbusinessunit in (", condition)
        self.assertNotIn("_owningbusinessunit_value", condition)

    def test_local_uses_owningbusinessunit_column(self):
        condition = self._build_condition(
            effective_depth="Local",
            role_business_unit_id="bu-root",
            principal_ids=set(),
        )

        self.assertEqual("owningbusinessunit = 'bu-root'", condition)

    def test_basic_uses_ownerid_column(self):
        condition = self._build_condition(
            effective_depth="Basic",
            role_business_unit_id=None,
            principal_ids={"user-a", "user-b"},
        )

        self.assertIn("ownerid in (", condition)
        self.assertNotIn("_ownerid_value", condition)

    def test_local_without_business_unit_returns_false_filter(self):
        condition = self._build_condition(
            effective_depth="Local",
            role_business_unit_id=None,
            principal_ids=set(),
        )

        self.assertEqual("false", condition)

    def test_basic_without_principals_returns_false_filter(self):
        condition = self._build_condition(
            effective_depth="Basic",
            role_business_unit_id=None,
            principal_ids=set(),
        )

        self.assertEqual("false", condition)

    def test_global_returns_none(self):
        condition = self._build_condition(
            effective_depth="Global",
            role_business_unit_id="bu-1",
            principal_ids=set(),
        )

        self.assertIsNone(condition)

    def test_unknown_depth_returns_false_deny_all(self):
        """Unknown depth must fail closed — deny all rows, not grant all."""
        condition = self._build_condition(
            effective_depth="Unknown",
            role_business_unit_id="bu-1",
            principal_ids={"user-a"},
        )

        self.assertEqual("false", condition)
        self.assertTrue(
            any(
                "Unrecognized effective depth" in w for w in self.client.logger.warnings
            )
        )

    def test_none_depth_returns_false_deny_all(self):
        """Null/None depth must fail closed — deny all rows."""
        condition = self._build_condition(
            effective_depth=None,
            role_business_unit_id="bu-1",
            principal_ids={"user-a"},
        )

        self.assertEqual("false", condition)

    def test_arbitrary_string_depth_returns_false_deny_all(self):
        """Unexpected depth values like 'Organization' must fail closed."""
        condition = self._build_condition(
            effective_depth="Organization",
            role_business_unit_id="bu-1",
            principal_ids={"user-a"},
        )

        self.assertEqual("false", condition)


if __name__ == "__main__":
    unittest.main()
