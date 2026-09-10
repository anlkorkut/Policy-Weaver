from types import SimpleNamespace

from policyweaver.core.enum import PolicyWeaverConnectorType
from policyweaver.models.config import SourceMapItem
from policyweaver.weaver import WeaverAgent


def _generate_rls_value(
    connector_type: PolicyWeaverConnectorType,
    schema_name: str = "dbo",
    table_name: str = "account",
) -> str:
    weaver = WeaverAgent.__new__(WeaverAgent)
    weaver.config = SimpleNamespace(type=connector_type)
    return weaver.__generate_rls_value__(
        schema_name=schema_name,
        table_name=table_name,
        filter_condition="ownerid != 'missing'",
    )


def test_dataverse_rls_value_omits_schema_qualification() -> None:
    value = _generate_rls_value(PolicyWeaverConnectorType.DATAVERSE)

    assert value == "SELECT * FROM account WHERE ownerid <> 'missing'"


def test_schema_based_connector_rls_value_keeps_schema_qualification() -> None:
    value = _generate_rls_value(PolicyWeaverConnectorType.SNOWFLAKE)

    assert value == "SELECT * FROM dbo.account WHERE ownerid <> 'missing'"


def test_dataverse_rls_value_uses_mapped_table_name() -> None:
    weaver = WeaverAgent.__new__(WeaverAgent)
    weaver.config = SimpleNamespace(
        type=PolicyWeaverConnectorType.DATAVERSE,
        mapped_items=[
            SourceMapItem(
                catalog="catalog",
                catalog_schema="dbo",
                table="account",
                mirror_table_name="renamed_account",
            )
        ],
    )

    value = weaver.__generate_rls_value__(
        catalog_name="catalog",
        schema_name="dbo",
        table_name="account",
        filter_condition="ownerid != 'missing'",
    )

    assert value == "SELECT * FROM renamed_account WHERE ownerid <> 'missing'"
