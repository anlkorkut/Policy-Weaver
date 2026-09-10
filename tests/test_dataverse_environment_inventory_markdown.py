from datetime import datetime, timezone

from policyweaver.plugins.dataverse.model import (
    DataverseBusinessUnit,
    DataverseEnvironment,
    DataverseRolePrivilege,
    DataverseSecurityRole,
    DataverseTeam,
    DataverseUser,
)
from scripts.dataverse_environment_inventory import build_markdown_inventory


def test_markdown_inventory_numbers_hierarchy_users_roles_and_assignments() -> None:
    environment = DataverseEnvironment(
        business_units=[
            DataverseBusinessUnit(
                id="bu-root",
                name="Root | BU",
                created_on="2026-01-01T00:00:00Z",
            ),
            DataverseBusinessUnit(
                id="bu-new",
                name="New BU",
                parent_business_unit_id="bu-root",
                created_on="2026-09-08T12:00:00Z",
                modified_on="2026-09-08T13:00:00Z",
            ),
        ],
        users=[
            DataverseUser(
                id="user-1",
                name="Ada User",
                email="ada@example.com",
                azure_ad_object_id="entra-1",
                business_unit_id="bu-new",
                access_mode=0,
                is_licensed=True,
                azure_state=0,
            )
        ],
        teams=[
            DataverseTeam(
                id="team-1",
                name="New BU Team",
                business_unit_id="bu-new",
                member_ids=["user-1"],
            )
        ],
        security_roles=[
            DataverseSecurityRole(
                id="role-direct",
                name="Direct Reader",
                business_unit_id="bu-new",
                is_inherited=1,
            ),
            DataverseSecurityRole(
                id="role-team",
                name="Team Reader",
                business_unit_id="bu-new",
                is_inherited=0,
            ),
        ],
        role_privileges=[
            DataverseRolePrivilege(
                role_id="role-direct",
                entity_name="account",
                can_read=True,
                depth="Local",
            )
        ],
        user_role_assignments={"user-1": ["role-direct"]},
        team_role_assignments={"team-1": ["role-team"]},
    )

    markdown = build_markdown_inventory(
        environment,
        "https://example.crm.dynamics.com",
        generated_at=datetime(2026, 9, 9, 12, tzinfo=timezone.utc),
    )

    assert "## 1. Summary" in markdown
    assert "## 2. Business units" in markdown
    assert "## 3. Active users" in markdown
    assert "## 4. Published security role instances" in markdown
    assert "Root \\| BU" in markdown
    assert "1. **New BU**" in markdown
    assert "Direct Reader [BU: New BU; ID: role-direct]" in markdown
    assert "Team Reader [BU: New BU; ID: role-team] via New BU Team" in markdown
    assert "| 1 | Ada User | User | New BU |" in markdown
    assert "| 1 | Direct Reader | New BU | 1 | 1 | 0 | 1 | 1 | Local: 1 |" in markdown
