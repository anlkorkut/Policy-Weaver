class PolicyWeaverError(Exception):
    """
    Custom exception for Policy Weaver errors.
    This exception can be raised for any errors specific to the Policy Weaver application.
    It can be used to differentiate between general exceptions and those specific to Policy Weaver.
    Attributes:
        message (str): The error message.
    """

    pass


class FabricCapacityNotActiveError(PolicyWeaverError):
    """Raised when Fabric rejects a role write because its capacity is inactive."""

    def __init__(self, capacity_id: str, workspace_id: str, item_id: str) -> None:
        self.capacity_id = capacity_id
        self.workspace_id = workspace_id
        self.item_id = item_id
        super().__init__(
            f"Fabric capacity {capacity_id} assigned to workspace {workspace_id} "
            f"is not active, so Data Access Roles for item {item_id} cannot be "
            "validated or applied. Resume the capacity in Azure/Fabric "
            "administration or reassign the workspace to an active compatible "
            "capacity, then rerun. No roles were changed."
        )
