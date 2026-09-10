import logging
import re
from urllib.parse import unquote

from requests.exceptions import HTTPError

from policyweaver.core.api.rest import RestAPIProxy
from policyweaver.core.auth import ServicePrincipal
from policyweaver.core.exception import FabricCapacityNotActiveError


class FabricAPI:
    """
    A class to interact with the Fabric API for managing data access policies.
    This class provides methods to put and list data access policies, and to retrieve workspace information.
    Attributes:
        workspace_id (str): The unique identifier of the Fabric workspace.
        logger (logging.Logger): Logger instance for logging API interactions.
        token (str): Authentication token for accessing the Fabric API.
        rest_api_proxy (RestAPIProxy): Proxy for making REST API calls to the Fabric API.
    """

    def __init__(self, workspace_id: str, weaver_type: str = None):
        """
        Initializes the FabricAPI instance with the given workspace ID.
        Args:
            workspace_id (str): The unique identifier of the Fabric workspace.
        """
        self.logger = logging.getLogger("POLICY_WEAVER")
        self.workspace_id = workspace_id
        self.weaver_type = weaver_type
        self.data_access_roles_etag = None

        headers = {
            "Content-Type": "application/json",
        }

        self.rest_api_proxy = RestAPIProxy(
            base_url="https://api.fabric.microsoft.com/v1",
            headers=headers,
            weaver_type=self.weaver_type,
            auth_header_provider=lambda force_refresh=False: (
                ServicePrincipal.get_token_header(force_refresh=force_refresh)
            ),
        )

    def __get_workspace_uri__(self, uri) -> str:
        """
        Constructs the full URI for the Fabric API workspace.
        Args:
            uri (str): The specific endpoint URI to append to the workspace base URI.
        Returns:
            str: The full URI for the Fabric API workspace.
        """
        uri = f"workspaces/{self.workspace_id}/{uri}"
        self.logger.debug(f"FABRIC API - WORKSPACE URI: {uri}")
        return uri

    def put_data_access_policy(
        self,
        item_id,
        access_policy,
        dry_run: bool = False,
        if_match: str = None,
    ):
        """
        Updates the data access policy for a specific item in the Fabric workspace.
        Args:
            item_id (str): The unique identifier of the item for which the access policy is being updated.
            access_policy (dict): The access policy to be applied to the item.
        Returns:
            Response: The response from the Fabric API after attempting to update the access policy.
        """
        uri = f"items/{item_id}/dataAccessRoles"
        headers = {"If-Match": if_match} if if_match else None
        try:
            return self.rest_api_proxy.put(
                endpoint=self.__get_workspace_uri__(uri),
                data=access_policy,
                headers=headers,
                params={"dryRun": str(dry_run).lower()},
            )
        except HTTPError as error:
            capacity_id = self.__inactive_capacity_id__(error)
            if capacity_id:
                raise FabricCapacityNotActiveError(
                    capacity_id, self.workspace_id, item_id
                ) from error
            raise

    @staticmethod
    def __inactive_capacity_id__(error: HTTPError) -> str | None:
        response = getattr(error, "response", None)
        if response is None:
            return None
        try:
            payload = response.json()
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None

        messages = [payload.get("message")]
        details = payload.get("moreDetails")
        if isinstance(details, list):
            messages.extend(
                detail.get("message") for detail in details if isinstance(detail, dict)
            )
        for message in messages:
            if not isinstance(message, str):
                continue
            match = re.search(
                r"CapacityNotActive\.Capacity "
                r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                r"[0-9a-f]{4}-[0-9a-f]{12}) is not active",
                message,
                flags=re.IGNORECASE,
            )
            if match:
                return match.group(1)
        return None

    def list_data_access_policy(self, item_id):
        """
        Retrieves the data access policy for a specific item in the Fabric workspace.
        Args:
            item_id (str): The unique identifier of the item for which the access policy is being retrieved.
        Returns:
            dict: The data access policy for the specified item.
        """
        uri = self.__get_workspace_uri__(f"items/{item_id}/dataAccessRoles")
        roles = []
        continuation_token = None
        seen_tokens = set()
        self.data_access_roles_etag = None

        while True:
            params = (
                {"continuationToken": unquote(continuation_token)}
                if continuation_token
                else None
            )
            response = self.rest_api_proxy.get(endpoint=uri, params=params)
            if self.data_access_roles_etag is None:
                self.data_access_roles_etag = response.headers.get("ETag")
            payload = response.json()
            if not isinstance(payload, dict) or "value" not in payload:
                raise ValueError(
                    "Fabric Data Access Roles response is missing a value collection."
                )
            page_roles = payload["value"]
            if not isinstance(page_roles, list):
                raise ValueError(
                    "Fabric Data Access Roles response has a non-list value."
                )
            roles.extend(page_roles)

            continuation_token = payload.get("continuationToken")
            if not continuation_token:
                break
            if not isinstance(continuation_token, str):
                raise ValueError(
                    "Fabric Data Access Roles response has an invalid "
                    "continuationToken."
                )
            if continuation_token in seen_tokens:
                raise ValueError(
                    "Fabric data access role pagination cycle detected for "
                    f"continuation token: {continuation_token}"
                )
            seen_tokens.add(continuation_token)

        return {"value": roles}

    def get_workspace_name(self) -> str:
        """
        Retrieves the display name of the Fabric workspace.
        Returns:
            str: The display name of the Fabric workspace.
        """
        response = self.rest_api_proxy.get(
            endpoint=self.__get_workspace_uri__("")
        ).json()
        return response["displayName"]
