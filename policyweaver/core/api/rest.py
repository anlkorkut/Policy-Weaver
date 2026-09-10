import logging
from collections.abc import Callable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class RestAPIProxy:
    """
    A class to interact with a REST API.
    This class provides methods to perform GET, POST, PUT, and DELETE requests.
    Attributes:
        logger (logging.Logger): Logger instance for logging API interactions.
        base_url (str): The base URL of the REST API.
        headers (dict): Default headers to be used in API requests.
    """

    def __init__(
        self,
        base_url: str,
        headers: dict | None = None,
        weaver_type: str | None = None,
        auth_header_provider: Callable[[bool], dict] | None = None,
        timeout: tuple[int, int] = (10, 120),
    ) -> None:
        """
        Initializes the RestAPIProxy with a base URL and optional headers.
        Args:
            base_url (str): The base URL of the REST API.
            headers (dict, optional): Default headers to be used in API requests. Defaults to None.

        Raises:
            ValueError: If the base URL is not provided.
        """
        self.logger = logging.getLogger("POLICY_WEAVER")
        self.base_url = base_url
        self.weaver_type = weaver_type if weaver_type else "UNKNOWN"
        self.auth_header_provider = auth_header_provider
        self.timeout = timeout

        self.headers = dict(headers or {})
        self.headers["User-Agent"] = f"PolicyWeaver/{self.weaver_type}"
        retry = Retry(
            total=5,
            connect=5,
            read=5,
            status=5,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(["GET", "PUT", "DELETE"]),
            respect_retry_after_header=True,
        )
        self.session = requests.Session()
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _build_headers(
        self, headers: dict | None = None, force_refresh: bool = False
    ) -> dict:
        request_headers = dict(self.headers)
        if self.auth_header_provider:
            request_headers.update(self.auth_header_provider(force_refresh))
        request_headers.update(headers or {})
        return request_headers

    def _request(
        self,
        method: str,
        endpoint: str,
        headers: dict | None = None,
        **kwargs,
    ) -> requests.Response:
        url = f"{self.base_url}/{endpoint}"
        request_headers = self._build_headers(headers)
        self.logger.debug("REST API PROXY - %s - %s", method, url)
        request = getattr(self.session, method.lower())
        response = request(
            url,
            headers=request_headers,
            timeout=self.timeout,
            **kwargs,
        )
        if response.status_code == 401 and self.auth_header_provider:
            request_headers = self._build_headers(headers, force_refresh=True)
            response = request(
                url,
                headers=request_headers,
                timeout=self.timeout,
                **kwargs,
            )
        return self._handle_response(response)

    def get(
        self, endpoint: str, params: dict | None = None, headers: dict | None = None
    ) -> requests.Response:
        """
        Performs a GET request to the specified endpoint of the REST API.
        Args:
            endpoint (str): The endpoint to which the GET request is made.
            params (dict, optional): Query parameters to be included in the request. Defaults to None.
            headers (dict, optional): Headers to be included in the request. Defaults to None.
        Returns:
            Response object: The response from the GET request.
        """
        return self._request("GET", endpoint, params=params, headers=headers)

    def post(
        self,
        endpoint: str,
        data=None,
        json=None,
        files=None,
        headers: dict | None = None,
    ) -> requests.Response:
        """
        Performs a POST request to the specified endpoint of the REST API.
        Args:
            endpoint (str): The endpoint to which the POST request is made.
            data (dict, optional): Form data to be included in the request. Defaults to None
            json (dict, optional): JSON data to be included in the request. Defaults to None.
            files (dict, optional): Files to be uploaded in the request. Defaults to None.
            headers (dict, optional): Headers to be included in the request. Defaults to None.
        Returns:
            Response object: The response from the POST request.
        """
        return self._request(
            "POST",
            endpoint,
            data=data,
            json=json,
            files=files,
            headers=headers,
        )

    def put(
        self,
        endpoint: str,
        data=None,
        json=None,
        headers: dict | None = None,
        params: dict | None = None,
    ) -> requests.Response:
        """
        Performs a PUT request to the specified endpoint of the REST API.
        Args:
            endpoint (str): The endpoint to which the PUT request is made.
            data (dict, optional): Form data to be included in the request. Defaults to None
            json (dict, optional): JSON data to be included in the request. Defaults to None.
            headers (dict, optional): Headers to be included in the request. Defaults to None.
        Returns:
            Response object: The response from the PUT request."""
        request_headers = dict(headers or {})
        request_headers["policyweaver"] = self.weaver_type
        return self._request(
            "PUT",
            endpoint,
            data=data,
            json=json,
            headers=request_headers,
            params=params,
        )

    def delete(self, endpoint: str, headers: dict | None = None) -> requests.Response:
        """
        Performs a DELETE request to the specified endpoint of the REST API.
        Args:
            endpoint (str): The endpoint to which the DELETE request is made.
            headers (dict, optional): Headers to be included in the request. Defaults to None.
        Returns:
            Response object: The response from the DELETE request.
        """
        return self._request("DELETE", endpoint, headers=headers)

    def _handle_response(self, response: requests.Response) -> requests.Response:
        """
        Handles the response from the REST API.
        Args:
            response (Response): The response object from the requests library.
        Returns:
            Response object: The response if the status code is 200, 201, or 202.
        Raises:
            HTTPError: If the response status code is not 200, 201, or 202.
        """
        self.logger.debug("REST API PROXY - RESPONSE - %s", response.status_code)
        if 200 <= response.status_code < 300:
            return response
        self.logger.error("REST API PROXY - ERROR - %s", response.status_code)
        response.raise_for_status()
