
import os
import requests
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional

class NamecheapAPIError(Exception):
    """Raised when Namecheap API returns an error."""

    def __init__(self, message: str, code: Optional[str] = None):
        super().__init__(message)
        self.code = code


class NamecheapClient:
    """
    Minimal Namecheap API client.

    This version is designed to be instantiated with explicit credentials
    (as you are doing in app.py), e.g.:

        client = NamecheapClient(
            api_user=...,
            api_key=...,
            username=...,
            client_ip=...,
            sandbox=False,
        )

    It currently implements:
      - get_domain_list(): list domains using namecheap.domains.getList
    """

    def __init__(
        self,
        api_user: str,
        api_key: str,
        username: str,
        client_ip: str,
        sandbox: bool = False,
        api_url: Optional[str] = None,
    ):
        missing = []
        if not api_user:
            missing.append("api_user")
        if not api_key:
            missing.append("api_key")
        if not username:
            missing.append("username")
        if not client_ip:
            missing.append("client_ip")

        if missing:
            raise NamecheapAPIError(
                "Missing Namecheap credentials: " + ", ".join(missing)
            )

        self.api_user = api_user
        self.api_key = api_key
        self.username = username
        self.client_ip = client_ip

        if api_url:
            self.base_url = api_url
        else:
            self.base_url = (
                "https://api.sandbox.namecheap.com/xml.response"
                if sandbox
                else "https://api.namecheap.com/xml.response"
            )

        # Debug fields
        self.last_params: Dict = {}
        self.last_response_text: str = ""
        self.last_status: Optional[str] = None
        self.last_error: Optional[str] = None

    def _request(self, command: str, extra: Dict = None) -> ET.Element:
        if extra is None:
            extra = {}

        params = {
            "ApiUser": self.api_user,
            "ApiKey": self.api_key,
            "UserName": self.username,
            "ClientIp": self.client_ip,
            "Command": command,
            "ResponseType": "XML",
        }
        params.update(extra)

        # Do not store ApiKey in debug
        self.last_params = {k: v for k, v in params.items() if k != "ApiKey"}

        try:
            resp = requests.get(self.base_url, params=params, timeout=15)
        except requests.RequestException as e:
            self.last_status = "HTTP_ERROR"
            self.last_error = str(e)
            raise NamecheapAPIError(f"HTTP error calling Namecheap API: {e}")

        self.last_response_text = resp.text

        try:
            root = ET.fromstring(resp.text)
        except ET.ParseError as e:
            self.last_status = "PARSE_ERROR"
            self.last_error = f"XML parse error: {e}"
            raise NamecheapAPIError(f"Failed to parse Namecheap XML response: {e}")

        status = root.attrib.get("Status")
        self.last_status = status or "UNKNOWN"

        # Handle Namecheap namespace
        ns = {"nc": "http://api.namecheap.com/xml.response"}

        if status != "OK":
            errors = root.findall(".//nc:Errors/nc:Error", ns)
            if errors:
                err = errors[0]
                code = err.attrib.get("Number")
                msg = (err.text or "").strip()
                full = f"{code} {msg}" if code else msg or "Unknown Namecheap API error"
                self.last_error = full
                raise NamecheapAPIError(full, code=code)

            self.last_error = "Unknown Namecheap API error"
            raise NamecheapAPIError("Unknown Namecheap API error")

        self.last_error = None
        return root

    def get_domain_list(self) -> List[Dict]:
        """
        Calls namecheap.domains.getList and returns:

        [
          {"Name": "...", "Expires": "...", "IsOurDNS": "true"/"false"},
          ...
        ]
        """
        root = self._request(
            "namecheap.domains.getList",
            {
                "PageSize": 100,
                "Page": 1,
                "ListType": "ALL",
                "SortBy": "NAME",
            },
        )
        ns = {"nc": "http://api.namecheap.com/xml.response"}
        result = root.find(".//nc:DomainGetListResult", ns)
        if result is None:
            return []

        domains: List[Dict] = []
        for d in result.findall("nc:Domain", ns):
            attrs = d.attrib
            domains.append(
                {
                    "Name": attrs.get("Name"),
                    "Expires": attrs.get("Expires"),
                    "IsOurDNS": attrs.get("IsOurDNS"),
                }
            )

        return domains

    def get_debug_snapshot(self) -> Dict:
        snippet = self.last_response_text[:400] if self.last_response_text else ""
        return {
            "api_url": self.base_url,
            "last_command": self.last_params.get("Command"),
            "last_status": self.last_status,
            "last_error": self.last_error,
            "last_params": self.last_params,
            "last_response_snippet": snippet.replace("\n", "\\n"),
        }
