import shodan
import sys
from typing import Optional

class ShodanClient:
    def __init__(self, api_key: str):
        self.api = shodan.Shodan(api_key)
        self._verify()

    def _verify(self):
        try:
            self.api.info()
        except shodan.APIError as e:
            print(f"[!] Shodan API error: {e}")
            sys.exit(1)

    def host(self, ip: str) -> Optional[dict]:
        try:
            return self.api.host(ip)
        except shodan.APIError as e:
            if "No information available" in str(e):
                return None
            print(f"[!] Error querying {ip}: {e}")
            return None