import os
import sys

CONFIG_PATH = os.path.expanduser("~/.rshade/config")

class Config:
    def __init__(self, api_key: str):
        self.api_key = api_key

def load_config(api_key_override: str = None) -> Config:
    api_key = api_key_override

    if not api_key:
        api_key = os.environ.get("SHODAN_API_KEY")

    if not api_key and os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            for line in f:
                line = line.strip()
                if line.startswith("api_key="):
                    api_key = line.split("=", 1)[1].strip()
                    break

    if not api_key:
        print("[!] No Shodan API key found.")
        print("    Set it via:")
        print("      export SHODAN_API_KEY=your_key")
        print("      or --api-key flag")
        print(f"      or add 'api_key=your_key' to {CONFIG_PATH}")
        sys.exit(1)

    return Config(api_key=api_key)