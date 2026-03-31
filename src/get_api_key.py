import argparse

from ezpanos import EzPanOS


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch a PAN-OS API key via secure credential prompt.")
    parser.add_argument("--endpoint", default=None, help="Firewall/Panorama management endpoint (if omitted, prompt)")
    parser.add_argument("--username", default=None, help="Username (if omitted, prompt)")
    return parser.parse_args()


def _prompt_if_missing(value: str | None, prompt_text: str) -> str:
    if value and value.strip():
        return value.strip()
    while True:
        entered = input(prompt_text).strip()
        if entered:
            return entered


def main() -> int:
    args = parse_args()
    endpoint = _prompt_if_missing(args.endpoint, "Endpoint: ")
    username = args.username
    if username is None:
        entered = input("Username (optional, press Enter to prompt later): ").strip()
        username = entered or None

    key = EzPanOS.prompt_and_request_api_key(
        endpoint=endpoint,
        username=username,
    )
    print(key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
