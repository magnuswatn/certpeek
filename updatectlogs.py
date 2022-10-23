#!/usr/bin/env python3
"""
Update the list of known CT logs

Run it like this:
> ./updatectlogs.py | black -
"""
import hashlib
from base64 import b64decode, b64encode
from operator import itemgetter

import httpx

from certpeek import KNOWN_LOGS


def main() -> None:
    resp = httpx.get("https://www.gstatic.com/ct/log_list/v3/log_list.json")
    resp.raise_for_status()
    js = resp.json()

    logs = [log for operator in js["operators"] for log in operator["logs"]]

    for log in logs:
        sha256 = hashlib.sha256()
        log_desc = log.get("description")
        log_key = b64decode(log.get("key"))
        sha256.update(log_key)
        log_id = b64encode(sha256.digest()).decode()
        KNOWN_LOGS.update({log_id: log_desc})

    print("KNOWN_LOGS=", end="")
    print({id: desc for id, desc in sorted(KNOWN_LOGS.items(), key=itemgetter(1))})


if __name__ == "__main__":
    main()
