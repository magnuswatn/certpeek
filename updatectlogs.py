#!/usr/bin/env python3
"""
Update the list of known CT logs

Run it like this:
> ./updatectlogs.py
"""

import hashlib
import re
import subprocess
from base64 import b64decode, b64encode
from operator import itemgetter
from pathlib import Path

import httpx

from certpeek import KNOWN_LOGS

CERTPEEK_SOURCE_FILE = Path("certpeek.py")


def main() -> None:
    resp = httpx.get("https://www.gstatic.com/ct/log_list/v3/log_list.json")
    resp.raise_for_status()
    js = resp.json()

    logs = [
        log
        for operator in js["operators"]
        for log in operator["logs"] + operator["tiled_logs"]
    ]

    for log in logs:
        sha256 = hashlib.sha256()
        log_desc = log.get("description")
        log_key = b64decode(log.get("key"))
        sha256.update(log_key)
        log_id = b64encode(sha256.digest()).decode()
        if log_id in (
            "LtakTeuPDIZGZ3acTt0EH4QjZ1X6OqymNNCTXfzVmnA=",
            "0vxlL6X5tzi4N1X6XrFfC0UlP06Po7m2T9TeVmLRhwg=",
        ):
            # Bogus placeholder logs to unbreak misbehaving CT libraries
            continue
        KNOWN_LOGS.update({log_id: log_desc})

    unformatted_new_known_logs_list = "KNOWN_LOGS="
    unformatted_new_known_logs_list += str(
        dict(sorted(KNOWN_LOGS.items(), key=itemgetter(1)))
    )
    new_known_logs_list = subprocess.check_output(
        ["ruff", "format", "--stdin-filename", "ctlist.py"],  # noqa: S607
        input=unformatted_new_known_logs_list,
        text=True,
    )

    certpeek_source = CERTPEEK_SOURCE_FILE.read_text()
    new_certpeek_source = re.sub(
        r"KNOWN_LOGS = {[^}]+}\n", new_known_logs_list, certpeek_source
    )
    CERTPEEK_SOURCE_FILE.write_text(new_certpeek_source)


if __name__ == "__main__":
    main()
