"""路径与默认值（单一来源）。

以前这些常量散在 server.py 里；产品收敛成单 CLI 后，它们只该有一份出处。
"""

from __future__ import annotations

import os
import shutil

DEFAULT_INBOXES = ["~/pentest-inbox", "~/pentest", "~/pentest-assets"]


def default_db_path() -> str:
    """默认库：~/.kara/vuln.db。

    改过两次名，老库依次在 ~/.sixeyes/vuln.db 与 ~/.acumen/vuln.db。
    新库不存在时按新→旧顺序挑第一个有数据的搬过来，连 -wal/-shm 一起搬——
    只搬 .db 会把 WAL 里没 checkpoint 的命中丢掉。搬不动就原地用老库。
    """
    new = os.path.expanduser("~/.kara/vuln.db")
    if os.path.exists(new):
        return new
    for legacy in ("~/.sixeyes/vuln.db", "~/.acumen/vuln.db"):
        old = os.path.expanduser(legacy)
        if not os.path.exists(old):
            continue
        try:
            os.makedirs(os.path.dirname(new), exist_ok=True)
            for suffix in ("", "-wal", "-shm"):
                if os.path.exists(old + suffix):
                    shutil.copy2(old + suffix, new + suffix)
            return new
        except OSError:
            return old
    return new
