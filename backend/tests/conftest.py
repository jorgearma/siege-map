import os

# The app builds its singletons at import time: keep them off the disk
os.environ.setdefault("DB_PATH", ":memory:")
os.environ.setdefault("TOR_EXIT_LIST", "false")
