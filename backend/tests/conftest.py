import os

# The app builds its singletons at import time: keep them off the disk
os.environ.setdefault("DB_PATH", ":memory:")
os.environ.setdefault("TOR_EXIT_LIST", "false")

# Timestamps with an offset are converted to the process's local time:
# pin it so the expected values do not depend on the machine running the tests
import time

os.environ["TZ"] = "UTC"
time.tzset()
