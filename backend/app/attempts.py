"""
Turn SSH log LINES into authentication ATTEMPTS.

One login try produces several lines, and which ones depends on the server:

  password auth enabled      Invalid user x from IP          (announcement)
                             Failed password for invalid user x from IP   (xN)
  password auth disabled     Invalid user x from IP
                             Connection closed by invalid user x IP [preauth]
  valid user, keys only      Connection closed by authenticating user root IP [preauth]

Counting lines would count the same try two or three times; deduplicating by
minute (what the store does for the live feed) would count a 20-tries-per-minute
brute force as one. So:

  * every "Failed password" is one attempt (one password was really tried)
  * any other line about a user is one attempt only if nothing was counted
    for that (ip, user) in the last few seconds
  * the "Failed password" that follows an already-counted "Invalid user"
    is the same try, so it uses up that credit instead of counting again
"""
from collections import OrderedDict

WINDOW_SECONDS = 5.0
_MAX_TRACKED = 20000

# Lines that tell us a user was tried
_USER_EVENTS = {"invalid_user", "connection_closed", "disconnected", "max_auth_exceeded"}


class AttemptCounter:
    def __init__(self, window: float = WINDOW_SECONDS):
        self.window = window
        # (ip, user) -> [last_counted_ts, credit]
        self._state: OrderedDict[tuple[str, str], list] = OrderedDict()

    def is_attempt(self, ip: str, username: str, event_type: str, ts: float) -> bool:
        if not username or username == "(none)":
            return False
        if event_type != "failed_password" and event_type not in _USER_EVENTS:
            return False

        key = (ip, username)
        state = self._state.get(key)
        recent = state is not None and 0 <= ts - state[0] <= self.window

        if event_type == "failed_password":
            if recent and state[1] > 0:
                state[1] -= 1          # same try as the line counted just before
                state[0] = ts
                return False
            self._remember(key, ts, credit=0)
            return True

        if recent:
            return False
        # "Invalid user" is followed by its own "Failed password": give it a credit
        self._remember(key, ts, credit=1 if event_type == "invalid_user" else 0)
        return True

    def _remember(self, key, ts: float, credit: int) -> None:
        self._state[key] = [ts, credit]
        self._state.move_to_end(key)
        while len(self._state) > _MAX_TRACKED:
            self._state.popitem(last=False)


attempt_counter = AttemptCounter()
