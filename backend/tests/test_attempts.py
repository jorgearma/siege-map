from app.attempts import AttemptCounter

IP = "8.8.8.8"


def count(lines):
    c = AttemptCounter()
    return sum(c.is_attempt(IP, user, etype, ts) for user, etype, ts in lines)


def test_invalid_user_then_failed_password_is_one_try():
    assert count([("admin", "invalid_user", 0), ("admin", "failed_password", 1)]) == 1


def test_every_extra_password_counts():
    lines = [("admin", "invalid_user", 0)] + [("admin", "failed_password", i) for i in (1, 2, 3)]
    assert count(lines) == 3


def test_brute_force_same_minute_is_not_collapsed():
    assert count([("root", "failed_password", i * 2) for i in range(20)]) == 20


def test_password_auth_disabled_server():
    # only announcement + close: one try
    assert count([("pi", "invalid_user", 0), ("pi", "connection_closed", 0.5)]) == 1


def test_valid_user_keys_only():
    assert count([("root", "connection_closed", 0)]) == 1


def test_lines_without_user_are_not_attempts():
    assert count([("(none)", "received_disconnect", 0), ("", "bad_protocol", 1)]) == 0


def test_separate_tries_over_time():
    assert count([("pi", "invalid_user", 0), ("pi", "invalid_user", 60)]) == 2


def test_different_users_do_not_share_state():
    assert count([("a", "invalid_user", 0), ("b", "invalid_user", 0)]) == 2
