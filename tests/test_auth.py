import pytest

from precogly_toolkit.auth import MissingCredentialsError, local_login_payload


def test_explicit_local_credentials():
    assert local_login_payload({"LOCAL_PRECOGLY_EMAIL": " user ", "LOCAL_PRECOGLY_PASSWORD": " pw "}) == {
        "email": "user", "password": " pw "
    }


@pytest.mark.parametrize("env", [
    {}, {"LOCAL_PRECOGLY_EMAIL": "user"}, {"LOCAL_PRECOGLY_PASSWORD": "pw"},
    {"LOCAL_PRECOGLY_EMAIL": " ", "LOCAL_PRECOGLY_PASSWORD": "pw"},
    {"LOCAL_PRECOGLY_EMAIL": "user", "LOCAL_PRECOGLY_PASSWORD": ""},
])
def test_missing_credentials_fail_closed(env):
    with pytest.raises(MissingCredentialsError, match="LOCAL_PRECOGLY_EMAIL"):
        local_login_payload(env)


def test_environment_binding(monkeypatch):
    monkeypatch.setenv("LOCAL_PRECOGLY_EMAIL", "user")
    monkeypatch.setenv("LOCAL_PRECOGLY_PASSWORD", "pw")
    assert local_login_payload() == {"email": "user", "password": "pw"}
