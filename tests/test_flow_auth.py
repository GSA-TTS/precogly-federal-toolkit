import pytest

from precogly_toolkit.flow_auth import load_auth_catalog, load_auth_metadata, auth_mechanism_properties


def test_explicit_catalog_with_overrides(tmp_path):
    path = tmp_path / "auth.yaml"
    path.write_text("version: 1\nallowed: [tls]\nmetadata:\n  tls:\n    nist: [SC-8]\n")
    assert load_auth_catalog(path=path, arch={"auth_mechanisms": {"allowed": ["local"]}}) == ({"tls", "local"}, {})
    metadata = load_auth_metadata(path=path)
    assert auth_mechanism_properties("tls", metadata=metadata)[1]["value"] == "SC-8"


def test_missing_catalog_fails_without_private_defaults():
    with pytest.raises(ValueError, match="explicit"):
        load_auth_catalog()


def test_bad_catalog_version_fails(tmp_path):
    path = tmp_path / "auth.yaml"
    path.write_text("version: 2\n")
    with pytest.raises(ValueError, match="version"):
        load_auth_metadata(path=path)
