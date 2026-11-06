import json
from importlib.metadata import PackageNotFoundError

import pytest

from external_sandbox_quicksand import images


def test_default_and_explicit_packages_always_include_requirements():
    assert images.parse_packages(None) == ("bash", "git", "python3", "ripgrep")
    assert images.parse_packages("") == ("bash", "python3")
    assert images.parse_packages(" jq, nodejs ,jq") == ("bash", "jq", "nodejs", "python3")
    for bad in ("bash;rm -rf /", "-x", "UPPER", "a b"):
        with pytest.raises(ValueError, match="Invalid Alpine package"):
            images.parse_packages(bad)


def test_identity_tracks_quicksand_image_and_packages():
    identity = images.alpine_identity(images.parse_packages(None))
    assert identity["base"] == "alpine" and identity["buildhash"]
    assert identity["quicksandAlpine"] and identity["arch"] in ("arm64", "amd64")
    other = images.alpine_identity(images.parse_packages("jq"))
    assert images.alpine_key(identity) == images.alpine_key(dict(identity))
    assert images.alpine_key(identity) != images.alpine_key(other)


async def test_cached_alpine_save_is_reused_without_booting(tmp_path, monkeypatch):
    identity = {"distribution": "3.23", "arch": "arm64", "packages": ["bash", "python3"], "schema": 1}
    monkeypatch.setattr(images, "alpine_identity", lambda packages: identity)
    prepared = []

    async def prepare(found, target, accel):
        prepared.append(target)
        target.mkdir(parents=True)
        (target / images.METADATA).write_text(json.dumps(found))

    monkeypatch.setattr(images, "prepare_alpine", prepare)
    first = await images.resolve_image("alpine", "", tmp_path)
    second = await images.resolve_image("alpine", "", tmp_path)
    assert first == second and len(prepared) == 1
    assert first.reference.startswith(str(tmp_path / "images" / "alpine-3.23-arm64-"))
    assert first.label == "alpine-3.23+bash,python3"


async def test_ubuntu_is_optional_and_takes_no_packages(monkeypatch):
    with pytest.raises(ValueError, match="only to the prepared Alpine"):
        await images.resolve_image("ubuntu", "git")

    def missing(name):
        raise PackageNotFoundError(name)

    monkeypatch.setattr(images, "version", missing)
    with pytest.raises(ValueError, match="--group ubuntu"):
        await images.resolve_image("ubuntu")


async def test_other_images_pass_through(tmp_path):
    assert (await images.resolve_image("my-save")).reference == "my-save"
    save = tmp_path / "save"
    save.mkdir()
    assert (await images.resolve_image(str(save))).reference == str(save)


def test_cache_root_honours_override_and_xdg(monkeypatch, tmp_path):
    assert images.cache_root(tmp_path) == tmp_path
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert images.cache_root() == tmp_path / "xdg" / "external-sandbox-quicksand"
