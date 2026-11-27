"""The owner's signed statement on the publishing side: printed, signed, and required."""

from __future__ import annotations

from pathlib import Path

import pytest

from public_release_publish_fixtures import (
    FakePublicReleaseAPI,
    MemoryReceiptStore,
    PUBLISHER,
    bundle,
    signature_for,
)
from release_fixtures import load_script
from release_signing import TEST_KEY, ReleaseKey
from strugglebus import release_signature

STATEMENT_SCRIPT = load_script("release_statement")


def prepared(tmp_path: Path):
    directory, commit, tree, version = bundle(tmp_path)
    tag = "v" + version
    api = FakePublicReleaseAPI(directory, tag=tag, commit=commit, tree=tree)
    return directory, commit, tree, tag, api, MemoryReceiptStore()


def publish(api, store, directory, *, commit, tree, tag, signature):
    return PUBLISHER.publish_public_release(
        api, store, directory, tag=tag, commit=commit, tree=tree,
        public_anchor_commit=api.public_head, approval=PUBLISHER.approval_phrase(tag, commit),
        resume=False, signature=signature,
    )


def test_the_printed_statement_is_the_one_the_publisher_expects_signed(tmp_path, capsysbinary):
    directory, commit, tree, tag, _api, _store = prepared(tmp_path)

    statement = STATEMENT_SCRIPT.statement_for(directory, tag)

    lines = statement.splitlines()
    assert lines[:2] == ["strugglebus-bus-release 1", f"version {tag[1:]}"]
    assert [line.split("  ")[1] for line in lines[2:]] == sorted(path.name for path in directory.iterdir())
    assert "\r" not in statement and statement.endswith("\n")
    # Signing exactly what was printed is what the publisher accepts.
    signed = PUBLISHER.signed_statement(
        tag, PUBLISHER._local_assets(directory, tag, commit, tree), TEST_KEY.sign(statement.encode()),
    )
    assert signed.startswith(statement)

    assert STATEMENT_SCRIPT.main([str(directory), "--tag", tag]) == 0
    assert capsysbinary.readouterr().out == statement.encode()
    output = tmp_path / "statement.txt"
    assert STATEMENT_SCRIPT.main([str(directory), "--tag", tag, "--output", str(output)]) == 0
    assert output.read_bytes() == statement.encode()


def test_the_statement_script_refuses_a_bad_tag_or_an_empty_folder(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(SystemExit, match="is not a release tag"):
        STATEMENT_SCRIPT.statement_for(tmp_path / "empty", "0.2.72")
    with pytest.raises(SystemExit, match="holds no release files"):
        STATEMENT_SCRIPT.statement_for(tmp_path / "empty", "v0.2.72")


def test_a_signed_release_is_published_with_the_statement_in_its_tag(tmp_path):
    directory, commit, tree, tag, api, store = prepared(tmp_path)
    signature = signature_for(directory, commit=commit, tree=tree, tag=tag)

    publish(api, store, directory, commit=commit, tree=tree, tag=tag, signature=signature)

    message = api.public_tag_object["message"]
    assert message.startswith("Strugglebus public release mirror v1\n")
    # An installed bus reads the files' hashes out of that message, and they are these files'.
    digests = release_signature.signed_digests(message, tag[1:])
    assert digests == {
        name: asset.digest for name, asset in PUBLISHER._local_assets(directory, tag, commit, tree).items()
    }


@pytest.mark.parametrize("signature", [
    lambda directory, **release: "",
    lambda directory, **release: "not a signature",
    lambda directory, **release: ReleaseKey().sign(
        release_signature.release_statement(release["tag"][1:], {"x": "0" * 64}).encode(),
    ),
    lambda directory, **release: TEST_KEY.sign(b"strugglebus-bus-release 1\nversion 9.9.9\n"),
], ids=["none", "not a signature", "by someone else", "of another statement"])
def test_nothing_is_published_without_the_owners_signature_of_these_files(tmp_path, signature):
    directory, commit, tree, tag, api, store = prepared(tmp_path)

    with pytest.raises(PUBLISHER.PublicReleaseError, match="not signed by a release key"):
        publish(
            api, store, directory, commit=commit, tree=tree, tag=tag,
            signature=signature(directory, commit=commit, tree=tree, tag=tag),
        )

    assert api.mutations == []


def test_a_signature_by_a_key_that_is_not_pinned_is_refused_even_for_the_right_statement(tmp_path):
    directory, commit, tree, tag, api, store = prepared(tmp_path)
    assets = PUBLISHER._local_assets(directory, tag, commit, tree)
    statement = release_signature.release_statement(tag[1:], {name: asset.digest for name, asset in assets.items()})

    with pytest.raises(PUBLISHER.PublicReleaseError, match="not signed by a release key"):
        publish(api, store, directory, commit=commit, tree=tree, tag=tag, signature=ReleaseKey().sign(statement.encode()))
    assert api.mutations == []
