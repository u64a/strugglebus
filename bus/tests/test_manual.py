from __future__ import annotations

import re
from pathlib import Path

import pytest

from release_fixtures import load_script


KIT = Path(__file__).resolve().parents[1] / "src" / "strugglebus" / "selfhost"
MANUAL = KIT / "manual"
PAGES = sorted(MANUAL.glob("*.md"))
PUBLISH = load_script("publish_public_docs")

LINK = re.compile(r"\[[^\]]+\]\(([^)\s]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.*)$", re.MULTILINE)


def anchors(path: Path) -> set[str]:
    """Heading anchors as GitHub makes them."""
    found = set()
    for title in HEADING.findall(path.read_text(encoding="utf-8")):
        slug = re.sub(r"[^\w\- ]", "", title.strip().lower()).replace(" ", "-")
        found.add(slug)
    return found


def test_the_manual_has_its_pages_and_an_index_that_lists_them() -> None:
    names = {page.name for page in PAGES}
    assert names == {
        "README.md", "console.md", "windows-app.md", "channels.md", "agents.md",
        "for-agents.md", "upkeep.md", "troubleshooting.md",
    }
    index = (MANUAL / "README.md").read_text(encoding="utf-8")
    for name in names - {"README.md"}:
        assert f"]({name})" in index, name


@pytest.mark.parametrize("page", PAGES, ids=lambda page: page.name)
def test_every_link_in_a_page_leads_somewhere(page: Path) -> None:
    text = page.read_text(encoding="utf-8")
    assert "\r" not in text
    for target in LINK.findall(text):
        if target.startswith(("https://", "http://")):
            continue
        name, _, anchor = target.partition("#")
        linked = (page.parent / name).resolve() if name else page
        assert linked.is_file(), f"{page.name}: {target} does not exist"
        if anchor:
            assert anchor in anchors(linked), f"{page.name}: no heading for {target}"


@pytest.mark.parametrize("page", PAGES, ids=lambda page: page.name)
def test_every_page_but_the_index_links_back_to_it(page: Path) -> None:
    if page.name != "README.md":
        assert "[Back to the manual](README.md)" in page.read_text(encoding="utf-8")


def _source(tmp_path: Path) -> Path:
    root = tmp_path / "source"
    manual = root / "src" / "strugglebus" / "selfhost" / "manual"
    manual.mkdir(parents=True)
    (manual / "README.md").write_text("# Manual\n", encoding="utf-8")
    (manual / "console.md").write_text("# Console\n", encoding="utf-8")
    (manual.parent / "INSTALL.md").write_text("# Install\n", encoding="utf-8")
    (root / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    return root


def _checkout(tmp_path: Path) -> Path:
    target = tmp_path / "public"
    (target / ".git").mkdir(parents=True)
    return target


def test_publish_writes_the_guide_twice_and_the_manual_under_docs(tmp_path: Path) -> None:
    root, target = _source(tmp_path), _checkout(tmp_path)

    written = PUBLISH.publish(root, target)

    assert written == [
        "INSTALL.md", "SECURITY.md", "docs/INSTALL.md",
        "docs/manual/README.md", "docs/manual/console.md",
    ]
    assert (target / "INSTALL.md").read_text(encoding="utf-8") == "# Install\n"
    assert (target / "docs" / "INSTALL.md").read_text(encoding="utf-8") == "# Install\n"
    assert (target / "docs" / "manual" / "console.md").read_text(encoding="utf-8") == "# Console\n"


def test_the_root_copy_of_the_guide_links_to_the_manual_where_it_is_published(tmp_path: Path) -> None:
    root, target = _source(tmp_path), _checkout(tmp_path)
    guide = root / "src" / "strugglebus" / "selfhost" / "INSTALL.md"
    guide.write_text("See [the manual](manual/README.md).", encoding="utf-8")

    PUBLISH.publish(root, target)

    assert "](docs/manual/README.md)" in (target / "INSTALL.md").read_text(encoding="utf-8")
    assert "](manual/README.md)" in (target / "docs" / "INSTALL.md").read_text(encoding="utf-8")


def test_the_real_guide_links_to_the_manual() -> None:
    assert "](manual/README.md)" in (KIT / "INSTALL.md").read_text(encoding="utf-8")


def test_publish_removes_a_page_that_left_the_manual_and_keeps_other_files(tmp_path: Path) -> None:
    root, target = _source(tmp_path), _checkout(tmp_path)
    old = target / "docs" / "manual" / "old-page.md"
    old.parent.mkdir(parents=True)
    old.write_text("gone", encoding="utf-8")
    (target / "README.md").write_text("kept", encoding="utf-8")

    PUBLISH.publish(root, target)

    assert not old.exists()
    assert (target / "README.md").read_text(encoding="utf-8") == "kept"


def test_publish_refuses_a_folder_that_is_not_a_checkout(tmp_path: Path) -> None:
    root = _source(tmp_path)
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(NotADirectoryError):
        PUBLISH.publish(root, plain)


def test_publish_refuses_a_source_with_no_manual(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        PUBLISH.plan(tmp_path)


def test_the_command_lists_what_it_wrote(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root, target = _source(tmp_path), _checkout(tmp_path)

    assert PUBLISH.main([str(target), "--root", str(root)]) == 0

    output = capsys.readouterr().out
    assert "docs/manual/README.md" in output
    assert "review, commit and push" in output
