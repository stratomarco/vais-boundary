from pathlib import Path
import vais


def test_bundled_v06_corpus_is_present_in_package_tree():
    package_root = Path(vais.__file__).resolve().parent
    assert (package_root / "data" / "static_v0_6_125.jsonl").is_file()
