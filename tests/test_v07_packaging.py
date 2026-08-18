from pathlib import Path
import vais


def test_bundled_mcp_profile_is_present_in_package_tree():
    package_root = Path(vais.__file__).resolve().parent
    assert (package_root / "data" / "mcp_example_profile.yaml").is_file()
