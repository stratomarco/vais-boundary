from pathlib import Path

def test_v08_mcp_corpus_is_present_in_source_tree():
    path = Path(__file__).parents[1] / "src" / "vais" / "data" / "mcp_static_v0_8_125.jsonl"
    assert path.exists()
    assert len(path.read_text(encoding="utf-8").splitlines()) == 125
