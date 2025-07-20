import pytest

import yara_scanner

@pytest.mark.unit
def test_basic_yara_scan(datadir):
    scanner = yara_scanner.YaraScanner(signature_dir=str(datadir / "yara_rules"))
    scanner.load_rules()
    target_file = str(datadir / "sample.target")
    result = scanner.scan(target_file)
