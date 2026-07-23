# tests/unit/test_yara_scanner.py
import pytest
from unittest.mock import patch, MagicMock
import yara_scanner
from yara_scanner import YaraScanner
import hashlib

# Inject mock yara module if not available
if not yara_scanner._YARA_AVAILABLE:
    yara_scanner.yara = MagicMock()

@pytest.fixture
def scanner(tmp_path):
    # Mocking YARA availability
    with patch("yara_scanner._YARA_AVAILABLE", True):
        mock_yara = yara_scanner.yara
        
        # Setup a fake rule file
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "test.yar").write_text('rule Test { condition: true }')

        # Mock the compile function to return a mock Rules object
        mock_rules = MagicMock()
        mock_yara.compile.return_value = mock_rules

        # Create scanner
        scanner = YaraScanner(str(rules_dir))
        
        # Inject the mocked rules object explicitly because of how patch works
        scanner._rules = mock_rules
        yield scanner

class TestYaraScanner:
    def test_scan_non_existent_file(self, scanner):
        assert scanner.scan("/does/not/exist.txt") is None

    def test_scan_unreadable_file(self, scanner, tmp_path):
        test_file = tmp_path / "unreadable.txt"
        test_file.write_text("secret")
        
        # Patch read_bytes to simulate permission error
        with patch.object(type(test_file), "read_bytes", side_effect=PermissionError):
            with patch("yara_scanner.Path", return_value=test_file):
                assert scanner.scan(str(test_file)) is None

    def test_scan_no_match(self, scanner, tmp_path):
        test_file = tmp_path / "clean.txt"
        test_file.write_text("clean content")
        
        scanner._rules.match.return_value = []
        assert scanner.scan(str(test_file)) is None

    def test_scan_match(self, scanner, tmp_path):
        test_file = tmp_path / "malware.exe"
        content = b"malicious payload"
        test_file.write_bytes(content)
        
        mock_match = MagicMock()
        mock_match.rule = "MAL_Test_Rule"
        scanner._rules.match.return_value = [mock_match]

        result = scanner.scan(str(test_file))
        assert result is not None
        assert result["rule_name"] == "MAL_Test_Rule"
        assert result["file_path"] == str(test_file)
        assert result["file_hash"] == "md5:" + hashlib.md5(content).hexdigest()
        assert result["ruleset"] == "neo23x0/signature-base"

    def test_yara_not_available(self, tmp_path):
        with patch("yara_scanner._YARA_AVAILABLE", False):
            scanner = YaraScanner(str(tmp_path))
            assert scanner._rules is None
            
            test_file = tmp_path / "test.txt"
            test_file.write_text("test")
            assert scanner.scan(str(test_file)) is None
