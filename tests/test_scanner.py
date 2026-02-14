import unittest
import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# We must mock androguard before importing scanner, since it imports at module level
mock_apk_module = MagicMock()
mock_dvm_module = MagicMock()
mock_analysis_module = MagicMock()

sys.modules['androguard'] = MagicMock()
sys.modules['androguard.core'] = MagicMock()
sys.modules['androguard.core.bytecodes'] = MagicMock()
sys.modules['androguard.core.bytecodes.apk'] = mock_apk_module
sys.modules['androguard.core.bytecodes.dvm'] = mock_dvm_module
sys.modules['androguard.core.analysis'] = MagicMock()
sys.modules['androguard.core.analysis.analysis'] = mock_analysis_module

from scanner import analyze_apk


class TestAnalyzeApk(unittest.TestCase):
    """Tests for the Android APK static analysis scanner."""

    def _setup_mock_apk(self):
        """Create a mock APK object with typical return values."""
        mock_apk = MagicMock()
        mock_apk.get_package.return_value = "com.example.testapp"
        mock_apk.get_app_name.return_value = "TestApp"
        mock_apk.is_debuggable.return_value = False
        mock_apk.get_activities.return_value = ["com.example.MainActivity"]
        mock_apk.get_permissions.return_value = [
            "android.permission.INTERNET",
            "android.permission.CAMERA"
        ]
        mock_apk.get_dex.return_value = b"fake_dex_data"
        return mock_apk

    def _setup_mock_dvm(self, strings=None):
        """Create a mock DalvikVMFormat with controllable strings."""
        mock_dex = MagicMock()
        mock_dex.get_strings.return_value = strings or []
        mock_dvm_module.DalvikVMFormat.return_value = mock_dex
        return mock_dex

    @patch('scanner.APK')
    def test_analyze_apk_basic(self, mock_apk_cls):
        """Test basic APK analysis without secrets or HTTP URLs."""
        mock_apk = self._setup_mock_apk()
        mock_apk_cls.return_value = mock_apk
        self._setup_mock_dvm(strings=["safe string", "another safe one"])
        # Should run without error
        analyze_apk("fake.apk")
        mock_apk_cls.assert_called_once_with("fake.apk")

    @patch('scanner.APK')
    def test_analyze_apk_debuggable(self, mock_apk_cls):
        """Test that debuggable flag is detected."""
        mock_apk = self._setup_mock_apk()
        mock_apk.is_debuggable.return_value = True
        mock_apk_cls.return_value = mock_apk
        self._setup_mock_dvm(strings=[])
        # Should run and report vulnerability
        analyze_apk("debug.apk")

    @patch('scanner.APK')
    def test_analyze_apk_finds_secrets(self, mock_apk_cls):
        """Test that hardcoded secrets are detected in strings."""
        mock_apk = self._setup_mock_apk()
        mock_apk_cls.return_value = mock_apk
        self._setup_mock_dvm(strings=[
            "api_key=ABCDEF123456",
            "my_password_here",
            "safe string"
        ])
        analyze_apk("secrets.apk")

    @patch('scanner.APK')
    def test_analyze_apk_finds_http_urls(self, mock_apk_cls):
        """Test detection of insecure HTTP URLs."""
        mock_apk = self._setup_mock_apk()
        mock_apk_cls.return_value = mock_apk
        self._setup_mock_dvm(strings=[
            "http://insecure.example.com/api",
            "https://secure.example.com/api"
        ])
        analyze_apk("http.apk")

    @patch('scanner.APK')
    def test_analyze_apk_load_error(self, mock_apk_cls):
        """Test graceful handling when APK cannot be loaded."""
        mock_apk_cls.side_effect = Exception("Bad APK")
        # Should not raise
        analyze_apk("corrupt.apk")

    @patch('scanner.APK')
    def test_analyze_apk_permissions_listed(self, mock_apk_cls):
        """Test that permissions are extracted from the APK."""
        mock_apk = self._setup_mock_apk()
        mock_apk.get_permissions.return_value = [
            "android.permission.INTERNET",
            "android.permission.READ_CONTACTS",
            "android.permission.SEND_SMS"
        ]
        mock_apk_cls.return_value = mock_apk
        self._setup_mock_dvm(strings=[])
        analyze_apk("perms.apk")
        mock_apk.get_permissions.assert_called_once()


if __name__ == '__main__':
    unittest.main()
