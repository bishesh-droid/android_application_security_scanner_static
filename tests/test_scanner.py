import unittest
import os
import sys
import io
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

    def setUp(self):
        """Reset mocks before each test to prevent state leaks."""
        mock_dvm_module.DalvikVMFormat.reset_mock()
        mock_dvm_module.DalvikVMFormat.side_effect = None

    def _setup_mock_apk(self):
        """Create a mock APK object with typical return values."""
        mock_apk = MagicMock()
        mock_apk.get_package.return_value = "com.example.testapp"
        mock_apk.get_app_name.return_value = "TestApp"
        mock_apk.is_debuggable.return_value = False
        mock_apk.get_activities.return_value = ["com.example.MainActivity"]
        mock_apk.get_services.return_value = []
        mock_apk.get_receivers.return_value = []
        mock_apk.get_providers.return_value = []
        mock_apk.get_intent_filters.return_value = {}
        mock_apk.get_permissions.return_value = [
            "android.permission.INTERNET",
            "android.permission.CAMERA"
        ]
        mock_apk.get_all_dex.return_value = [b"fake_dex_data"]
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

        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            analyze_apk("fake.apk")
            output = mock_out.getvalue()

        mock_apk_cls.assert_called_once_with("fake.apk")
        self.assertIn("com.example.testapp", output)
        self.assertIn("TestApp", output)
        self.assertNotIn("VULNERABILITY", output)
        self.assertIn("No obvious hardcoded secrets found", output)
        self.assertIn("No HTTP URLs found", output)

    @patch('scanner.APK')
    def test_analyze_apk_debuggable(self, mock_apk_cls):
        """Test that debuggable flag is detected."""
        mock_apk = self._setup_mock_apk()
        mock_apk.is_debuggable.return_value = True
        mock_apk_cls.return_value = mock_apk
        self._setup_mock_dvm(strings=[])

        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            analyze_apk("debug.apk")
            output = mock_out.getvalue()

        self.assertIn("VULNERABILITY", output)
        self.assertIn("debuggable", output)

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

        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            analyze_apk("secrets.apk")
            output = mock_out.getvalue()

        self.assertIn("Potential Hardcoded Secrets Found", output)
        self.assertIn("api_key=ABCDEF123456", output)
        self.assertIn("my_password_here", output)

    @patch('scanner.APK')
    def test_analyze_apk_finds_http_urls(self, mock_apk_cls):
        """Test detection of insecure HTTP URLs."""
        mock_apk = self._setup_mock_apk()
        mock_apk_cls.return_value = mock_apk
        self._setup_mock_dvm(strings=[
            "http://insecure.example.com/api",
            "https://secure.example.com/api"
        ])

        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            analyze_apk("http.apk")
            output = mock_out.getvalue()

        self.assertIn("Insecure HTTP URLs Found", output)
        self.assertIn("http://insecure.example.com/api", output)
        self.assertNotIn("https://secure.example.com/api", output)

    @patch('scanner.APK')
    def test_analyze_apk_load_error(self, mock_apk_cls):
        """Test graceful handling when APK cannot be loaded."""
        mock_apk_cls.side_effect = Exception("Bad APK")

        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            analyze_apk("corrupt.apk")
            output = mock_out.getvalue()

        self.assertIn("Error loading APK", output)
        self.assertIn("Bad APK", output)

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

        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            analyze_apk("perms.apk")
            output = mock_out.getvalue()

        mock_apk.get_permissions.assert_called_once()
        self.assertIn("android.permission.INTERNET", output)
        self.assertIn("android.permission.READ_CONTACTS", output)
        self.assertIn("android.permission.SEND_SMS", output)

    @patch('scanner.APK')
    def test_analyze_apk_exported_components(self, mock_apk_cls):
        """Test detection of exported components with intent filters."""
        mock_apk = self._setup_mock_apk()
        mock_apk.get_activities.return_value = [
            "com.example.MainActivity",
            "com.example.ExportedActivity"
        ]
        mock_apk.get_services.return_value = ["com.example.MyService"]

        def mock_intent_filters(comp_type, comp_name):
            if comp_name == "com.example.ExportedActivity":
                return {"action": ["android.intent.action.VIEW"]}
            return {}

        mock_apk.get_intent_filters.side_effect = mock_intent_filters
        mock_apk_cls.return_value = mock_apk
        self._setup_mock_dvm(strings=[])

        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            analyze_apk("exported.apk")
            output = mock_out.getvalue()

        self.assertIn("Exported Activity: com.example.ExportedActivity", output)
        self.assertNotIn("Exported Activity: com.example.MainActivity", output)

    @patch('scanner.APK')
    def test_analyze_apk_no_exported_components(self, mock_apk_cls):
        """Test message when no exported components are found."""
        mock_apk = self._setup_mock_apk()
        mock_apk.get_intent_filters.return_value = {}
        mock_apk_cls.return_value = mock_apk
        self._setup_mock_dvm(strings=[])

        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            analyze_apk("safe.apk")
            output = mock_out.getvalue()

        self.assertIn("No exported components with intent filters found", output)

    @patch('scanner.APK')
    def test_analyze_apk_multi_dex(self, mock_apk_cls):
        """Test that all dex files are scanned in multi-dex APKs."""
        mock_apk = self._setup_mock_apk()
        mock_apk.get_all_dex.return_value = [b"dex1", b"dex2"]
        mock_apk_cls.return_value = mock_apk

        mock_dex1 = MagicMock()
        mock_dex1.get_strings.return_value = ["safe string"]
        mock_dex2 = MagicMock()
        mock_dex2.get_strings.return_value = ["api_key=SECRET123"]
        mock_dvm_module.DalvikVMFormat.side_effect = [mock_dex1, mock_dex2]

        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            analyze_apk("multidex.apk")
            output = mock_out.getvalue()

        self.assertEqual(mock_dvm_module.DalvikVMFormat.call_count, 2)
        self.assertIn("api_key=SECRET123", output)


if __name__ == '__main__':
    unittest.main()
