# Android Application Security Scanner (Static)

This tool is a static analysis security scanner specifically designed for Android Application Package (APK) files. It decompiles an APK and scans its manifest file (`AndroidManifest.xml`) and bytecode for common security vulnerabilities without actually executing the application. This helps developers and security professionals identify potential flaws early in the development lifecycle or assess the security posture of third-party applications.

## Features

*   **APK Decompilation:** Automatically unpacks and decompiles the Android APK file to access its components.
*   **Manifest Analysis:** Scans the `AndroidManifest.xml` file for security misconfigurations, such as:
    *   `android:debuggable="true"` being enabled.
    *   Exported components (Activities, Services, Broadcast Receivers, Content Providers) with intent filters.
    *   Permissions requested by the application.
*   **Bytecode Analysis:** Examines the application's bytecode (including multi-dex APKs) for common coding vulnerabilities, such as:
    *   **Hardcoded Secrets:** Detection of API keys, passwords, tokens, or other sensitive information directly embedded in the code.
    *   **Insecure Communication:** Flags the use of unencrypted HTTP connections for data transfer, making the app vulnerable to Man-in-the-Middle attacks.

## How it Works

Static Application Security Testing (SAST) for Android apps involves examining the application's code and configuration files without running the app. Here's a simplified breakdown:

1.  **APK Input:** You provide the scanner with an Android APK file. This is the package format used to distribute and install Android apps.
2.  **Decompilation:** The tool first "decompiles" the APK. This process extracts all the components of the app, including its resources, libraries, and the compiled code (Dalvik bytecode, typically in `classes.dex` files). It also reconstructs the `AndroidManifest.xml` file, which declares the app's essential characteristics and permissions.
3.  **Manifest Analysis:** The `AndroidManifest.xml` is a critical security boundary. The scanner examines this file for common misconfigurations. For example, if an app component has intent filters, it is considered exported and other apps can interact with it, which can be a vulnerability if not handled carefully.
4.  **Bytecode Analysis:** The tool then analyzes all of the app's DEX files (supporting multi-dex APKs). It searches for specific patterns or coding practices that are known to be insecure. For instance:
    *   It looks for strings that resemble API keys or passwords that are directly written into the code.
    *   It checks if the app is making network requests using unencrypted `HTTP` instead of secure `HTTPS`.
5.  **Reporting:** All the potential security flaws found during the manifest and bytecode analysis are printed to the console.

## Key Vulnerabilities Detected

*   **Hardcoded Secrets:** Embedding API keys, passwords, encryption keys, or other sensitive credentials directly in the application's source code.
*   **Insecure Communication:** Using unencrypted protocols (like plain HTTP) for transmitting sensitive data, making it vulnerable to eavesdropping.
*   **Exported Components:** Activities, services, broadcast receivers, or content providers with intent filters that can be accessed by other apps on the device.
*   **Debuggable Applications:** Detecting `android:debuggable="true"` in the manifest, which can expose an application to reverse engineering and exploitation.

## System Requirements

*   **Python 3.x:** The tool is written in Python.
*   **Android APK File:** The input for the scanner must be a valid Android APK file.
*   **Operating System:** Works on Linux, macOS, and Windows.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/android_application_security_scanner_static.git
    cd android_application_security_scanner_static
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    This will install the `androguard` library, which is essential for APK analysis.

4.  **Install the package:**
    ```bash
    pip install -e .
    ```
    This makes the `android-scanner` command available in your terminal.

## Dependencies
*   **`androguard`**: This is the primary external dependency. It's a powerful Python library and tool suite for Android malware analysis and reverse engineering. It provides the core functionality for parsing and analyzing APK files. It will be installed automatically via `requirements.txt`.

## Usage

### Using the installed command
After installing with `pip install -e .`, you can run:
```bash
android-scanner /path/to/your/app.apk
```

### Running directly
```bash
python src/scanner.py /path/to/your/app.apk
```

The tool will output a report of identified vulnerabilities and potential security issues directly to the console.

## Project Structure

```
.
├── src/
│   └── scanner.py       # Core logic for APK analysis and vulnerability scanning
├── tests/
│   ├── __init__.py
│   └── test_scanner.py  # Unit tests with mocked androguard
├── requirements.txt     # Python dependencies (androguard)
├── setup.py             # Package setup with console_scripts entry point
└── README.md
```

## Running Tests
To run the included unit tests, use `pytest`:
```bash
python -m pytest tests/
```

## License
This project is not currently licensed.

## Notes
*   **Static vs. Dynamic Analysis:** This tool performs static analysis (without running the app). While effective for many common vulnerabilities, it may miss issues that only appear during runtime (dynamic analysis). For a comprehensive security assessment, both static and dynamic analysis are recommended.
*   **False Positives/Negatives:** SAST tools can sometimes produce false positives (reporting a vulnerability that isn't real) or false negatives (missing a real vulnerability). Manual review by a security expert is always advisable.
*   **Evolving Threats:** The mobile security landscape is constantly changing. Regular updates to the scanner's rules and signatures are necessary to keep up with new threats and vulnerabilities.
*   This tool is intended for authorized security research, ethical hacking, and educational purposes. Ensure you have proper authorization before analyzing any APK file.
