from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
import argparse
import sys
import re

def analyze_apk(apk_path):
    print(f"[*] Analyzing APK: {apk_path}...")
    try:
        a = APK(apk_path)
    except Exception as e:
        print(f"[-] Error loading APK: {e}")
        return

    # 1. Manifest Analysis
    print("\n--- Manifest Analysis ---")
    print(f"Package Name: {a.get_package()}")
    print(f"App Name: {a.get_app_name()}")

    if a.is_debuggable():
        print("[!] VULNERABILITY: App is debuggable (android:debuggable='true')")

    # Check for exported components
    print("\n[*] Checking Exported Components:")
    exported_found = False

    components = {
        "Activity": a.get_activities(),
        "Service": a.get_services(),
        "Receiver": a.get_receivers(),
        "Provider": a.get_providers(),
    }

    for comp_type, comp_list in components.items():
        for comp in comp_list:
            intent_filters = a.get_intent_filters(comp_type.lower(), comp)
            is_exported = len(intent_filters) > 0 if intent_filters else False
            if is_exported:
                print(f"  [!] Exported {comp_type}: {comp}")
                exported_found = True

    if not exported_found:
        print("  [+] No exported components with intent filters found.")

    # listing permissions
    print("\n[*] Permissions:")
    for p in a.get_permissions():
        print(f"  - {p}")

    # 2. String/Code Analysis
    print("\n--- Code Analysis ---")
    # Load all dex files (supports multi-dex APKs)
    all_dex_data = a.get_all_dex()

    print("[*] Searching for hardcoded secrets and insecurities...")

    secrets = ["api_key", "password", "secret", "token"]
    suspicious_urls = []
    found_secrets = []

    for dex_data in all_dex_data:
        d = DalvikVMFormat(dex_data)

        for s in d.get_strings():
            # Check for secrets
            for secret_key in secrets:
                if secret_key in s.lower() and len(s) < 100:
                     found_secrets.append(s)

            # Check for HTTP
            if "http://" in s:
                 suspicious_urls.append(s)

    if found_secrets:
        print("\n[!] Potential Hardcoded Secrets Found:")
        for s in set(found_secrets[:10]):
            print(f"  - {s}")
        if len(found_secrets) > 10:
             print(f"  ... and {len(found_secrets) - 10} more.")
    else:
        print("\n[+] No obvious hardcoded secrets found in strings.")

    if suspicious_urls:
        print("\n[!] Insecure HTTP URLs Found:")
        for u in set(suspicious_urls[:10]):
            print(f"  - {u}")
        if len(suspicious_urls) > 10:
            print(f"  ... and {len(suspicious_urls) - 10} more.")
    else:
        print("\n[+] No HTTP URLs found.")

def main():
    parser = argparse.ArgumentParser(description="Android Static Analysis Tool")
    parser.add_argument("apk_file", help="Path to the APK file")

    args = parser.parse_args()
    analyze_apk(args.apk_file)

if __name__ == "__main__":
    main()
