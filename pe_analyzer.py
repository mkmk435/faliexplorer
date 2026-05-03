import os
import argparse
import lief
from pathlib import Path

# Disable LIEF's internal C++ logging so it doesn't clutter our terminal output
lief.logging.disable()

# ANSI Color Codes for terminal highlighting
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def check_driver_imports(driver_path: str, target_functions: list) -> dict:
    """
    Checks a Windows PE/Driver file to see if it imports specific functions using LIEF.
    """
    results = {func: False for func in target_functions}
    
    if not os.path.exists(driver_path):
        return results

    try:
        pe = lief.parse(driver_path)
        
        if pe is None or not isinstance(pe, lief.PE.Binary):
            return results

        if pe.has_imports:
            for imp in pe.imports:
                for entry in imp.entries:
                    if entry.name in results:
                        results[entry.name] = True
                        
        return results

    except Exception as e:
        # Only print errors if we aren't doing a clean bulk scan
        return results

def check_driver_signature(driver_path: str) -> dict:
    """
    Checks the Authenticode embedded signature of a Windows driver using LIEF.
    """
    sig_info = {
        "is_signed": False,
        "status": "Unknown",
        "is_whql": False,
        "is_ev": False,
        "subject": "",
        "issuer": ""
    }

    if not os.path.exists(driver_path):
        sig_info["status"] = "FileNotFound"
        return sig_info

    try:
        pe = lief.parse(driver_path)
        
        if pe is None or not isinstance(pe, lief.PE.Binary):
            sig_info["status"] = "Invalid PE Format"
            return sig_info

        if pe.has_signatures:
            sig_info["is_signed"] = True
            sig_info["status"] = "Embedded Signature Found"

            for sig in pe.signatures:
                for cert in sig.certificates:
                    subject_str = str(cert.subject)
                    issuer_str = str(cert.issuer)

                    if "Windows Hardware" in issuer_str or "Microsoft Windows Third Party Component" in issuer_str:
                        sig_info["is_whql"] = True

                    if "EV " in subject_str or "Extended Validation" in subject_str or \
                       "EV " in issuer_str or "Extended Validation" in issuer_str:
                        sig_info["is_ev"] = True

                    if not sig_info["subject"]:
                        sig_info["subject"] = subject_str
                        sig_info["issuer"] = issuer_str
        else:
            sig_info["status"] = "No Embedded Signature (Unsigned or Catalog-Signed)"

        return sig_info

    except Exception as e:
        sig_info["status"] = f"Error parsing signature"
        return sig_info

def analyze_file(file_path: str, functions_to_search: list, match_only: bool = False):
    """
    Runs the full analysis on a single file. 
    If match_only is True, it suppresses output unless a targeted import is found.
    """
    # 1. Test Imports FIRST before printing any headers
    import_results = check_driver_imports(file_path, functions_to_search)
    
    # Check if at least one function was found
    has_matches = any(import_results.values())
    
    # If the user only wants matches, and we found none, exit silently
    if match_only and not has_matches:
        return

    # If we get here, we are printing the results
    print(f"\n{Colors.BLUE}[*] Analyzing: {file_path}{Colors.RESET}")
    print("-" * 70)

    print("[*] Imports:")
    for func, found in import_results.items():
        if found:
            print(f"    - {func}: {Colors.GREEN}FOUND{Colors.RESET}")
        else:
            print(f"    - {func}: Not Found")

    # 2. Test Signature
    print("\n[*] Digital Signature (Authenticode):")
    sig_results = check_driver_signature(file_path)
    
    sig_color = Colors.GREEN if sig_results['is_signed'] else Colors.RED
    print(f"    - Is Signed:      {sig_color}{sig_results['is_signed']}{Colors.RESET}")
    print(f"    - Status:         {sig_results['status']}")
    
    if sig_results['is_signed']:
        whql_color = Colors.GREEN if sig_results['is_whql'] else Colors.RESET
        ev_color = Colors.GREEN if sig_results['is_ev'] else Colors.RESET
        
        print(f"    - Is WHQL:        {whql_color}{sig_results['is_whql']}{Colors.RESET}")
        print(f"    - Is EV:          {ev_color}{sig_results['is_ev']}{Colors.RESET}")
        print(f"    - Subject:        {sig_results['subject']}")
        print(f"    - Issuer:         {sig_results['issuer']}")
    print("-" * 70)

def main():
    parser = argparse.ArgumentParser(description="Cross-platform Windows driver (.sys, .dll) import and signature scanner.")
    parser.add_argument("target", help="Path to a single file or a directory to scan.")
    
    # NEW ARGUMENT: -m / --match-only
    parser.add_argument("-m", "--match-only", action="store_true", help="Only show output for drivers that import at least one of the searched functions.")
    
    args = parser.parse_args()
    target_path = Path(args.target)

    # Functions to search for
    functions_to_search = [
        "ZwTerminateProcess", 
        # "ExAllocatePoolWithTag", 
        # "IoCreateDevice",
        # "KeStackAttachProcess",
        # "MmMapIoSpace"
    ]

    os.system("") # Init ANSI colors for older terminals

    if target_path.is_file():
        analyze_file(str(target_path), functions_to_search, args.match_only)
        
    elif target_path.is_dir():
        print(f"[*] Scanning directory: {target_path} for .sys and .dll files...")
        if args.match_only:
            print(f"[*] Filtering enabled: Only showing drivers containing target imports.\n")
            
        valid_extensions = {".sys", ".dll"}
        files_to_scan = [
            f for f in target_path.rglob("*") 
            if f.is_file() and f.suffix.lower() in valid_extensions
        ]
        
        if not files_to_scan:
            print(f"[-] No .sys or .dll files found in {target_path}")
            return
            
        for file in files_to_scan:
            analyze_file(str(file), functions_to_search, args.match_only)
    else:
        print(f"{Colors.RED}[-] The specified path does not exist or is inaccessible: {target_path}{Colors.RESET}")

if __name__ == "__main__":
    main()