import os
import sys
import importlib.util
import argparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions

def run_selenium_tests(target_url, scripts_dir, use_headless=True, browser='chrome'):
    """Runs all Python test scripts found in a directory using Selenium."""

    # --- WebDriver Setup ---
    driver = None
    try:
        if browser.lower() == 'chrome':
            options = ChromeOptions()
            if use_headless:
                options.add_argument("--headless")
            options.add_argument("--no-sandbox") # Thường cần thiết trong môi trường container/CI
            options.add_argument("--disable-dev-shm-usage") # Thường cần thiết
            # options.add_argument("--window-size=1920,1080") # Có thể cần thiết cho headless
            driver = webdriver.Chrome(options=options)
        elif browser.lower() == 'firefox':
             options = FirefoxOptions()
             if use_headless:
                 options.add_argument("--headless")
             driver = webdriver.Firefox(options=options)
        else:
            print(f"Error: Unsupported browser '{browser}'")
            return
        print(f"WebDriver ({browser}{' headless' if use_headless else ''}) initialized.")
    except Exception as e:
        print(f"Error initializing WebDriver: {e}")
        print("Make sure you have the correct WebDriver installed and in your PATH.")
        return

    # --- Test Discovery and Execution ---
    results = {}
    found_scripts = False
    for filename in os.listdir(scripts_dir):
        if filename.endswith(".py") and filename.startswith("test_"):
            found_scripts = True
            script_path = os.path.join(scripts_dir, filename)
            module_name = filename[:-3] # Bỏ ".py"
            print(f"\n>>> Found test script: {filename}")

            try:
                # Import the test module dynamically
                spec = importlib.util.spec_from_file_location(module_name, script_path)
                test_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(test_module)

                # Check if the module has the 'run_test' function
                if hasattr(test_module, 'run_test') and callable(test_module.run_test):
                    # Execute the test
                    success, message = test_module.run_test(driver, target_url)
                    results[module_name] = {"success": success, "message": message}
                    print(f"<<< Result [{module_name}]: {'Success' if success else 'Failed'} - {message}")
                else:
                    print(f"Warning: Script {filename} does not have a 'run_test' function.")
                    results[module_name] = {"success": False, "message": "No run_test function found"}

            except Exception as e:
                print(f"Error running script {filename}: {e}")
                results[module_name] = {"success": False, "message": f"Execution error: {e}"}

    if not found_scripts:
         print(f"No test scripts found in directory: {scripts_dir}")

    # --- Cleanup ---
    if driver:
        driver.quit()
        print("\nWebDriver closed.")

    # --- Report Summary (optional) ---
    print("\n--- Test Summary ---")
    for name, result in results.items():
         print(f"- {name}: {'PASS' if result['success'] else 'FAIL'} ({result['message']})")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Selenium tests from a directory.")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-d", "--scripts-dir", default="selenium_tests", help="Directory containing test scripts (default: selenium_tests)")
    parser.add_argument("-b", "--browser", default="chrome", choices=["chrome", "firefox"], help="Browser to use (default: chrome)")
    parser.add_argument("--no-headless", action="store_true", help="Disable headless mode")

    args = parser.parse_args()

    run_selenium_tests(args.url, args.scripts_dir, use_headless=(not args.no_headless), browser=args.browser)
