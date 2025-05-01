import requests
import json
import urllib3

# ANSI color codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

# Suppress only the single InsecureRequestWarning from urllib3 needed.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def format_result(domain, path, status, message, color):
    return {
        "domain": domain,
        "path": path,
        "status": status,
        "message": message,
        "color": color
    }

def print_results(results):
    from collections import defaultdict

    domain_results = defaultdict(list)
    for result in results:
        domain_results[result['domain']].append(result)

    for domain, res_list in domain_results.items():
        found_paths = [r for r in res_list if r['status'] == 'success']
        not_found_paths = [r for r in res_list if r['status'] != 'success']

        if len(found_paths) == 0:
            # All tests failed or not found
            print(f"{RED}{domain} : all of test is 404 or not found{RESET}")
        else:
            print(f"{domain} :")
            for r in found_paths:
                print(f"  {GREEN}{domain}/{r['path']}{RESET}")
            """for r in not_found_paths:
                print(f"  {r['path']} not found")"""

def get_slugs_from_domain(domain):
    print(f"starting testing user enumeration in {domain}")
    url = f"https://{domain}/wp-json/wp/v2/users"
    path = "wp-json/wp/v2/users"
    results = []
    try:
        response = requests.get(url, timeout=10, verify=False)
        if response.status_code == 200:
            users = response.json()
            if users:
                results.append(format_result(domain, path, "success", "Users found", GREEN))
                output_data = []
                for user in users:
                    slug = user.get('slug')
                    name = user.get('name')
                    if slug and name:
                        output_data.append({"username": slug, "name": name})
                if output_data:
                    with open(f"{domain}.json", "w", encoding="utf-8") as f:
                        json.dump(output_data, f, ensure_ascii=False, indent=2)
            else:
                results.append(format_result(domain, path, "error", "No slugs found in response.", RED))
        elif response.status_code == 401:
            output_data = []
            results.append(format_result(domain, path, "warning", "Endpoint access denied, trying individual user endpoints...", YELLOW))
            for i in range(1, 101):
                user_url = f"https://{domain}/wp-json/wp/v2/users/{i}"
                try:
                    user_resp = requests.get(user_url, timeout=10, verify=False)
                    if user_resp.status_code == 200:
                        user = user_resp.json()
                        slug = user.get('slug')
                        name = user.get('name')
                        if slug and name:
                            output_data.append({"username": slug, "name": name})
                    elif user_resp.status_code == 404:
                        continue
                    else:
                        break
                except requests.RequestException:
                    break
            if output_data:
                with open(f"{domain}.json", "w", encoding="utf-8") as f:
                    json.dump(output_data, f, ensure_ascii=False, indent=2)
            else:
                results.append(format_result(domain, path, "error", "No users found via individual endpoints.", RED))
        elif response.status_code == 403:
            results.append(format_result(domain, path, "warning", f"Endpoint access denied (Status code: {response.status_code})", YELLOW))
        else:
            results.append(format_result(domain, path, "error", f"Endpoint users not found or inaccessible (Status code: {response.status_code})", RED))
    except requests.RequestException as e:
        results.append(format_result(domain, path, "error", f"Request failed: {e}", RED))
    return results

def check_wp_login_admin(domain):
    print(f"starting testing admin login in {domain}")
    paths = ["wp-login.php", "wp-admin.php", "wp-login", "wp-admin", "login"]
    results = []
    for path in paths:
        url = f"https://{domain}/{path}"
        try:
            response = requests.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                results.append(format_result(domain, path, "success", f"{path} exists", GREEN))
            elif response.status_code in [401, 403]:
                results.append(format_result(domain, path, "warning", f"{path} access denied (Status code: {response.status_code})", YELLOW))
            else:
                results.append(format_result(domain, path, "error", f"{path} does not exist (Status code: {response.status_code})", RED))
        except requests.RequestException as e:
            results.append(format_result(domain, path, "error", f"{path} check failed: {e}", RED))
    return results

def check_wp_uploads_accessible(domain):
    print(f"starting testing uploads accessability in {domain}")
    url = f"https://{domain}/wp-content/uploads"
    results = []
    try:
        response = requests.get(url, timeout=10, verify=False)
        if response.status_code == 200:
            results.append(format_result(domain, "wp-content/uploads", "success", "wp-content/uploads is accessible", GREEN))
        else:
            results.append(format_result(domain, "wp-content/uploads", "error", f"wp-content/uploads is not accessible (Status code: {response.status_code})", RED))
    except requests.RequestException as e:
        results.append(format_result(domain, "wp-content/uploads", "error", f"wp-content/uploads check failed: {e}", RED))
    return results

def check_xmlrpc(domain):
    print(f"starting testing xmlrpc for pingback and brute forcing in {domain}")
    url = f"https://{domain}/xmlrpc.php"
    results = []
    try:
        response = requests.get(url, timeout=10, verify=False)
        if response.status_code == 200:
            results.append(format_result(domain, "xmlrpc.php", "success", "xmlrpc.php exists", GREEN))
        elif response.status_code in [401, 403]:
            results.append(format_result(domain, "xmlrpc.php", "warning", f"xmlrpc.php access denied (Status code: {response.status_code})", YELLOW))
        else:
            results.append(format_result(domain, "xmlrpc.php", "error", f"xmlrpc.php does not exist (Status code: {response.status_code})", RED))
    except requests.ConnectionError as e:
        results.append(format_result(domain, "xmlrpc.php", "error", f"xmlrpc.php check failed: Connection error: {e}", RED))
    except requests.RequestException as e:
        results.append(format_result(domain, "xmlrpc.php", "error", f"xmlrpc.php check failed: {e}", RED))
    return results

def check_and_download_wp_config(domain):
    print(f"starting testing information discloser in {domain}")
    filenames = [
        "wp-config.bak",
        "wp-config.good",
        "wp-config.php_",
        "wp-config.php~",
        "wp-config.php.0",
        "wp-config.php.1",
        "wp-config.php_1",
        "wp-config.php.2",
        "wp-config.php.3",
        "wp-config.php.4",
        "wp-config.php.5",
        "wp-config.php.6",
        "wp-config.php.7",
        "wp-config.php.8",
        "wp-config.php.9",
        "wp-config.php.a",
        "wp-config.php.b",
        "wp-config.php.backup",
        "wp-config.php-bak",
        "wp-config.php.bak",
        "wp-config.php_bak",
        "wp-config.php.bak1",
        "wp-config.php.bk",
        "wp-config.php.cust",
        "wp-config.php.disabled",
        "wp-config.php.new",
        "wp-config.php_new",
        "wp-config.php.old",
        "wp-config.php_Old",
        "wp-config.php.orig",
        "wp-config.php_orig",
        "wp-config.php-original",
        "wp-config.php.original",
        "wp-config.php_original",
        "wp-config.phporiginal",
        "wp-config.php.save",
        "wp-config.php.swn",
        "wp-config.php.swo",
        "wp-config.php.swp",
        "wp-config.php"
    ]
    results = []
    for filename in filenames:
        url = f"https://{domain}/{filename}"
        try:
            response = requests.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                if response.content and len(response.content) > 0:
                    safe_filename = filename.replace("/", "_").replace(" ", "_")
                    save_name = f"{domain}_{safe_filename}"
                    with open(save_name, "wb") as f:
                        f.write(response.content)
                    results.append(format_result(domain, filename, "success", f"{filename} downloaded as {save_name}", GREEN))
                else:
                    results.append(format_result(domain, filename, "warning", f"{filename} is empty, not saved", YELLOW))
            elif response.status_code in [401, 403]:
                results.append(format_result(domain, filename, "warning", f"{filename} access denied (Status code: {response.status_code})", YELLOW))
            else:
                results.append(format_result(domain, filename, "error", f"{filename} does not exist (Status code: {response.status_code})", RED))
        except requests.RequestException as e:
            results.append(format_result(domain, filename, "error", f"{filename} check failed: {e}", RED))
    return results

def check_oembed_proxy(domain):
    print(f"starting testing SSRF in {domain}")
    url = f"https://{domain}/wp-json/oembed/1.0/proxy?url"
    results = []
    try:
        response = requests.get(url, timeout=10, verify=False)
        if response.status_code == 200:
            results.append(format_result(domain, "wp-json/oembed/1.0/proxy?url", "success", "wp-json/oembed/1.0/proxy?url exists", GREEN))
        elif response.status_code in [401, 403]:
            results.append(format_result(domain, "wp-json/oembed/1.0/proxy?url", "warning", f"wp-json/oembed/1.0/proxy?url access denied (Status code: {response.status_code})", YELLOW))
        else:
            results.append(format_result(domain, "wp-json/oembed/1.0/proxy?url", "error", f"wp-json/oembed/1.0/proxy?url does not exist (Status code: {response.status_code})", RED))
    except requests.RequestException as e:
        results.append(format_result(domain, "wp-json/oembed/1.0/proxy?url", "error", f"wp-json/oembed/1.0/proxy?url check failed: {e}", RED))
    return results

def process_domain(domain):
    results = []
    results.extend(get_slugs_from_domain(domain))
    results.extend(check_wp_login_admin(domain))
    results.extend(check_wp_uploads_accessible(domain))
    results.extend(check_xmlrpc(domain))
    results.extend(check_and_download_wp_config(domain))
    results.extend(check_oembed_proxy(domain))
    print_results(results)

def main():
    with open("domains.txt", "r") as file:
        domains = [line.strip() for line in file if line.strip()]
    for domain in domains:
        #print(f"starting test of {domain}")
        process_domain(domain)

if __name__ == "__main__":
    main()
