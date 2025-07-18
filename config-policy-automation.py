import requests
import json
import os
import csv

# --- Configuration ---
PRISMA_CLOUD_API_URL = os.environ.get("PRISMA_CLOUD_API_URL", "https://api.sg.prismacloud.io") # Your Prisma Cloud API URL
# SECURITY NOTE: In a real environment, load keys from environment variables or a secure vault.
ACCESS_KEY = os.environ.get("PRISMA_CLOUD_ACCESS_KEY", "653cb16e-a95c-44db-8942-377272850170") # Your Prisma Cloud Access Key
SECRET_KEY = os.environ.get("PRISMA_CLOUD_SECRET_KEY", "KZIPjuJg1AuctgDlKGay4DSMaBg=") # Your Prisma Cloud Secret Key

# Read configuration from CSV file using DictReader
csv_file_path = 'policy_20250718 - Sheet1.csv'

# --- API Endpoints ---
LOGIN_URL = f"{PRISMA_CLOUD_API_URL}/login"
SEARCH_CONFIG_URL = f"{PRISMA_CLOUD_API_URL}/search/api/v2/config" #https://pan.dev/prisma-cloud/api/cspm/search-config-v-2/
SAVE_SEARCH_URL_TEMPLATE = f"{PRISMA_CLOUD_API_URL}/search/history/" #https://pan.dev/prisma-cloud/api/cspm/search-history/
ADD_POLICY_URL = f"{PRISMA_CLOUD_API_URL}/policy" #https://pan.dev/prisma-cloud/api/cspm/add-policy/

def get_jwt_token(access_key, secret_key):
    """
    Prisma Cloud API에 로그인하여 JWT 토큰을 반환합니다.
    """
    headers = {"Content-Type": "application/json"}
    payload = {"username": access_key, "password": secret_key}
    try:
        print("Attempting to get JWT token...")
        response = requests.post(LOGIN_URL, headers=headers, json=payload)
        response.raise_for_status()
        token = response.json().get("token")
        if not token:
            raise ValueError("JWT token not found in login response.")
        print("Successfully obtained JWT token.")
        return token
    except requests.exceptions.RequestException as e:
        print(f"Error during login: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response content: {e.response.text}")
        return None

def get_search_id(jwt_token, rql_query):
    """
    RQL 쿼리를 실행하여 Search ID를 반환합니다.
    /permission-search-v-4 API에 맞춰 payload를 구성합니다.
    """
    headers = {
        "Content-Type": "application/json",
        "x-redlock-auth": jwt_token
    }
    payload = {
        "query": rql_query,
    }
    try:
        print(f"Attempting to get search ID from {SEARCH_CONFIG_URL} for RQL: {rql_query}")
        response = requests.post(SEARCH_CONFIG_URL, headers=headers, json=payload)
        response.raise_for_status()
        search_id = response.json().get("searchId")
        if not search_id:
             search_id = response.json().get("id")
        if not search_id:
            raise ValueError("Search ID not found in permission search response. Check 'searchId' or 'id' key.")
        print(f"Successfully obtained Search ID: {search_id}")
        return search_id
    except requests.exceptions.RequestException as e:
        print(f"Error getting search ID: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response content: {e.response.text}")
        return None

def save_search(jwt_token, search_id, rql_query, name, description, cloud_type):
    """
    기존의 recent search를 saved search로 변환하거나 업데이트합니다.
    """
    headers = {
        "Content-Type": "application/json",
        "x-redlock-auth": jwt_token
    }
    payload = {
        "query": rql_query,
        "id": search_id,
        "name": name,
        "description": description,
        "saved": True,
        "cloudType": cloud_type,
        # "timeRange": { 
        #     "type": "relative",
        #     "value": {
        #         "unit": "day",
        #         "amount": 7  # 원하는 기간으로 변경
        #     }
        # },
        "default": False
    }
    try:
        save_search_url = f"{SAVE_SEARCH_URL_TEMPLATE}{search_id}"
        print(f"Attempting to save search '{name}' with ID: {search_id}")
        response = requests.post(save_search_url, headers=headers, json=payload)
        response.raise_for_status()
        print(f"Successfully saved search '{name}'.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error saving search: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response content: {e.response.text}")
        return False

def add_policy(jwt_token, search_id, policy_name, policy_description, policy_severity, policy_labels, policy_cloud_type):
    """
    Search ID를 사용하여 Prisma Cloud에 새 정책을 추가합니다.
    """
    headers = {
        "Content-Type": "application/json",
        "x-redlock-auth": jwt_token
    }
    payload = {
        "name": policy_name,
        "description": policy_description,
        "severity": policy_severity,
        "labels": policy_labels,
        "policyType": "config",
        "cloudType": policy_cloud_type,
        "enabled": True,
        "recommendation": "",
        "rule": {
            "name": f"{policy_name} Rule",
            "criteria": search_id,
            "parameters": {
                "savedSearch": True
            },
            "type": "Config"
        }
    }
    try:
        print(f"Attempting to add policy: {policy_name}")
        response = requests.post(ADD_POLICY_URL, headers=headers, json=payload)
        response.raise_for_status()
        policy_details = response.json()
        print(f"Successfully added policy '{policy_name}' with ID: {policy_details.get('policyId')}")
        return policy_details
    except requests.exceptions.RequestException as e:
        print(f"Error adding policy: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response content: {e.response.text}")
        if hasattr(e, 'response') and "already exists" in e.response.text:
            print(f"Policy with name '{policy_name}' already exists. Skipping.")
        return None

def main():
    """
    메인 함수: 로그인, CSV 파일의 각 줄을 읽어 Search ID 획득, Saved Search로 변환, 정책 추가 순으로 실행합니다.
    """
    print("Starting Prisma Cloud policy creation script...")

    # 1. JWT 토큰 획득
    jwt_token = get_jwt_token(ACCESS_KEY, SECRET_KEY)
    if not jwt_token:
        print("Failed to get JWT token. Exiting.")
        return

    try:
        with open(csv_file_path, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for i, row in enumerate(reader):
                print(f"\n--- Processing Policy from CSV row {i+1} ---")
                
                # CSV에서 각 줄의 데이터를 변수에 할당
                rql_query = row.get('RQL_QUERY', '')
                policy_name = row.get('POLICY_NAME', '')
                policy_description = row.get('POLICY_DESCRIPTION', '')
                policy_severity = row.get('POLICY_SEVERITY', '')
                
                # POLICY_LABELS 문자열을 Python 리스트로 파싱
                labels_str = row.get('POLICY_LABELS', '[]').strip('[]')
                if labels_str:
                    policy_labels = [label.strip().strip('"') for label in labels_str.split(',')]
                else:
                    policy_labels = []
                    
                policy_cloud_type = row.get('POLICY_CLOUD_TYPE', '')
                saved_search_name = row.get('SAVED_SEARCH_NAME', '')
                saved_search_description = row.get('SAVED_SEARCH_DESCRIPTION', '')

                # 필수 필드 검증
                if not all([rql_query, policy_name, policy_severity, policy_cloud_type, saved_search_name]):
                    print(f"Skipping row {i+1} due to missing required fields (RQL_QUERY, POLICY_NAME, POLICY_SEVERITY, POLICY_CLOUD_TYPE, SAVED_SEARCH_NAME).")
                    continue

                print(f"Loaded RQL_QUERY: {rql_query}")
                print(f"Loaded POLICY_NAME: {policy_name}")
                print(f"Loaded POLICY_DESCRIPTION: {policy_description}")
                print(f"Loaded POLICY_SEVERITY: {policy_severity}")
                print(f"Loaded POLICY_LABELS: {policy_labels}")
                print(f"Loaded POLICY_CLOUD_TYPE: {policy_cloud_type}")
                print(f"Loaded SAVED_SEARCH_NAME: {saved_search_name}")
                print(f"Loaded SAVED_SEARCH_DESCRIPTION: {saved_search_description}")

                # 2. RQL 쿼리로 Search ID 획득
                search_id = get_search_id(jwt_token, rql_query)
                if not search_id:
                    print(f"Failed to get Search ID for policy '{policy_name}'. Skipping this policy.")
                    continue

                # 3. Recent Search를 Saved Search로 변환
                saved_successfully = save_search(jwt_token, search_id, rql_query, saved_search_name, saved_search_description, policy_cloud_type)
                if not saved_successfully:
                    print(f"Failed to save the search for policy '{policy_name}'. Skipping this policy.")
                    continue

                # 4. Saved Search ID를 사용하여 정책 추가
                added_policy = add_policy(
                    jwt_token,
                    search_id,
                    policy_name,
                    policy_description,
                    policy_severity,
                    policy_labels,
                    policy_cloud_type
                )

                if added_policy:
                    print(f"\nPolicy '{policy_name}' created successfully.")
                    print(f"Policy ID: {added_policy.get('policyId')}")
                    print(f"Corresponding Saved Search Name: {saved_search_name}")
                else:
                    print(f"\nPolicy '{policy_name}' creation failed or already exists.")

    except FileNotFoundError:
        print(f"Error: The file {csv_file_path} was not found. Please ensure it's in the same directory as the script.")
        exit()
    except Exception as e:
        print(f"An unexpected error occurred while processing the CSV file: {e}")
        exit()

    print("\nPrisma Cloud policy creation script finished.")

if __name__ == "__main__":
    main()