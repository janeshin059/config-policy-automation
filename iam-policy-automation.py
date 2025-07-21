import requests
import json
import os
import csv

# Prisma Cloud의 search/history API 대신 /iam/api/v3/search/permission API를 사용하여 새로운 Saved Search를 만들고 이를 정책에 연결하도록 코드를 수정해 드리겠습니다.
#/iam/api/v3/search/permission API 문서를 확인한 결과, 이 API는 RQL 쿼리를 사용하여 IAM 권한을 검색하는 동시에, 요청 본문에 id 필드를 제공하지 않으면 자동으로 새로운 Saved Search를 생성하는 기능을 포함하고 있습니다. 이 Saved Search의 ID는 API 응답의 id 필드 (Message id)로 반환됩니다. 이 ID를 정책 생성에 활용할 수 있습니다.
#따라서 기존 get_search_id 함수를 수정하여 /iam/api/v3/search/permission을 호출하고, 그 응답에서 반환되는 ID를 Saved Search ID로 사용합니다. 별도의 save_search 함수는 필요 없게 됩니다.
#또한, IAM 권한 관련 정책이므로 add_policy 함수의 policyType과 rule.type을 "IAM"으로 변경했습니다.



# --- Configuration ---
PRISMA_CLOUD_API_URL = os.environ.get("PRISMA_CLOUD_API_URL", "https://api.sg.prismacloud.io") # Your Prisma Cloud API URL
# SECURITY NOTE: In a real environment, load keys from environment variables or a secure vault.
ACCESS_KEY = os.environ.get("PRISMA_CLOUD_ACCESS_KEY", "653cb16e-a95c-44db-8942-377272850170") # Your Prisma Cloud Access Key
SECRET_KEY = os.environ.get("PRISMA_CLOUD_SECRET_KEY", "KZIPjuJg1AuctgDlKGay4DSMaBg=") # Your Prisma Cloud Secret Key

POLICY_CSV_FILE = "policy_20250718 - Copy of Sheet1.csv" # The name of your CSV file

# --- API Endpoints ---
LOGIN_URL = f"{PRISMA_CLOUD_API_URL}/login"
# New API endpoint for IAM permission searches that can also create saved searches
SEARCH_PERMISSION_API_URL = f"{PRISMA_CLOUD_API_URL}/iam/api/v3/search/permission"
ADD_POLICY_URL = f"{PRISMA_CLOUD_API_URL}/policy"

def get_jwt_token(access_key, secret_key):
    """
    Prisma Cloud API에 로그인하여 JWT 토큰을 반환합니다.
    """
    headers = {"Content-Type": "application/json"}
    payload = {"username": access_key, "password": secret_key}
    try:
        print("JWT 토큰을 가져오는 중...")
        response = requests.post(LOGIN_URL, headers=headers, json=payload)
        response.raise_for_status()  # HTTP 오류 (4xx 또는 5xx) 발생 시 예외 발생
        token = response.json().get("token")
        if not token:
            raise ValueError("로그인 응답에서 JWT 토큰을 찾을 수 없습니다.")
        print("JWT 토큰 획득 성공.")
        return token
    except requests.exceptions.RequestException as e:
        print(f"로그인 중 오류 발생: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"응답 내용: {e.response.text}") # 올바른 접근
        return None

def create_and_get_saved_search_id_iam(jwt_token, rql_query, name, description, cloud_type):
    """
    RQL 쿼리를 사용하여 IAM 권한을 검색하고, 동시에 새로운 Saved Search를 생성하여 그 ID를 반환합니다.
    /iam/api/v3/search/permission API를 사용합니다.
    """
    headers = {
        "Content-Type": "application/json",
        "x-redlock-auth": jwt_token
    }
    payload = {
        "query": rql_query,
        "name": name,          # Attempt to pass name for saved search creation
        "description": description # Attempt to pass description for saved search creation
    }
    try:
        print(f"  RQL에 대한 Saved Search ID를 가져오는 중 (IAM Permission API): {rql_query[:80]}...")
        response = requests.post(SEARCH_PERMISSION_API_URL, headers=headers, json=payload)
        response.raise_for_status()
        search_id = response.json().get("id")
        if not search_id:
            raise ValueError("IAM Permission Search 응답에서 Search ID를 찾을 수 없습니다.")
        print(f"  Saved Search ID (IAM Permission API) 획득 성공: {search_id}")
        return search_id
    except requests.exceptions.RequestException as e:
        print(f"  IAM Permission Search ID 가져오는 중 오류 발생: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"  응답 내용: {e.response.text}")
        return None

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
        "policyType": "IAM", # IAM 권한 정책이므로 "IAM"으로 설정
        "cloudType": policy_cloud_type,
        "enabled": True,
        "recommendation": "권한 관련 정책 발견 시 권장 사항.", # 적절한 권장 사항으로 변경
        "rule": {
            "name": f"{policy_name} Rule",
            "criteria": search_id,
            "parameters": {
                "savedSearch": True
            },
            "type": "IAM" # IAM 권한 정책이므로 "IAM"으로 설정
        }
    }
    try:
        print(f"  정책 추가 시도: '{policy_name}'...")
        response = requests.post(ADD_POLICY_URL, headers=headers, json=payload)
        response.raise_for_status()
        policy_details = response.json()
        print(f"  정책 '{policy_name}' 추가 성공, ID: {policy_details.get('policyId')}")
        return policy_details
    except requests.exceptions.RequestException as e:
        print(f"  정책 추가 중 오류 발생: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"  응답 내용: {e.response.text}")
        if hasattr(e, 'response') and "already exists" in e.response.text:
            print(f"  이름 '{policy_name}'을(를) 가진 정책이 이미 존재할 수 있습니다. 건너뜁니다.")
        return None

def process_policy_from_csv(jwt_token, policy_data):
    """
    CSV 한 행에서 읽은 데이터를 기반으로 Search 생성, 저장, Policy 생성을 처리합니다.
    """
    rql_query = policy_data['RQL_QUERY']
    policy_name = policy_data['POLICY_NAME']
    policy_description = policy_data.get('POLICY_NAME.1', '') # CSV의 POLICY_NAME.1 컬럼을 설명으로 사용
    policy_severity = policy_data['POLICY_SEVERITY']

    labels_str = policy_data.get('POLICY_LABELS', '')
    policy_labels = [label.strip() for label in labels_str.split(',') if label.strip()]

    policy_cloud_type = policy_data['POLICY_CLOUD_TYPE']
    saved_search_name = policy_data.get('SAVED_SEARCH_NAME', policy_name + " Query")
    saved_search_description = policy_data.get('SAVED_SEARCH_DESCRIPTION', policy_description)

    print(f"\n--- 정책 처리 중: '{policy_name}' ---")

    # 1. IAM Permission Search를 실행하고 Saved Search ID를 획득 (새 Saved Search가 생성됨)
    search_id = create_and_get_saved_search_id_iam(jwt_token, rql_query, saved_search_name, saved_search_description, policy_cloud_type)
    if not search_id:
        print(f"  Search ID 획득 실패로 정책 '{policy_name}' 건너뜁니다.")
        return False
    
    # NOTE: /iam/api/v3/search/permission API가 'name'과 'description'을
    # 직접적으로 새로운 saved search의 메타데이터로 설정하는 기능이 불확실합니다.
    # 만약 이름과 설명이 제대로 설정되지 않으면, 별도의 API 호출이 필요할 수 있습니다.
    # 현재 가정은 이 API가 이름과 설명을 사용하여 saved search를 생성한다는 것입니다.

    # 2. Saved Search ID를 사용하여 정책 추가
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
        print(f"--- 정책 '{policy_name}' 처리 완료. ---")
        return True
    else:
        print(f"--- 정책 '{policy_name}' 추가 실패. ---")
        return False

def main():
    """
    메인 함수: 로그인 후 CSV 파일의 각 행을 읽어 정책을 생성합니다.
    """
    print("Prisma Cloud 정책 생성 스크립트 시작...")

    # 1. JWT 토큰 획득 (한번만 로그인)
    jwt_token = get_jwt_token(ACCESS_KEY, SECRET_KEY)
    if not jwt_token:
        print("JWT 토큰 획득 실패. 종료합니다.")
        return

    # 2. CSV 파일 읽기
    if not os.path.exists(POLICY_CSV_FILE):
        print(f"오류: 정책 CSV 파일 '{POLICY_CSV_FILE}'을(를) 찾을 수 없습니다. 같은 디렉토리에 있는지 확인하세요.")
        return

    policies_processed = 0
    policies_failed = 0

    with open(POLICY_CSV_FILE, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        required_columns = ['RQL_QUERY', 'POLICY_NAME', 'POLICY_SEVERITY', 'POLICY_LABELS', 'POLICY_CLOUD_TYPE']
        # 'POLICY_NAME.1'은 필수는 아니지만, 있다면 POLICY_DESCRIPTION으로 사용합니다.
        
        if not all(col in reader.fieldnames for col in required_columns):
            print(f"오류: CSV에 하나 이상의 필수 컬럼이 누락되었습니다. 필수: {required_columns}")
            print(f"발견됨: {reader.fieldnames}")
            return

        for row_num, row in enumerate(reader, start=1):
            try:
                if process_policy_from_csv(jwt_token, row):
                    policies_processed += 1
                else:
                    policies_failed += 1
            except KeyError as e:
                print(f"오류: CSV {row_num} 행에 예상된 컬럼이 누락되었습니다: {e}. 해당 행을 건너뜁니다.")
                policies_failed += 1
            except Exception as e:
                print(f"CSV {row_num} 행 처리 중 예상치 못한 오류 발생: {e}. 해당 행을 건너뜁니다.")
                policies_failed += 1

    print(f"\n--- 스크립트 완료 ---")
    print(f"시도된 총 정책 수: {policies_processed + policies_failed}")
    print(f"성공적으로 처리된 정책 수: {policies_processed}")
    print(f"실패한 정책 수: {policies_failed}")

if __name__ == "__main__":
    main()