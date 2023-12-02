import struct
from decryption import *
from decoding import *
from registry_data import *
from data_saver import *

def get_current_user_sid():
    import locale
    import subprocess
    import re
    
    command = "whoami /user"
    output = subprocess.check_output(command, shell=True).decode(locale.getpreferredencoding())
    sid_pattern = re.compile(r'S-1-\d+-(\d+-)*\d+')
    sid_match = sid_pattern.search(output)

    if sid_match:
        return sid_match.group(0)
    else:
        return "No SID"

def extract_user_assist():
    hive = winreg.HKEY_CURRENT_USER
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
    data = get_registry_data(hive, key_path)
    result = []

    if data:
        for name, value, type in data:
            decrypted_name = decrypt_rot13(name)
            if ".exe" in decrypted_name:
                result.append([decrypted_name])
        
    save_to_excel(result, "user_assist", 'file path')

def extract_current_user_startup_programs():
    hive = winreg.HKEY_CURRENT_USER
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    data = get_registry_data(hive, key_path)
    result = []

    for name, value, type in data:
        result.append([name, value])
    
    save_to_excel(result, "current_user_startup_programs", "name", "file_path")

def extract_current_user_installed_programs():
    hive = winreg.HKEY_CURRENT_USER
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    subkeys = get_registry_subkey(hive, key_path)
    result = []

    for i in range(len(subkeys)):
        subkey_path = fr"Software\Microsoft\Windows\CurrentVersion\Uninstall\{subkeys[i]}"
        result.append(query_registry_data(hive, subkey_path, "DisplayName", "DisplayIcon", "DisplayVersion", "InstallDate", "InstallLocation"))

    save_to_excel(result, "current_user_installed_programs", "display_name", "display_icon", "display_version", "install_date", "install_location")

def extract_current_user_internet_settings():
    hive = winreg.HKEY_CURRENT_USER
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    result = get_registry_hierarchical_data(hive, key_path)
    save_to_json(result, "current_user_internet_settings")

# Decodig Todo
def extract_recent_document():
    hive = winreg.HKEY_CURRENT_USER
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    return get_registry_data(hive, key_path)

def extract_recent_url():
    hive = winreg.HKEY_CURRENT_USER
    key_path = r"Software\Microsoft\Internet Explorer\TypedURLs"
    result = []

    data = get_registry_data(hive, key_path)
    for i in range(len(data)):
        result.append(data[i][1])

    save_to_excel(result, "recent_urls", "url")


def extract_recent_search():
    hive = winreg.HKEY_CURRENT_USER
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
    key_data = get_registry_data(hive, key_path)
    subkeys = get_registry_subkey(hive, key_path)
    
    all_searches = {}

    main_searches = extract_searches_from_key_data(key_data)
    if main_searches:
        all_searches["Main"] = main_searches

    for subkey in subkeys:
        subkey_data = get_registry_data(hive, "{}\{}".format(key_path, subkey))
        subkey_searches = extract_searches_from_key_data(subkey_data)
        if subkey_searches:
            all_searches[subkey] = subkey_searches
    
    data = ""

    for key, searches in all_searches.items():
        data += f"Key: {key}\n"
        for search in searches:
            data += f"  - {search}\n"
    save_to_notepad(data, "recent_research")

def extract_searches_from_key_data(key_data):
    mru_list_ex_value = next((item for item in key_data if item[0] == 'MRUListEx'), None)
    if mru_list_ex_value is None:
        return []

    mru_list_ex_data = mru_list_ex_value[1]
    mru_indexes = struct.unpack('<' + 'I' * (len(mru_list_ex_data) // 4), mru_list_ex_data)
    mru_indexes = [index for index in mru_indexes if index != 0xFFFFFFFF]

    searches = []
    for index in mru_indexes:
        search_data_value = next((item for item in key_data if item[0] == str(index)), None)
        if search_data_value:
            search_data = search_data_value[1]
            searches.append(decode_utf16(search_data))
    return searches
    
def extract_print_history():
    hive = winreg.HKEY_CURRENT_USER
    key_path = r"Printers"
    result = get_registry_hierarchical_data(hive, key_path)
    save_to_json(result, 'print_history')

def extract_current_user_policy():
    hive = winreg.HKEY_CURRENT_USER
    key_path = r"SOFTWARE\Policies\Microsoft"
    result = get_registry_hierarchical_data(hive, key_path)
    save_to_json(result, 'user_policy')

def extract_current_user_security_authentication():
    hive = winreg.HKEY_CURRENT_USER
    key_path = r"Software\Microsoft\SystemCertificates"
    result = get_registry_hierarchical_data(hive, key_path)
    save_to_json(result, 'user_security_authentication')

def extract_file_associations():
    extensions = [
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".txt", ".rtf", ".jpg", ".jpeg", ".png",
        ".gif", ".bmp", ".tif", ".tiff", ".mp3", ".wav",
        ".mp4", ".mov", ".avi", ".mkv", ".zip", ".rar",
        ".7z", ".exe", ".msi", ".bat", ".sh", ".html",
        ".htm", ".css", ".js", ".json", ".xml", ".c",
        ".cpp", ".py", ".java", ".php", ".dll"
    ]

    hive = winreg.HKEY_CLASSES_ROOT
    result = {}

    for i in range(len(extensions)):
        try:
            key_path = f"{extensions[i]}"
            result[extensions[i]] = get_registry_hierarchical_data(hive, key_path)
        except Exception as e:
            result[i] = None
            
    save_to_json(result, 'file_associations')

def extract_all_users_startup_programs():
        hive = winreg.HKEY_LOCAL_MACHINE
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        data = get_registry_data(hive, key_path)
        result = []

        for name, value, type in data:
            result.append([name, value])

        save_to_excel(result, "all_users_startup_programs", "name", "file_path")

def extract_usb_history():
    hive = winreg.HKEY_LOCAL_MACHINE
    key_path = r"SYSTEM\CurrentControlSet\Enum\USB"
    result = get_registry_hierarchical_data(hive, key_path)
    save_to_json(result, "usb_history")

def extract_all_users_installed_programs():
    hive = winreg.HKEY_LOCAL_MACHINE
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    subkeys = get_registry_subkey(hive, key_path)
    result = []

    for i in range(len(subkeys)):
        subkey_path = fr"Software\Microsoft\Windows\CurrentVersion\Uninstall\{subkeys[i]}"
        result.append(query_registry_data(hive, subkey_path, "DisplayName", "DisplayIcon", "DisplayVersion", "InstallDate", "InstallLocation"))

    save_to_excel(result, "all_users_installed_programs", "display_name", "display_icon", "display_version", "install_date", "install_location")

def extract_logon_ui_settings():
    hive = winreg.HKEY_LOCAL_MACHINE
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
    result = get_registry_hierarchical_data(hive, key_path)
    
    save_to_json(result, "logon_ui_settings")

def extract_system_services():
    hive = winreg.HKEY_LOCAL_MACHINE
    key_path = r"SYSTEM\CurrentControlSet\Services"
    result = get_registry_hierarchical_data(hive, key_path)

    save_to_json(result, "system_services")

def extract_network_adapters():
    hive = winreg.HKEY_LOCAL_MACHINE
    key_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    result = get_registry_hierarchical_data(hive, key_path)

    save_to_json(result, "network_adapters")

def extract_local_machine_policy():
    hive = winreg.HKEY_LOCAL_MACHINE
    key_path = r"SOFTWARE\Policies\Microsoft"
    result = get_registry_hierarchical_data(hive, key_path)

    save_to_json(result, "local_machine_policy")

def extract_firewall_policy():
    hive = winreg.HKEY_LOCAL_MACHINE
    key_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
    result = get_registry_hierarchical_data(hive, key_path)

    save_to_json(result, "firewall_policy")

def extract_security_providers():
    hive = winreg.HKEY_LOCAL_MACHINE
    key_path = r"SYSTEM\CurrentControlSet\Control\SecurityProviders"
    result = get_registry_hierarchical_data(hive, key_path)

    save_to_json(result, "security_providers")

def extract_local_machine_security_authentication():
    hive = winreg.HKEY_LOCAL_MACHINE
    key_path = r"SOFTWARE\Microsoft\SystemCertificates"
    result = get_registry_hierarchical_data(hive, key_path)

    save_to_json(result, "local_machine_security_authentication")

def extract_network_profile():
    hive = winreg.HKEY_LOCAL_MACHINE
    key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
    result = get_registry_hierarchical_data(hive, key_path)

    save_to_json(result, "network_profile")

def extract_user_application_history():
        hive = winreg.HKEY_USERS
        sid = get_current_user_sid()
        key_path = fr"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        result = get_registry_hierarchical_data(hive, key_path)

        save_to_json(result, "user_application_history")


'''
사전 프로파일
1. 사이버 공격 사건 (Cyber Attack Incident)
목표: 악성 소프트웨어 활동, 무단 접근, 시스템 변경 등을 추적
포함할 키:
    - 시작 프로그램 (Run keys)
        HKEY_LOCAL_MACHINE_Extractor.extract_all_users_startup_programs()
        HKEY_CURRENT_USER_Extractor.extract_current_user_startup_programs()
    - 설치된 소프트웨어 (Software installations)
        HKEY_LOCAL_MACHINE_Extractor.extract_all_users_installed_programs()
        HKEY_CURRENT_USER_Extractor.extract_current_user_installed_programs()
    - 시스템 서비스 및 드라이버 (System services and drivers)
        HKEY_LOCAL_MACHINE_Extractor.extract_system_services()
    - 네트워크 연결 기록 (Network connections)
        HKEY_LOCAL_MACHINE.extract_network_adapters() 또는 이벤트 로그

2. 사용자 활동 모니터링 (User Activity Monitoring)
목표: 특정 사용자의 컴퓨터 사용 패턴 및 활동 이력 추적
포함할 키:
    - 최근 사용한 문서 및 파일 (Recent documents and files) -> 사용자 특수 폴더로 접근
        %userprofile%\AppData\Roaming\Microsoft\Windows\Recent 최근 폴더
        %userprofile%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations 작업폴더
        %userprofile%\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations 작업 폴더
    - 시작 메뉴 사용 기록 (Start menu usage)
        %userprofile%\AppData\Roaming\Microsoft\Windows\Recent  최근 실행한 항목에 대한 바로가기
        %userprofile%\AppData\Local\Microsoft\Windows\Explorer\RecentDocs 시작 메뉴 및 탐색기 관련 사용 기록
    - 파일 다운로드 기록 (File download history)
        브라우저 캐시
    - USB 장치 사용 기록 (USB device history)
        이벤트 로그

3. 기업 보안 감사 (Corporate Security Audit)
목표: 기업의 컴퓨터 보안 정책 준수 여부 확인
포함할 키:
    - 시스템 보안 정책 (System security policies)
        HKEY_LOCAL_MACHINE_Extractor.extract_local_machine_policy()
        HKEY_CURRENT_USER_Extractor.extract_current_user_policy()
    - 방화벽 및 보안 설정 (Firewall and security settings)
        HKEY_LOCAL_MACHINE_Extractor.extract_local_machine_security_authentication()
        HKEY_CURRENT_USER_Extractor.extract_current_user_security_authentication()
    - 네트워크 프로필 (Network profiles)
        HKEY_LOCAL_MACHINE_Extractor.extract_network_profile()
    - 프린터 사용 기록 (Printer usage)
        이벤트 로그나 프린터 서비스 로그 파일
    
4. 절도 또는 물리적 침입 사건 (Theft or Physical Intrusion)
목표: 물리적 침입 후 컴퓨터 사용 여부 및 활동 추적
포함할 키:
    - 시스템 로그온 정보 (System logon information)
        보안 로그나 시스템 로그
    - USB 장치 사용 기록 (USB device history)
        이벤트 로그
    - 최근 사용한 파일 (Recently used files)
        %userprofile%\AppData\Roaming\Microsoft\Windows\Recent
    - 시스템 복원 및 백업 정보 (System restore and backup)
        파일 시스템
'''


# HKEY_CLASSES_ROOT
extract_file_associations() # 자주쓰는 파일 확장자의 연결된 프로그램 목록

# HKEY_CURRENT_USER
extract_user_assist() # 실행된 프로그램
extract_current_user_startup_programs() # 시작 프로그램 정보
extract_current_user_installed_programs() # 설치된 프로그램
extract_current_user_internet_settings() # 인터넷 설정
extract_recent_document() # 최근 문서 목록
extract_recent_url() # Internet Explorer 브라우저에 입력한 URL 목록
extract_recent_search() # 파일 탐색기에 입력한 검색어 기록
extract_print_history() # 프린터 정보
extract_current_user_policy() # 그룹 보안 정책 
extract_current_user_security_authentication() # 보안 인증서 및 인증 기관

# HKEY_LOCAL_MACHINE 
extract_all_users_startup_programs() # 시작 프로그램 정보
extract_usb_history() # USB 장치의 연결 및 이력 정보
extract_all_users_installed_programs() # 설치된 프로그램 목록 
extract_logon_ui_settings() # 로그온 UI 설정 정보
extract_system_services() # 시스템 서비스 설정 및 정보
extract_network_adapters() # 네트워크 어댑터 설정 정보 
extract_local_machine_policy() # 그룹 보안 정책
extract_firewall_policy() # 방화벽 정책
extract_security_providers() # 보안 공급자 및 인증
extract_local_machine_security_authentication() # 보안 인증서 및 인증 기관
extract_network_profile() # 네트워크 프로필

# HKEY_USERS
extract_user_application_history() # 현재 사용자의 응용 프로그램 정보
