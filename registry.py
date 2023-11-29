import winreg
import json

def get_registry_data(hive, key_path, depth=0, max_depth=1):
    if depth > max_depth:
        return {'info': 'Reached max depth'}

    try:
        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
            main_key = {}
            value_count = 0
            subkey_count = 0

            while True:
                try:
                    name, value, type = winreg.EnumValue(key, value_count)
                    main_key[name] = decode_utf16(value)
                    value_count += 1
                except OSError:
                    break

            while True:
                try:
                    subkey_name = winreg.EnumKey(key, subkey_count)
                    subkey_path = f"{key_path}\\{subkey_name}"
                    subkey_values = get_registry_data(hive, subkey_path, depth + 1, max_depth)

                    main_key[subkey_name] = subkey_values
                    subkey_count += 1
                except OSError:
                    break
        return main_key
    
    except FileNotFoundError:
        print(f"Cannot find the key: {key_path}")
        return {}

def decode_utf16(data):
    if isinstance(data, bytes):
        try:
            decoded_string = bytearray(data, 'utf-16le').decode('utf-16le')
            return decoded_string
        except UnicodeDecodeError:
            return data
    else:
        return data

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

def save_json(data, file_name):
    json_data = json.dumps(data, indent=4)

    with open(file_name, "w") as json_file:
        json_file.write(json_data)



class HKEY_CLASSES_ROOT_Extractor:

    # 특정 확장자와 연결되어 있는 애플리케이션(악성 파일 실행이나 문서 열람 등의 활동 추적 가능)
    @staticmethod
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
        associations = {}

        for i in range(len(extensions)):
            try:
                key_path = f"{extensions[i]}"
                associations[extensions[i]] = get_registry_data(hive, key_path, max_depth=2)
            except Exception as e:
                associations[i] = None
                print(e)
                
        return associations



class HKEY_CURRENT_USER_Extractor:

    # 시작 프로그램 목록
    @staticmethod
    def extract_current_user_startup_programs():
        hive = winreg.HKEY_CURRENT_USER
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        return get_registry_data(hive, key_path)

    # 설치된 프로그램 목록
    @staticmethod
    def extract_current_user_installed_programs():
        hive = winreg.HKEY_CURRENT_USER
        key_path = r"Software"
        return get_registry_data(hive, key_path)

    # 인터넷 설정 정보
    @staticmethod
    def extract_current_user_internet_settings():
        hive = winreg.HKEY_CURRENT_USER
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        return get_registry_data(hive, key_path)

    # 최근 문서 목록 정보
    @staticmethod
    def extract_recent_document():
        hive = winreg.HKEY_CURRENT_USER
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        return get_registry_data(hive, key_path)

    # 최근 검색 정보
    @staticmethod
    def extract_recent_search():
        hive = winreg.HKEY_CURRENT_USER
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
        return get_registry_data(hive, key_path)

    # 프린터 연결 정보
    @staticmethod
    def extract_print_history():
        hive = winreg.HKEY_CURRENT_USER
        key_path = r"Printers\Connections"
        return get_registry_data(hive, key_path)

    # 그룹 정책
    @staticmethod
    def extract_current_user_policy():
        hive = winreg.HKEY_CURRENT_USER
        key_path = r"SOFTWARE\Policies\Microsoft"
        return get_registry_data(hive, key_path, max_depth=3)

    # 보안 인증서 및 인증 기관
    @staticmethod
    def extract_current_user_security_authentication():
        hive = winreg.HKEY_CURRENT_USER
        key_path = r"Software\Microsoft\SystemCertificates"
        return get_registry_data(hive, key_path)



class HKEY_LOCAL_MACHINE_Extractor:

    # 시작 프로그램 목록
    @staticmethod
    def extract_all_users_startup_programs():
        hive = winreg.HKEY_LOCAL_MACHINE
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        return get_registry_data(hive, key_path)

    # USB 장치의 연결 및 이력 정보
    @staticmethod
    def extract_usb_history():
        hive = winreg.HKEY_LOCAL_MACHINE
        key_path = r"SYSTEM\CurrentControlSet\Enum\USB"
        return get_registry_data(hive, key_path)

    # 설치된 프로그램 목록    
    @staticmethod
    def extract_all_users_installed_programs():
        hive = winreg.HKEY_LOCAL_MACHINE
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        return get_registry_data(hive, key_path)

    # 로그온 UI 설정 정보
    @staticmethod
    def extract_logon_ui_settings():
        hive = winreg.HKEY_LOCAL_MACHINE
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
        return get_registry_data(hive, key_path)

    # 시스템 서비스 설정 및 정보
    @staticmethod
    def extract_system_services():
        hive = winreg.HKEY_LOCAL_MACHINE
        key_path = r"SYSTEM\CurrentControlSet\Services"
        return get_registry_data(hive, key_path, max_depth=4)

    # 네트워크 어댑터 설정 정보
    @staticmethod
    def extract_network_adapters():
        hive = winreg.HKEY_LOCAL_MACHINE
        key_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        return get_registry_data(hive, key_path)
    
    # 그룹 보안 정책
    @staticmethod
    def extract_local_machine_policy():
        hive = winreg.HKEY_LOCAL_MACHINE
        key_path = r"SOFTWARE\Policies\Microsoft"
        return get_registry_data(hive, key_path, max_depth=4)

    # 방화벽 정책
    @staticmethod
    def extract_firewall_policy():
        hive = winreg.HKEY_LOCAL_MACHINE
        key_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        return get_registry_data(hive, key_path)

    # 보안 공급자 및 인증
    @staticmethod
    def extract_security_providers():
        hive = winreg.HKEY_LOCAL_MACHINE
        key_path = r"SYSTEM\CurrentControlSet\Control\SecurityProviders"
        return get_registry_data(hive, key_path)

    # 보안 인증서 및 인증 기관
    def extract_local_machine_security_authentication():
        hive = winreg.HKEY_LOCAL_MACHINE
        key_path = r"SOFTWARE\Microsoft\SystemCertificates"
        return get_registry_data(hive, key_path)

    # 네트워크 프로필
    def extract_network_profile():
        hive = winreg.HKEY_LOCAL_MACHINE
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
        return get_registry_data(hive, key_path)

class HKEY_USERS_Extractor:

    # 현재 사용자의 응용 프로그램 정보
    @staticmethod
    def extract_user_application_history():
        hive = winreg.HKEY_USERS
        sid = get_current_user_sid()
        key_path = fr"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        return get_registry_data(hive, key_path)


#save_json(HKEY_LOCAL_MACHINE_Extractor.extract_local_machine_security_authentication(), "registry_data.json")
print(HKEY_LOCAL_MACHINE_Extractor.extract_system_services())


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
