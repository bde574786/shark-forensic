import winreg
import pandas as pd
import os
import json

def get_registry_data(hive, subkey):
    try:
        with winreg.OpenKey(hive, subkey) as key:
            values = []
            index = 0
            while True:
                try:
                    value = winreg.EnumValue(key, index)
                    values.append(value)
                    index += 1
                except OSError as e:
                    break
            return values
    except OSError as e:
        print(f"레지스트리 키 열기 실패: {e}")
        return None

def get_registry_hierarchical_data(hive, key_path, depth=0, max_depth=None):
    
    if max_depth is not None and depth > max_depth:
        return {'info': 'Reached max depth'}

    try:
        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
            main_key = {}
            value_count = 0
            subkey_count = 0

            #
            while True:
                try:
                    name, value, type = winreg.EnumValue(key, value_count)
                    
                    if type == winreg.REG_BINARY:
                        value = value.hex()
                    elif type in (winreg.REG_SZ, winreg.REG_MULTI_SZ, winreg.REG_EXPAND_SZ):
                        value = value.rstrip('\x00')
                    main_key[name] = value
                    value_count += 1
                except OSError:
                    break

            # 서브키들을 재귀적으로 읽어서 main_key 사전에 추가합니다.
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, subkey_count)
                    subkey_path = f"{key_path}\\{subkey_name}"
                    subkey_values = get_registry_hierarchical_data(hive, subkey_path, depth + 1, max_depth)
                    main_key[subkey_name] = subkey_values
                    subkey_count += 1
                except OSError:
                    break
        return main_key
    
    except FileNotFoundError:
        print(f"Cannot find the key: {key_path}")
        return None


def get_registry_subkey(hive, subkey):
        try:
            with winreg.OpenKey(hive, subkey) as key:
                subkeys = []
                index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, index)
                        subkeys.append(subkey_name)
                        index += 1
                    except OSError:
                        break
                return subkeys
        except OSError as e:
            print(f"레지스트리 서브키 열기 실패: {e}")
        return None

def query_registry_data(hive, subkey, *value_names):
    results = []

    try:
        with winreg.OpenKey(hive, subkey) as key:
            for value_name in value_names:
                try:
                    value, _ = winreg.QueryValueEx(key, value_name)
                    results.append(value)
                except FileNotFoundError:
                    results.append(None)
                except OSError:
                    results.append(None)
    except OSError as e:
        print(f"레지스트리 키 열기 실패: {e}")
    
    return results


def save_to_excel(data, file_name, *column_names):
    folder_name = 'registry_data'
    if not os.path.exists(folder_name):
        os.mkdir(folder_name)

    df = pd.DataFrame(data, columns=column_names)

    file_path = os.path.join(folder_name, f"{file_name}.xlsx")
    df.to_excel(file_path, index=False, engine='openpyxl') 

def save_to_json(data, file_name):
    folder_name = 'registry_data'
    if not os.path.exists(folder_name):
        os.mkdir(folder_name)

    file_path = os.path.join(folder_name, f"{file_name}.json")
    with open(file_path, "w") as json_file:
        json.dump(data, json_file, indent=4)


class decryption:
    def decrypt_rot13(string):
        lower_letters = [chr(x) for x in range(97, 123)];
        upper_letters = [chr(x) for x in range(65, 91)];
        decrypt_string = ""

        for char in string:
            if char.isupper():
                original_index = upper_letters.index(char)
                new_index = (original_index + 13) % len(upper_letters)
                decrypt_string += upper_letters[new_index]
            elif char.islower():
                original_index = lower_letters.index(char)
                new_index = (original_index + 13) % len(lower_letters)
                decrypt_string += lower_letters[new_index]
            else:
                decrypt_string += char
        return decrypt_string



class HKEY_CURRENT_USER_Extractor:
    
    def extract_user_assist():
        hive = winreg.HKEY_CURRENT_USER
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
        data = get_registry_data(hive, key_path)
        result = []
    
        if data:
            for name, value, type in data:
                decrypted_name = decryption.decrypt_rot13(name)
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
        
        save_to_excel(result, "startup_programs", "name", "file_path")
    
    def extract_current_user_installed_programs():
        hive = winreg.HKEY_CURRENT_USER
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
        subkeys = get_registry_subkey(hive, key_path)
        result = []

        for i in range(len(subkeys)):
            subkey_path = fr"Software\Microsoft\Windows\CurrentVersion\Uninstall\{subkeys[i]}"
            result.append(query_registry_data(hive, subkey_path, "DisplayName", "DisplayIcon", "DisplayVersion", "InstallDate", "InstallLocation"))

        save_to_excel(result, "installed_programs", "display_name", "display_icon", "display_version", "install_date", "install_location")

    def extract_current_user_internet_settings():
        hive = winreg.HKEY_CURRENT_USER
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        result = get_registry_hierarchical_data(hive, key_path)
        save_to_json(result, "internet_settings")

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
        subkey_data = []

        for i in range(len(subkeys)):
            subkey_data = get_registry_data(hive, "{}\{}".format(key_path, subkeys[i]))
        
        print(key_data)
        print(subkey_data)

HKEY_CURRENT_USER_Extractor.extract_recent_search()