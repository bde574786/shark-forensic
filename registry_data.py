import winreg

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

            while True:
                try:
                    name, value, type = winreg.EnumValue(key, value_count)
                    
                    if type == winreg.REG_BINARY:
                        if value is not None:
                            value = value.hex()
                    elif type in (winreg.REG_SZ, winreg.REG_MULTI_SZ, winreg.REG_EXPAND_SZ):
                        if isinstance(value, str): 
                            value = value.rstrip('\x00')
                    main_key[name] = value
                    value_count += 1
                except OSError:
                    break

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