import pandas as pd
import os
import json

def save_to_excel(data, file_name, *column_names):
    folder_name = 'registry_data'
    if not os.path.exists(folder_name):
        os.mkdir(folder_name)
    data = [row for row in data if any(item is not None for item in row)]
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

def save_to_notepad(data, file_name):
    folder_name = 'registry_data'
    if not os.path.exists(folder_name):
        os.mkdir(folder_name)
    
    file_path = os.path.join(folder_name, f"{file_name}.txt")
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(data)