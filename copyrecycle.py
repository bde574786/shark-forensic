import os
import shutil
import winshell
import time
import hashlib

def get_file_metadata(file_path):
    # 파일 메타데이터 조회 및 MD5 해시 계산 함수
    try:
        # 파일 크기
        size = os.path.getsize(file_path)

        # 마지막 수정 시간
        modification_time = os.path.getmtime(file_path)
        mod_time_readable = time.ctime(modification_time)

        # 파일 생성 시간 (Windows에서만 작동)
        creation_time = os.path.getctime(file_path)
        cre_time_readable = time.ctime(creation_time)

        # 파일의 MD5 해시값 계산
        md5_hash = calculate_md5(file_path)

        return size, mod_time_readable, cre_time_readable, md5_hash
    except Exception as e:
        print(f"Error retrieving metadata for {file_path}: {e}")
        return None

def calculate_md5(file_path):
    # 파일의 MD5 해시값을 계산하는 함수
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# 현재 디렉토리에 recyclelist 폴더를 만들기 위한 경로 설정
current_directory = os.getcwd()
restore_folder = os.path.join(current_directory, 'recyclelist')

# 지정된 폴더가 없으면 생성
if not os.path.exists(restore_folder):
    os.makedirs(restore_folder)
    print(f"Created folder: {restore_folder}")

# 휴지통 항목 가져오기
recycle_bin_items = list(winshell.recycle_bin())

# 휴지통의 모든 파일을 지정된 폴더로 복원
for item in recycle_bin_items:
    original_path = item.original_filename()
    file_name = os.path.basename(original_path)
    new_path = os.path.join(restore_folder, file_name)

    # 파일 복원
    winshell.undelete(original_path)
    print("-------------------------------")
    #print(f"File restored to original location: {original_path}")

    # 파일을 지정된 폴더로 이동 및 이름 변경하여 복제 (파일이 이미 존재하면 덮어쓰기)
    try:
        # UTF-8로 파일 경로 변환
        original_path = original_path.encode('utf-8').decode('utf-8')
        new_path = new_path.encode('utf-8').decode('utf-8')
        shutil.move(original_path, new_path)
        copy_file_name = "copy_" + file_name 
        copy_path = os.path.join(restore_folder, copy_file_name)
        copy_path = copy_path.encode('utf-8').decode('utf-8')
        shutil.copy2(new_path, copy_path)
    except shutil.SameFileError:
        pass
    
    #print(f"File moved to {new_path}")

    # 메타데이터 조회 및 MD5 해시 계산
    metadata = get_file_metadata(new_path) 
    if metadata:
        size, mod_time, cre_time, md5_hash = metadata
        print(f"File Name: {file_name}")
        print(f"File Size: {size} bytes")
        print(f"Last Modified: {mod_time}")
        print(f"Created: {cre_time}")
        print(f"MD5 Hash: {md5_hash}")
        print(f"original_path: {original_path}")

    # 파일을 다시 휴지통으로 이동
    winshell.delete_file(new_path, no_confirm=True, silent=True)
    print(f"File moved back to recycle bin: {new_path}")
