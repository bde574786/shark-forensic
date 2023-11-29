import win32evtlog as wevt
import ctypes, sys, os

# 보안 로그에 접근하기 위해 관리자 권한 필요
server = 'localhost'
logtype_sec = 'Security'
logtype_app = 'Application'
logtype_sys = 'System'

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def security_log():
    if is_admin():
        hand_sec = wevt.OpenEventLog(server, logtype_sec)
        flags = wevt.EVENTLOG_BACKWARDS_READ | wevt.EVENTLOG_SEQUENTIAL_READ
        total = wevt.GetNumberOfEventLogRecords(hand_sec)
        
        # 현재 경로에 'SecurityLogs' 폴더 생성 (폴더가 이미 존재하지 않는 경우에만)
        os.makedirs('EventLogs', exist_ok=True)

        # 'SecurityLogs' 폴더 내에 로그 파일 저장
        with open('EventLogs/Security_logs.txt', 'w', encoding='utf-8') as log_file:
            while True:
                events = wevt.ReadEventLog(hand_sec, flags, 0)
                if not events:
                    break

                for evt in events:
                    event_id = evt.EventID & 0xFFFF
                    log_file.write(f'이벤트 카테고리: {evt.EventCategory}\n')
                    log_file.write(f'생성 시간: {evt.TimeGenerated}\n')
                    log_file.write(f'소스 이름: {evt.SourceName}\n')
                    log_file.write(f'이벤트 ID: {event_id}\n')
                    log_file.write(f'이벤트 유형: {evt.EventType}\n')

                    data = evt.StringInserts
                    if data:
                        log_file.write('이벤트 데이터:\n')
                        for msg in data:
                            log_file.write(f'{msg}\n')

                    log_file.write('*' * 100 + '\n')
    else:
    # 관리자 권한이 없을 경우, 스크립트를 관리자 권한으로 재실행
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

def application_log():
    hand_app = wevt.OpenEventLog(server, logtype_app)
    flags = wevt.EVENTLOG_BACKWARDS_READ | wevt.EVENTLOG_SEQUENTIAL_READ
    total = wevt.GetNumberOfEventLogRecords(hand_app)
    
    # 현재 경로에 'SecurityLogs' 폴더 생성 (폴더가 이미 존재하지 않는 경우에만)
    os.makedirs('EventLogs', exist_ok=True)

    # 'SecurityLogs' 폴더 내에 로그 파일 저장
    with open('EventLogs/Application_logs.txt', 'w', encoding='utf-8') as log_file:
        while True:
            events = wevt.ReadEventLog(hand_app, flags, 0)
            if not events:
                break

            for evt in events:
                event_id = evt.EventID & 0xFFFF
                log_file.write(f'이벤트 카테고리: {evt.EventCategory}\n')
                log_file.write(f'생성 시간: {evt.TimeGenerated}\n')
                log_file.write(f'소스 이름: {evt.SourceName}\n')
                log_file.write(f'이벤트 ID: {event_id}\n')
                log_file.write(f'이벤트 유형: {evt.EventType}\n')

                data = evt.StringInserts
                if data:
                    log_file.write('이벤트 데이터:\n')
                    for msg in data:
                        log_file.write(f'{msg}\n')

                log_file.write('*' * 100 + '\n')

def system_log():       
    hand_sys = wevt.OpenEventLog(server, logtype_sys)
    flags = wevt.EVENTLOG_BACKWARDS_READ | wevt.EVENTLOG_SEQUENTIAL_READ
    total = wevt.GetNumberOfEventLogRecords(hand_sys)
    
    # 현재 경로에 'SecurityLogs' 폴더 생성 (폴더가 이미 존재하지 않는 경우에만)
    os.makedirs('EventLogs', exist_ok=True)

    # 'SecurityLogs' 폴더 내에 로그 파일 저장
    with open('EventLogs/System_logs.txt', 'w', encoding='utf-8') as log_file:
        while True:
            events = wevt.ReadEventLog(hand_sys, flags, 0)
            if not events:
                break

            for evt in events:
                event_id = evt.EventID & 0xFFFF
                log_file.write(f'이벤트 카테고리: {evt.EventCategory}\n')
                log_file.write(f'생성 시간: {evt.TimeGenerated}\n')
                log_file.write(f'소스 이름: {evt.SourceName}\n')
                log_file.write(f'이벤트 ID: {event_id}\n')
                log_file.write(f'이벤트 유형: {evt.EventType}\n')

                data = evt.StringInserts
                if data:
                    log_file.write('이벤트 데이터:\n')
                    for msg in data:
                        log_file.write(f'{msg}\n')

                log_file.write('*' * 100 + '\n')
if __name__ == "__main__":
    security_log()  # 보안 로그 기록
    application_log()  # 애플리케이션 로그 기록
    system_log()  # 시스템 로그 기록






