import sys
import time
import os
from PyQt5.QtWidgets import QApplication, QSplashScreen, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QCheckBox, QScrollArea
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap


class Shark(QWidget):
    button_names = ['Test1', 'Test2', 'Test3', 'Test4', 'Test5']  # 좌측 버튼명 리스트
    checkbox_names = [chr(i)
                      for i in range(ord('A'), ord('Z')+1)]  # 우측 체크박스 리스트

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Shark-Forensic')
        # 메인 레이아웃 (전체 수직 레이아웃)
        mainLayout = QVBoxLayout(self)

        # 수평 레이아웃 (좌측 | 우측)
        hbox = QHBoxLayout()

        # --- 좌측 레이아웃 영역
        leftWidget = QWidget()
        leftLayout = QVBoxLayout(leftWidget)
        self.buttons = []
        for name in self.button_names:
            btn = QPushButton(name, leftWidget)
            btn.clicked.connect(self.onButtonClick)
            self.buttons.append(btn)
            leftLayout.addWidget(btn)
            btn.setFixedHeight(100)

        leftWidget.setFixedWidth(300)  # 좌측 영역 Width

        # --- 우측 레이아웃 영역
        scrollWidget = QWidget()
        rightLayout = QVBoxLayout(scrollWidget)
        self.checkboxes = []
        for name in self.checkbox_names:
            cb = QCheckBox(name, scrollWidget)
            self.checkboxes.append(cb)
            rightLayout.addWidget(cb)

        scroll = QScrollArea()
        scroll.setWidget(scrollWidget)
        scroll.setWidgetResizable(True)
        scroll.setFixedWidth(500)  # 우측 영역 Width

        # 수평 레이아웃 박스에 좌우측 영역 추가
        hbox.addWidget(leftWidget)
        hbox.addWidget(scroll)

        # 하단 레이아웃
        bottomButtonLayout = QHBoxLayout()

        # 분석 시작 버튼
        self.startButton = QPushButton("분석 시작", self)
        self.startButton.setFixedHeight(50)
        self.startButton.clicked.connect(self.onButtonClick)
        bottomButtonLayout.addWidget(self.startButton)

        # 저장 버튼 (초기 비활성화 상태)
        self.saveButton = QPushButton("결과 저장", self)
        self.saveButton.setFixedHeight(50)
        self.saveButton.setFixedWidth(100)
        self.saveButton.setEnabled(False)
        bottomButtonLayout.addWidget(self.saveButton)

        # 초기화 버튼 추가
        self.restartButton = QPushButton("초기화", self)
        self.restartButton.setFixedHeight(50)
        self.restartButton.clicked.connect(self.onRestartButtonClick)
        self.restartButton.hide()  # 초기에 버튼 숨김

        # 메인 레이아웃 박스에 수평 레이아웃과 하단 레이아웃 추가
        mainLayout.addLayout(hbox)
        mainLayout.addLayout(bottomButtonLayout)
        mainLayout.setSpacing(10)

        # 메인 레이아웃을 감싸는 최상위 위젯 설정
        self.topLevelWidget = QWidget(self)
        self.topLevelWidget.setLayout(mainLayout)
        self.topLevelWidget.show()

    def onButtonClick(self):
        clicked_button = self.sender()

        if clicked_button == self.startButton:
            # 분석 시작 버튼 클릭 시
            self.startButton.setText("분석 완료")
            self.disableAllControls()  # 모든 컨트롤 비활성화
            self.saveButton.setEnabled(True)
            self.restartButton.show()  # 다시 시작 버튼 표시

        else:
            # 좌측 영역 버튼 클릭시
            button_index = self.buttons.index(clicked_button)
            start = button_index * 5
            end = min(start + 5, len(self.checkboxes))

            for cb in self.checkboxes:
                cb.setChecked(False)  # 체크박스 초기화

            for i in range(start, end):
                self.checkboxes[i].setChecked(True)  # 체크박스 그룹 활성화

    def disableAllControls(self):
        # 모든 버튼과 체크박스 비활성화
        for button in self.buttons:
            button.setEnabled(False)
        for checkbox in self.checkboxes:
            checkbox.setEnabled(False)
        self.startButton.setEnabled(False)

    def onRestartButtonClick(self):
        # 초기화 버튼 클릭 시
        self.enableAllControls()  # 모든 컨트롤 활성화
        self.startButton.setText("분석 시작")
        self.saveButton.setEnabled(False)
        self.restartButton.hide()  # 초기화 버튼 숨김

    def enableAllControls(self):
        # 모든 버튼과 체크박스 활성화
        for button in self.buttons:
            button.setEnabled(True)
        for checkbox in self.checkboxes:
            checkbox.setEnabled(True)
        self.startButton.setEnabled(True)
        self.uncheckAllCheckboxes()

    def resizeEvent(self, event):
        # 윈도우 크기 변경 시 "초기화" 버튼 위치 조정
        super(Shark, self).resizeEvent(event)
        button_width = 100
        button_height = 50
        x = (self.width() - button_width) / 2
        y = (self.height() - button_height) / 2
        self.restartButton.setGeometry(x, y, button_width, button_height)
        self.restartButton.raise_()  # 버튼을 다른 위젯 위에 표시

    def uncheckAllCheckboxes(self):
        # 모든 체크박스의 선택 해제
        for checkbox in self.checkboxes:
            checkbox.setChecked(False)


def main():
    app = QApplication(sys.argv)

    if getattr(sys, 'frozen', False):
        # 실행 파일로 패키징된 경우
        application_path = sys._MEIPASS
    else:
        # 개발 중인 경우 (스크립트 직접 실행)
        application_path = os.path.dirname(os.path.abspath(__file__))

    # 스플래시 화면 동작
    splash_image_path = os.path.join(application_path, 'splash.png')
    splash_pix = QPixmap(splash_image_path)
    scaled_splash_pix = splash_pix.scaled(
        800, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    splash = QSplashScreen(scaled_splash_pix, Qt.WindowStaysOnTopHint)
    splash.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
    splash.setEnabled(False)

    splash.show()
    ex = Shark()
    app.processEvents()
    time.sleep(2)
    ex.show()
    splash.finish(ex)
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
