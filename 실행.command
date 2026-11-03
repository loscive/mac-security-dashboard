#!/bin/bash
# 더블클릭하면 Mac 보안 대시보드를 실행합니다. 종료하려면 이 터미널 창을 닫으세요.
cd "$(dirname "$0")"
exec /usr/bin/python3 security_dashboard.py
