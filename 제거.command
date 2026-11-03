#!/bin/bash
# Mac 보안 대시보드 앱을 제거합니다. 더블클릭해서 실행하세요.
APP_NAME="Mac 보안 대시보드"
DATA="$HOME/Library/Application Support/MacSecurityDashboard"

pkill -f "Contents/Resources/security_dashboard.py" 2>/dev/null || true
for d in /Applications "$HOME/Applications"; do
  if [ -d "$d/$APP_NAME.app" ]; then
    rm -rf "$d/$APP_NAME.app" && echo "✔ 앱 제거: $d/$APP_NAME.app"
  fi
done

if [ -d "$DATA" ]; then
  read -r -p "격리함과 검사 기록도 지울까요? 휴지통으로 옮깁니다. (y/N) " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    mv "$DATA" "$HOME/.Trash/MacSecurityDashboard-$(date +%Y%m%d%H%M%S)" && echo "✔ 데이터를 휴지통으로 옮겼습니다."
  else
    echo "· 데이터는 남겨 두었습니다: $DATA"
  fi
fi
echo "제거가 끝났습니다. 이 창을 닫으셔도 됩니다."
