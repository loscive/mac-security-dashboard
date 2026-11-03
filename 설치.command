#!/bin/bash
# Mac 보안 대시보드를 응용 프로그램 폴더에 앱으로 설치합니다. 더블클릭해서 실행하세요.
set -e
trap 'echo "✖ 설치 중 오류가 발생했습니다 (설치.command ${LINENO}번째 줄). 위의 메시지를 확인하세요."' ERR
cd "$(dirname "$0")"

APP_NAME="Mac 보안 대시보드"
BUNDLE_ID="local.macsecuritydashboard"
DEST="/Applications"
[ -w "$DEST" ] || DEST="$HOME/Applications"
mkdir -p "$DEST"
APP="$DEST/$APP_NAME.app"

echo "▶ Mac 보안 대시보드 설치"

if ! /usr/bin/python3 -c "import sys" >/dev/null 2>&1; then
  echo "✖ Python 3가 필요합니다. 터미널에서 'xcode-select --install' 을 실행해 개발자 도구를 설치한 뒤 다시 시도하세요."
  exit 1
fi
for f in security_dashboard.py dashboard.html AppIcon.icns; do
  [ -f "$f" ] || { echo "✖ $f 파일이 없습니다. 설치 파일을 모두 같은 폴더에 두세요."; exit 1; }
done

# 실행 중인 이전 버전 종료
pkill -f "Contents/Resources/security_dashboard.py" 2>/dev/null || true

# 앱 껍데기: 실행하면 대시보드 서버를 백그라운드로 띄우고 브라우저를 연다 (이미 실행 중이면 브라우저만).
# 서버는 준비되면 스스로 백그라운드로 빠지고, 시작에 실패하면 오류 메시지를 돌려줘 대화상자로 보여준다.
TMP="$(mktemp -d)"
cat > "$TMP/launcher.applescript" <<'APPLESCRIPT'
set py to POSIX path of (path to me) & "Contents/Resources/security_dashboard.py"
try
	do shell script "/usr/bin/python3 " & quoted form of py & " --launch"
on error errMsg
	display dialog "Mac 보안 대시보드를 시작하지 못했습니다." & return & return & errMsg buttons {"확인"} default button 1 with icon stop with title "Mac 보안 대시보드"
end try
APPLESCRIPT
osacompile -o "$TMP/$APP_NAME.app" "$TMP/launcher.applescript"

RES="$TMP/$APP_NAME.app/Contents/Resources"
cp security_dashboard.py dashboard.html "$RES/"
cp AppIcon.icns "$RES/applet.icns"
rm -f "$RES/Assets.car"  # 기본 스크립트 아이콘이 우리 아이콘을 덮어쓰지 않도록
PLIST="$TMP/$APP_NAME.app/Contents/Info.plist"
plutil -remove CFBundleIconName "$PLIST" 2>/dev/null || true
plutil -replace CFBundleIdentifier -string "$BUNDLE_ID" "$PLIST"
plutil -replace CFBundleName -string "$APP_NAME" "$PLIST"
plutil -replace CFBundleShortVersionString -string "1.0" "$PLIST"
if ! SIGN_OUT="$(codesign --force --deep -s - "$TMP/$APP_NAME.app" 2>&1)"; then
  echo "✖ 앱 서명에 실패했습니다:"; echo "$SIGN_OUT"; exit 1
fi

rm -rf "$APP"
mv "$TMP/$APP_NAME.app" "$APP"
rm -rf "$TMP"
xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true
touch "$APP"

echo "✔ 설치 완료: $APP"
echo "  Launchpad 또는 응용 프로그램 폴더에서 '$APP_NAME' 을 실행하세요."
echo "  Dock에 고정하려면 실행 중 Dock 아이콘을 오른쪽 클릭 → 옵션 → Dock에 유지."
open "$APP"
