#!/bin/bash
# Installs reelbot as a macOS background service that starts at login and stays up.
set -euo pipefail

[ "$(uname)" = "Darwin" ] || { echo "reelbot's service runs on macOS only."; exit 1; }
command -v uv >/dev/null || { echo "Install uv first: https://docs.astral.sh/uv/getting-started/installation/"; exit 1; }
command -v claude >/dev/null || { echo "Install Claude Code and log in first: https://claude.com/claude-code"; exit 1; }

home="$HOME/.reelbot"
plist="$HOME/Library/LaunchAgents/com.reelbot.plist"
mkdir -p "$home/app" "$HOME/Library/LaunchAgents"
cp "$(dirname "$0")"/reelbot.py "$home/app/"
chmod +x "$home/app/reelbot.py"

if [ ! -s "$home/token" ]; then
  echo "Make a bot with @BotFather in Telegram, then paste its token here (it stays in $home/token):"
  read -rs token
  curl -fs "https://api.telegram.org/bot$token/getMe" >/dev/null || { echo "Telegram rejected that token. Run ./install.sh again."; exit 1; }
  (umask 077; printf '%s' "$token" > "$home/token")
fi

cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.reelbot</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/caffeinate</string><string>-i</string><string>-s</string>
    <string>$(command -v uv)</string><string>run</string><string>--script</string>
    <string>$home/app/reelbot.py</string>
  </array>
  <key>WorkingDirectory</key><string>$home/app</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>$(dirname "$(command -v claude)"):$(dirname "$(command -v uv)"):/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>PYTHONUNBUFFERED</key><string>1</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardOutPath</key><string>$home/bot.log</string>
  <key>StandardErrorPath</key><string>$home/bot.log</string>
</dict>
</plist>
PLIST

launchctl bootout "gui/$(id -u)/com.reelbot" 2>/dev/null || true
[ -s "$home/chat_id" ] || : > "$home/bot.log"  # so the pairing code printed below is this run's
launchctl bootstrap "gui/$(id -u)" "$plist"
echo "reelbot is running. Log: $home/bot.log"
if [ ! -s "$home/chat_id" ]; then
  echo "Waiting for the pairing code (the first start downloads its dependencies)..."
  until grep -q "Send this code" "$home/bot.log" 2>/dev/null; do sleep 2; done
  grep "Send this code" "$home/bot.log" | tail -1
fi
echo "Optional, for reels that say 'comment WORD and I'll DM you the link': $home/app/reelbot.py login"
