# reelbot

Send a Reel, TikTok, YouTube Short, X video, GitHub link, web page or PDF to your own Telegram bot.
Claude works out which Claude Code skill, MCP server or project it describes, checks it, and sets it up on your Mac.

It runs as a background service, so it works while you are away from the computer.

## What it does

| You send | The bot does |
| --- | --- |
| A video link | Downloads it, transcribes it, reads the frames, and finds the tool it promotes. |
| A GitHub link | Clones it into quarantine, reviews it, and offers to install it. |
| A "comment WORD and I'll DM you" reel | After one tap: follows the creator, comments the word, answers the buttons in their DM, and reads the link they send. |
| A web page, PDF or text file | Builds what it describes in a sandbox folder. |
| A description (40+ characters) | Builds it in a sandbox folder. |

Commands: `/list`, `/status`, `/check`, `/remove NAME`, `/cancel`, `/help`.

## Install (macOS)

You need [uv](https://docs.astral.sh/uv/getting-started/installation/), [Claude Code](https://claude.com/claude-code) (logged in), git and Google Chrome.

1. In Telegram, message [@BotFather](https://t.me/BotFather), send `/newbot`, and copy the token.
2. Run:

   ```bash
   git clone https://github.com/adamissac/reelbot && cd reelbot && ./install.sh
   ```

3. Paste the token when asked. The installer prints a pairing code. Send that code to your bot.
4. Optional, for comment-to-DM reels: run `~/.reelbot/app/reelbot.py login` and log in to Instagram in the window that opens. The bot keeps this login in its own browser profile and never sees your password.

Check the setup at any time with `~/.reelbot/app/reelbot.py doctor`. The log is `~/.reelbot/bot.log`.

To try one link with no bot and no installs: `./reelbot.py URL`.

## Safety

Videos, repos and DMs come from strangers, so the bot treats all of them as untrusted.

- Only the Telegram chat you paired can give it orders.
- Claude only reads untrusted content, with no shell, web or connector access. Fixed code in `reelbot.py` makes every change.
- Every repo is cloned into quarantine and reviewed. A repo judged malicious is blocked.
- Nothing is installed without your Yes. The one exception is a text-only skill from a GitHub link you sent yourself that passes every check.
- Builds run in a sandbox under `/Users/Shared/reelbot-builds`, with no access to your home folder.
- It never types passwords or keys, creates accounts, or pays for anything.
- Its Instagram browser can only open instagram.com pages.

Commenting, following and replying use your Instagram account through the normal website. Automation may be against Instagram's terms, so use that part at your own risk.

## Tests

```bash
uv run --python 3.12 test_reelbot.py
uv run --script test_buttons.py
```

## Uninstall

```bash
launchctl bootout gui/$(id -u)/com.reelbot; rm ~/Library/LaunchAgents/com.reelbot.plist
```

Your data stays in `~/.reelbot` until you delete it.

## License

MIT
