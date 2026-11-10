# /// script
# requires-python = ">=3.12"
# dependencies = ["playwright"]
# ///
"""Runs the DM button logic in real Chrome against a mock chat panel. Run: uv run --script test_buttons.py"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import reelbot as r
from playwright.sync_api import sync_playwright

PANEL = '''<div style="width:360px"><a role="button">View profile</a><div>
{buttons}</div><div role="textbox">Message</div></div>'''


def run(page, buttons, pressed=()):
    page.set_content(PANEL.format(buttons=buttons))
    return r.tap_button(page, list(pressed))


with sync_playwright() as pw:
    browser = pw.chromium.launch(channel="chrome", headless=True)
    page = browser.new_context().new_page()

    assert run(page, "") == ("", [])
    assert run(page, '<div role="button"><svg></svg></div><button>Delete chat history forever please do</button>') == ("", [])

    label, _ = run(page, '<div role="button" onclick="this.textContent=1">I\'m following</div><div role="button">Get link</div>')
    assert label == "I'm following", label

    label, _ = run(page, '<div role="button">Get link</div><div role="button" onclick="1">Continue</div>', ["continue"])
    assert label == "Get link", label

    label, opened = run(page, '''<div role="button" onclick="window.open('https://example.com/from-popup')">Get the link</div>''')
    assert label == "Get the link" and opened == ["https://example.com/from-popup"], (label, opened)
    assert r.external_links(opened) == ["https://example.com/from-popup"]
    assert len(page.context.pages) == 1

    label, opened = run(page, '''<div role="button" onclick="location.href='https://example.com/same-tab'">Open guide</div>''')
    assert label == "Open guide" and opened == ["https://example.com/same-tab"], (label, opened)

    page.set_content('<div role="textbox" contenteditable style="width:300px;height:30px" onkeydown="if(event.key==\'Enter\'){window.sent=this.innerText;event.preventDefault()}"></div>')
    r.answer_button(page, "SEND IT TO ME \u2705")
    assert page.evaluate("window.sent").strip() == "SEND IT TO ME \u2705", page.evaluate("window.sent")
    browser.close()
print("buttons ok")
