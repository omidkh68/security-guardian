#!/usr/bin/env python3
"""Dependency-free, keyboard-driven front end for the offline installer."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

AGENTS = ("claude", "codex", "gemini")
LABELS = ("Claude Code", "OpenAI Codex", "Gemini CLI")
REPO = Path(__file__).resolve().parent.parent
PACKAGE = REPO / "plugins/security-guardian"
URL = "https://github.com/omidkh68/security-guardian"
TAGLINE = "Security auditing, safe remediation and versioned PDF reports"


class Cancelled(Exception):
    pass


def metadata():
    """Read shipping metadata rather than advertising an invented release."""
    version = "unknown"
    author = "Security Guardian contributors"
    try:
        version = (PACKAGE / "skills/security-guardian/VERSION").read_text().strip()
        manifest = json.loads((PACKAGE / ".claude-plugin/plugin.json").read_text())
        author = manifest.get("author", {}).get("name") or author
    except (OSError, ValueError, AttributeError):
        pass
    return version, author


def clean(value):
    # Keep control characters (including terminal escape sequences) off screen.
    return "".join(c if c.isprintable() else "?" for c in str(value))


def color(text, code):
    if sys.stdout.isatty() and os.environ.get("TERM") not in ("", "dumb", None) and "NO_COLOR" not in os.environ:
        return "\033[" + code + "m" + text + "\033[0m"
    return text


def banner(step):
    version, author = metadata()
    print()
    print(color("SECURITY GUARDIAN  /  SETUP", "1;36"))
    print(f"v{clean(version)}  |  Maintainer: omidkh68")
    print("Author: " + clean(author))
    print(TAGLINE)
    print(URL)
    print(color("-" * 52, "36"))
    print(color(step, "1;36"))


def read_prompt(prompt):
    """Retry malformed terminal input; never transform it into consent."""
    while True:
        try:
            value = input(prompt)
        except UnicodeDecodeError:
            print("Invalid text encoding. Please type your response again.")
            continue
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            print("Invalid text encoding. Please type your response again.")
            continue
        return value.strip()


def confirm_install():
    prompt = "Apply this plan (including backups for existing copies)? [y/N] "
    while True:
        answer = read_prompt(prompt).lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("", "n", "no", "q"):
            return False
        print("Please enter y/yes to install, or n/no to cancel (English keyboard).")


def choose_plain(title, options, multiple=False, *, step="", detail="", statuses=()):
    banner(step)
    print(title)
    if detail:
        print(detail)
    for i, option in enumerate(options, 1):
        suffix = f"  [{statuses[i-1]}]" if statuses else ""
        print(f"  {i}. {option}{suffix}")
    while True:
        raw = read_prompt("Numbers (comma-separated, q to cancel): " if multiple else "Number (q to cancel): ")
        if raw.lower() == "q":
            raise Cancelled()
        try:
            picks = sorted({int(x.strip()) - 1 for x in raw.split(",")})
            if picks and all(0 <= x < len(options) for x in picks) and (multiple or len(picks) == 1):
                return picks
        except ValueError:
            pass
        print("Select at least one valid option.")


def choose(title, options, multiple=False, *, step="", detail="", statuses=()):
    def fallback():
        return choose_plain(title, options, multiple, step=step, detail=detail, statuses=statuses)
    if os.environ.get("TERM", "") in ("", "dumb"):
        return fallback()
    try:
        import curses
        curses.setupterm()
    except ImportError:
        return fallback()
    except curses.error:
        return fallback()
    size = shutil.get_terminal_size()
    if size.columns < 36 or size.lines < len(options) + 6:
        return fallback()

    def screen(win):
        cursor = 0
        selected = set()
        hint = ""
        version, author = metadata()
        win.keypad(True)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        styles = {"brand": curses.A_BOLD, "muted": curses.A_DIM,
                  "good": curses.A_BOLD, "warn": curses.A_BOLD,
                  "active": curses.A_REVERSE | curses.A_BOLD}
        if curses.has_colors() and "NO_COLOR" not in os.environ:
            try:
                curses.start_color()
                try:
                    curses.use_default_colors()
                    bg = -1
                except curses.error:
                    bg = curses.COLOR_BLACK
                for i, (name, fg, emphasis) in enumerate((
                    ("brand", curses.COLOR_CYAN, curses.A_BOLD),
                    ("good", curses.COLOR_GREEN, curses.A_BOLD),
                    ("warn", curses.COLOR_YELLOW, curses.A_BOLD),
                    ("muted", curses.COLOR_WHITE, curses.A_DIM),
                ), 1):
                    curses.init_pair(i, fg, bg)
                    styles[name] = curses.color_pair(i) | emphasis
            except curses.error:
                pass

        while True:
            win.erase()
            height, width = win.getmaxyx()
            if height < len(options) + 6 or width < 30:
                raise Cancelled("Terminal too small; resize and try again.")
            def put(y, x, text, style=0):
                if 0 <= y < height and 0 <= x < width-1:
                    win.addnstr(y, x, clean(text), width-x-1, style)
            full = height >= len(options)+14
            put(0, 1, "SECURITY GUARDIAN  /  SETUP", styles["brand"])
            if full:
                put(1, 1, f"v{version}  |  Maintainer: omidkh68", styles["brand"])
                put(2, 1, "Author: "+author, styles["muted"])
                put(3, 1, TAGLINE, styles["muted"])
                put(4, 1, URL, styles["muted"])
                put(5, 1, "─" * (width-3), styles["brand"])
                put(6, 1, step+"  /  "+title, curses.A_BOLD)
                put(7, 1, detail, styles["muted"])
                first = 9
                stride = 1
            else:
                put(1, 1, f"v{version} | omidkh68 | {step}", styles["muted"])
                put(2, 1, title, curses.A_BOLD)
                first, stride = 3, 1
            for i, option in enumerate(options):
                mark = "[x]" if i in selected else "[ ]"
                prefix = ("> " if cursor == i else "  ") + (mark+" " if multiple else "")
                attr = styles["active"] if cursor == i else styles["good"] if i in selected else curses.A_NORMAL
                row = first+i*stride
                if statuses and width >= 58:
                    put(row, 1, (prefix+option).ljust(29), attr)
                    detected = statuses[i] == "CLI detected"
                    put(row, 31, ("+ " if detected else "! ")+statuses[i],
                        styles["good"] if detected else styles["warn"])
                else:
                    suffix = " | "+statuses[i] if statuses else ""
                    put(row, 1, prefix+option+suffix, attr)
            after = first+len(options)*stride
            if multiple:
                put(after, 1, f"Selected: {len(selected)} / {len(options)} agent(s)", styles["good"])
            elif full:
                put(after, 1, "Enter confirms this scope; no files written yet.", styles["muted"])
            if full:
                put(after+1, 1, "Codex and Gemini share a skill directory.", styles["muted"])
            put(height-2, 1, hint or ("↑↓ Move · Space Toggle · Enter Continue · q Cancel" if multiple else "↑↓ Move · Enter Continue · q Cancel"),
                styles["warn"] if hint else styles["brand"])
            win.refresh()
            key = win.getch()
            if key in (ord("q"), 27):
                raise Cancelled()
            if key in (curses.KEY_UP, ord("k")):
                cursor = (cursor-1) % len(options)
            elif key in (curses.KEY_DOWN, ord("j")):
                cursor = (cursor+1) % len(options)
            elif key == ord(" ") and multiple:
                selected.symmetric_difference_update({cursor})
                hint = ""
            elif key in (10, 13, curses.KEY_ENTER):
                if not multiple:
                    return [cursor]
                if selected:
                    return sorted(selected)
                hint = "Select at least one agent with Space."
    return curses.wrapper(screen)


def plan(agents, base):
    paths = []
    if "claude" in agents:
        paths.append(base / ".claude" / "skills" / "security-guardian")
    if {"codex", "gemini"}.intersection(agents):
        paths.append(base / ".agents" / "skills" / "security-guardian")
    return paths


def main(installer):
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Interactive setup requires a terminal. Use --agent and --user/--project.", file=sys.stderr)
        return 2
    try:
        statuses = ["CLI detected" if shutil.which(agent) else "CLI not on PATH" for agent in AGENTS]
        agents = [AGENTS[i] for i in choose("Select AI agents", LABELS, True, step="1 / 3",
                    detail="Choose one or more assistants. Missing CLIs can be installed later.", statuses=statuses)]
        scope = choose("Choose installation scope", ["Global (user) - all projects", "Local (project) - one project"],
                       step="2 / 3", detail="Choose where Security Guardian will be available.")[0]
        if scope:
            raw = read_prompt(f"Project directory [{clean(Path.cwd())}]: ")
            if raw.lower() == "q":
                raise Cancelled()
            base = Path(raw or ".").expanduser().resolve()
            if not base.is_dir():
                print("Project directory does not exist.", file=sys.stderr)
                return 2
            args = ["--project", str(base)]
        else:
            base = Path.home().resolve()
            args = ["--user"]
        paths = plan(agents, base)
        banner("3 / 3  Review installation")
        print("Agents:", ", ".join(LABELS[AGENTS.index(a)] for a in agents))
        print("Scope:", "Local (project)" if scope else "Global (user)")
        print(f"Destinations: {len(paths)}")
        for path in paths:
            exists = path.exists() or path.is_symlink()
            print("  "+color("UPGRADE / BACKUP" if exists else "NEW INSTALL", "33" if exists else "32"))
            print("    "+clean(path))
        if {"codex", "gemini"}.intersection(agents):
            print("Codex and Gemini share one skill directory; both may discover this skill.")
        print("Local installation only. No audit or agent execution.")
        if not confirm_install():
            raise Cancelled()
    except (Cancelled, EOFError, KeyboardInterrupt) as exc:
        print("\nCancelled. No installation changes requested." + (f" {exc}" if str(exc) else ""))
        return 0
    print(color("\nInstalling Security Guardian...", "1;36"), flush=True)
    result = subprocess.call(["bash", installer, "--agent", ",".join(agents), *args, "--upgrade-existing"])
    if result:
        print(color(f"Installation did not complete (exit {result}). Review the messages above.", "1;31"))
        return result
    print(color("Installation complete.", "1;32"))
    for agent in agents:
        print("  "+LABELS[AGENTS.index(agent)] + (": use $security-guardian" if agent == "codex" else ": ask to use the security-guardian skill"))
    print("Restart or reload your agent to discover the skill.")
    print(URL)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
