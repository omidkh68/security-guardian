#!/usr/bin/env python3
"""Interactive terminal front end for the existing offline installer."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

AGENTS = ("claude", "codex", "gemini")
LABELS = ("Claude Code", "OpenAI Codex", "Gemini CLI")


class Cancelled(Exception):
    pass


def choose_plain(title, options, multiple=False):
    print("\n" + title)
    for i, option in enumerate(options, 1):
        print(f"  {i}. {option}")
    while True:
        raw = input("Numbers (comma-separated, q to cancel): " if multiple else "Number (q to cancel): ").strip()
        if raw.lower() == "q":
            raise Cancelled()
        try:
            picks = sorted({int(x.strip()) - 1 for x in raw.split(",")})
            if picks and all(0 <= x < len(options) for x in picks) and (multiple or len(picks)==1):
                return picks
        except ValueError:
            pass
        print("Select at least one valid option.")


def choose(title, options, multiple=False):
    # Keep redirected streams and TERM=dumb out of curses.
    if os.environ.get("TERM", "") in ("", "dumb"):
        return choose_plain(title, options, multiple)
    try:
        import curses
        curses.setupterm()
    except (ImportError, curses.error if 'curses' in locals() else RuntimeError):
        return choose_plain(title, options, multiple)
    if shutil.get_terminal_size().columns < 48 or shutil.get_terminal_size().lines < len(options) + 6:
        return choose_plain(title, options, multiple)

    def screen(win):
        cursor = 0
        selected = set()
        hint = ""
        win.keypad(True)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        while True:
            win.erase()
            height, width = win.getmaxyx()
            if height < len(options)+6 or width < 30:
                raise Cancelled("Terminal too small; resize and try again.")
            win.addnstr(0, 0, "Security Guardian  /  Setup", width-1, curses.A_BOLD)
            win.addnstr(2, 0, title, width-1)
            for i, option in enumerate(options):
                mark = "[x]" if i in selected else "[ ]"
                prefix = ("> " if cursor==i else "  ") + (mark+" " if multiple else "")
                win.addnstr(3+i, 0, prefix+option, width-1,
                            curses.A_REVERSE if cursor==i else curses.A_NORMAL)
            win.addnstr(3+len(options), 0, hint or ("Arrows / Space / Enter / q cancel" if multiple else "Arrows / Enter / q cancel"), width-1)
            win.refresh()
            key = win.getch()
            if key in (ord("q"), 27):
                raise Cancelled()
            if key in (curses.KEY_UP, ord("k")):
                cursor = (cursor-1)%len(options)
            elif key in (curses.KEY_DOWN, ord("j")):
                cursor = (cursor+1)%len(options)
            elif key==ord(" ") and multiple:
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
    if {"codex","gemini"}.intersection(agents):
        paths.append(base / ".agents" / "skills" / "security-guardian")
    return paths


def main(installer):
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Interactive setup requires a terminal. Use --agent and --user/--project.", file=sys.stderr)
        return 2
    try:
        labels = [f"{label} ({'CLI found' if shutil.which(agent) else 'CLI not found'})"
                  for agent,label in zip(AGENTS,LABELS)]
        agents = [AGENTS[i] for i in choose("Select AI agents", labels, True)]
        scope = choose("Choose installation scope", ["Global (user) - all projects", "Local (project) - one project"])[0]
        if scope:
            raw = input(f"Project directory [{Path.cwd()}]: ").strip()
            base = Path(raw or ".").expanduser().resolve()
            if not base.is_dir():
                print("Project directory does not exist.", file=sys.stderr)
                return 2
            args = ["--project", str(base)]
        else:
            base = Path.home().resolve()
            args = ["--user"]
        paths = plan(agents,base)
        print("\nInstallation preview")
        print("Agents:", ", ".join(agents))
        print("Scope:", "Local" if scope else "Global")
        for path in paths:
            print(f"  {'UPGRADE (backup)' if path.exists() or path.is_symlink() else 'INSTALL'}  {path}")
        if {"codex","gemini"}.intersection(agents):
            print("Codex and Gemini share one skill directory; both may discover this skill.")
        if input("Apply this plan (including backups for existing copies)? [y/N] ").strip().lower() not in ("y","yes"):
            raise Cancelled()
        # Mixed existing/new destinations are explicitly approved by the prompt.
        return subprocess.call(["bash",installer,"--agent",",".join(agents),*args,"--upgrade-existing"])
    except (Cancelled, EOFError, KeyboardInterrupt) as exc:
        print("\nCancelled. No installation changes requested." + (f" {exc}" if str(exc) else ""))
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
