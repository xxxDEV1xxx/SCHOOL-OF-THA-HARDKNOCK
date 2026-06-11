#!/usr/bin/env python3
"""
command_board_tui.py — Terminal UI Command Board.

Pure stdlib. No pip, no apt, no network. Runs anywhere Python 3 runs —
including single-user mode, rescue shells, over SSH, inside tmux. Uses the
same curses library htop uses (ncurses).

Layout (minimal, buttons prominent):

    ┌────────────────────────────────────────────────────────────┐
    │ Header: page, page description, theme                      │
    ├──────────────────────────────────────┬─────────────────────┤
    │                                      │                     │
    │   4×4 button grid                    │   OUTPUT pane       │
    │   (prominent, takes most space)      │   (live scrolling)  │
    │                                      │                     │
    ├──────────────────────────────────────┴─────────────────────┤
    │ Edit panel: cmd [____] desc [____]  (Tab cycles fields)    │
    ├────────────────────────────────────────────────────────────┤
    │ Hints                                                      │
    └────────────────────────────────────────────────────────────┘

Edit fields are always visible and always reflect the selected button.
Tab cycles focus: grid → command → description → grid.
Typing in a field updates that slot live — no modal popup.

Controls (when grid has focus):
  ↑ ↓ ← → / hjkl   move selection
  Enter / Space    execute selected command
  Tab              jump focus to command field
  p                edit page description (modal)
  n / PgDn / >     next page
  b / PgUp / <     previous page
  1-5              jump to page
  c                clear output pane
  [ / ]            scroll output up / down
  End              snap output to tail
  t                cycle theme
  s                save now
  r                reload from disk
  q / Esc / Ctrl+C quit (auto-saves)

Controls (when editing a field):
  Tab              next field
  Shift-Tab        previous field
  Enter / Esc      leave edit mode, return focus to grid
  Ctrl+U           clear field
  Ctrl+C           quit the app

Command prefixes:
  (none)   bash -c, capture stdout/stderr to output pane
  !cmd     take over terminal (for interactive things like htop)
  @path    execute script file (honors shebang if +x)
  #cmd     detach and launch (GUI apps)

Config location priority:
  $COMMAND_BOARD_DIR → $PWD (if writable) → $HOME/.command_board → /tmp
"""

import curses
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

# ── Config ──────────────────────────────────────────────────────────
NUM_BUTTONS = 16
MAX_PAGES   = 5
GRID_COLS   = 4
GRID_ROWS   = 4
MAX_FIELD_LEN    = 4096
OUTPUT_LINE_CAP  = 2000
OUTPUT_TRIM_SLOP = 200


def choose_config_dir() -> Path:
    env_dir = os.environ.get("COMMAND_BOARD_DIR")
    if env_dir:
        p = Path(env_dir)
        if _try_make_writable(p):
            return p
    cwd = Path.cwd()
    if _is_writable(cwd):
        return cwd
    home = os.environ.get("HOME")
    if home:
        p = Path(home) / ".command_board"
        if _try_make_writable(p):
            return p
    return Path("/tmp")


def _try_make_writable(p: Path) -> bool:
    try:
        p.mkdir(parents=True, exist_ok=True)
        return _is_writable(p)
    except OSError:
        return False


def _is_writable(p: Path) -> bool:
    try:
        probe = p / ".cb_write_probe"
        probe.write_text("")
        probe.unlink()
        return True
    except OSError:
        return False


# ── Themes ──────────────────────────────────────────────────────────
THEMES = {
    "matrix": {
        "name": "Matrix",
        "bg": (0, 0, 0), "fg": (22, 181, 4), "border": (22, 181, 4),
        "select_bg": (22, 181, 4), "select_fg": (0, 0, 0),
        "button_bg": (11, 16, 150), "button_fg": (255, 255, 255),
        "button1_bg": (195, 25, 21), "button1_fg": (255, 255, 255),
        "output_bg": (0, 0, 0), "output_fg": (22, 181, 4),
        "error_fg": (255, 80, 80), "title_fg": (100, 255, 100),
        "dim_fg": (0, 130, 0), "focus_border": (255, 255, 0),
    },
    "amber": {
        "name": "Amber CRT",
        "bg": (20, 10, 0), "fg": (255, 176, 0), "border": (255, 140, 0),
        "select_bg": (255, 176, 0), "select_fg": (20, 10, 0),
        "button_bg": (80, 40, 0), "button_fg": (255, 200, 80),
        "button1_bg": (180, 50, 20), "button1_fg": (255, 255, 180),
        "output_bg": (20, 10, 0), "output_fg": (255, 176, 0),
        "error_fg": (255, 80, 80), "title_fg": (255, 220, 100),
        "dim_fg": (140, 90, 0), "focus_border": (255, 255, 140),
    },
    "ice": {
        "name": "Ice",
        "bg": (5, 10, 20), "fg": (140, 200, 255), "border": (100, 180, 255),
        "select_bg": (100, 180, 255), "select_fg": (5, 10, 20),
        "button_bg": (30, 60, 120), "button_fg": (220, 240, 255),
        "button1_bg": (200, 30, 100), "button1_fg": (255, 255, 255),
        "output_bg": (5, 10, 20), "output_fg": (140, 200, 255),
        "error_fg": (255, 120, 140), "title_fg": (200, 230, 255),
        "dim_fg": (80, 120, 170), "focus_border": (255, 255, 255),
    },
    "lsd": {
        "name": "LSD",
        "bg": (0, 0, 0), "fg": (255, 80, 255), "border": (255, 255, 0),
        "select_bg": (255, 0, 255), "select_fg": (255, 255, 0),
        "button_bg": (80, 0, 120), "button_fg": (0, 255, 255),
        "button1_bg": (255, 100, 0), "button1_fg": (255, 255, 0),
        "output_bg": (0, 0, 20), "output_fg": (0, 255, 200),
        "error_fg": (255, 80, 140), "title_fg": (255, 255, 100),
        "dim_fg": (140, 0, 140), "focus_border": (0, 255, 255),
    },
    "classic": {
        "name": "DOS Classic",
        "bg": (0, 0, 170), "fg": (255, 255, 255), "border": (255, 255, 85),
        "select_bg": (0, 170, 170), "select_fg": (0, 0, 0),
        "button_bg": (170, 0, 0), "button_fg": (255, 255, 255),
        "button1_bg": (170, 85, 0), "button1_fg": (255, 255, 85),
        "output_bg": (0, 0, 0), "output_fg": (85, 255, 85),
        "error_fg": (255, 85, 85), "title_fg": (255, 255, 85),
        "dim_fg": (85, 85, 255), "focus_border": (255, 255, 255),
    },
}
THEME_ORDER = ["matrix", "amber", "ice", "lsd", "classic"]


# ── Persistence ─────────────────────────────────────────────────────
def _is_control(c: str) -> bool:
    return ord(c) < 32 or ord(c) == 127


def _sanitize(s: str) -> str:
    if len(s) > MAX_FIELD_LEN:
        s = s[:MAX_FIELD_LEN]
    return "".join(c for c in s if c == "\t" or not _is_control(c))


def _atomic_write(path: Path, data: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(data, encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass


def load_theme_name(d: Path) -> str:
    try:
        p = d / "theme.txt"
        if p.exists():
            name = p.read_text(encoding="utf-8").strip()
            if name in THEMES:
                return name
    except OSError:
        pass
    return "matrix"


def save_theme_name(d: Path, name: str) -> None:
    _atomic_write(d / "theme.txt", name + "\n")


def load_commands(d: Path) -> dict:
    result = {p: [""] * NUM_BUTTONS for p in range(1, MAX_PAGES + 1)}
    p = d / "commands.txt"
    try:
        if not p.exists():
            return result
        for line in p.read_text(encoding="utf-8").splitlines():
            parts = line.split("|", 2)
            if len(parts) != 3:
                continue
            try:
                page, idx = int(parts[0]), int(parts[1])
            except ValueError:
                continue
            if 1 <= page <= MAX_PAGES and 0 <= idx < NUM_BUTTONS:
                result[page][idx] = _sanitize(parts[2])
    except OSError:
        pass
    return result


def save_commands(d: Path, cmds: dict) -> None:
    lines = []
    for page in range(1, MAX_PAGES + 1):
        for idx, cmd in enumerate(cmds[page]):
            lines.append(f"{page}|{idx}|{cmd}")
    _atomic_write(d / "commands.txt", "\n".join(lines) + "\n")


def load_descriptions(d: Path):
    button_descs = {p: [""] * NUM_BUTTONS for p in range(1, MAX_PAGES + 1)}
    page_descs = {p: f"Page {p}" for p in range(1, MAX_PAGES + 1)}
    p = d / "descriptions.txt"
    try:
        if not p.exists():
            return button_descs, page_descs
        for line in p.read_text(encoding="utf-8").splitlines():
            parts = line.split("|", 2)
            if len(parts) != 3:
                continue
            kind, key, val = parts
            try:
                if kind == "B":
                    page_s, idx_s = key.split(",")
                    page, idx = int(page_s), int(idx_s)
                    if 1 <= page <= MAX_PAGES and 0 <= idx < NUM_BUTTONS:
                        button_descs[page][idx] = _sanitize(val)
                elif kind == "P":
                    page = int(key)
                    if 1 <= page <= MAX_PAGES:
                        page_descs[page] = _sanitize(val)
            except (ValueError, IndexError):
                continue
    except OSError:
        pass
    return button_descs, page_descs


def save_descriptions(d: Path, button_descs: dict, page_descs: dict):
    lines = []
    for page in range(1, MAX_PAGES + 1):
        for idx, desc in enumerate(button_descs[page]):
            lines.append(f"B|{page},{idx}|{desc}")
        lines.append(f"P|{page}|{page_descs[page]}")
    _atomic_write(d / "descriptions.txt", "\n".join(lines) + "\n")


# ── Color management ────────────────────────────────────────────────
class ColorManager:
    def __init__(self):
        self.truecolor = False
        self.num_colors = 8
        self.can_change = False
        self.pair_cache = {}
        self.color_cache = {}
        self.next_color = 16
        self.next_pair  = 1

    def init(self):
        curses.start_color()
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        self.num_colors = curses.COLORS
        self.can_change = curses.can_change_color()
        ct = os.environ.get("COLORTERM", "").lower()
        term = os.environ.get("TERM", "").lower()
        self.truecolor = (ct in ("truecolor", "24bit")
                          or "truecolor" in term or "direct" in term)

    def _rgb_1000(self, rgb):
        r, g, b = rgb
        return (r * 1000 // 255, g * 1000 // 255, b * 1000 // 255)

    def _nearest_256(self, rgb):
        r, g, b = rgb
        if r > 240 and g > 240 and b > 240: return 231
        if r < 8 and g < 8 and b < 8: return 16
        if abs(r - g) < 8 and abs(g - b) < 8:
            gray = (r + g + b) // 3
            return 232 + min(23, max(0, (gray - 8) // 10))
        def q(v):
            if v < 48: return 0
            if v < 115: return 1
            return min(5, (v - 35) // 40)
        return 16 + 36 * q(r) + 6 * q(g) + q(b)

    def _allocate(self, rgb):
        if rgb in self.color_cache:
            return self.color_cache[rgb]
        if self.truecolor and self.can_change and self.next_color < self.num_colors:
            try:
                idx = self.next_color
                curses.init_color(idx, *self._rgb_1000(rgb))
                self.color_cache[rgb] = idx
                self.next_color += 1
                return idx
            except curses.error:
                pass
        if self.num_colors >= 256:
            idx = self._nearest_256(rgb)
            self.color_cache[rgb] = idx
            return idx
        r, g, b = rgb
        base = 0
        if r > 64: base |= 1
        if g > 64: base |= 2
        if b > 64: base |= 4
        if max(r, g, b) > 128 and self.num_colors >= 16:
            base += 8
        self.color_cache[rgb] = base
        return base

    def pair(self, fg, bg):
        key = (fg, bg)
        if key in self.pair_cache:
            return curses.color_pair(self.pair_cache[key])
        fi = self._allocate(fg)
        bi = self._allocate(bg)
        n = self.next_pair
        if n >= curses.COLOR_PAIRS:
            return curses.color_pair(0)
        try:
            curses.init_pair(n, fi, bi)
        except curses.error:
            return curses.color_pair(0)
        self.pair_cache[key] = n
        self.next_pair += 1
        return curses.color_pair(n)


# ── Command execution ───────────────────────────────────────────────
class CommandRunner:
    MAX_LINE_LEN = 4096

    def __init__(self):
        self.out_queue = queue.Queue()

    def submit(self, cmd_text: str):
        cmd_text = cmd_text.strip()
        if not cmd_text:
            self.out_queue.put(("err", "[empty command]"))
            return
        self.out_queue.put(("cmd", f"$ {cmd_text}"))

        if cmd_text.startswith("#"):
            self._detach(cmd_text[1:].strip())
            return
        if cmd_text.startswith("!"):
            self.out_queue.put(("takeover", cmd_text[1:].strip()))
            return
        if cmd_text.startswith("@"):
            path = cmd_text[1:].strip()
            if not os.path.isfile(path):
                self.out_queue.put(("err", f"[err] script not found: {path}"))
                return
            argv = [path] if os.access(path, os.X_OK) else ["bash", path]
        else:
            argv = ["bash", "-c", cmd_text]

        threading.Thread(target=self._run, args=(argv,), daemon=True).start()

    def _detach(self, cmd: str):
        try:
            proc = subprocess.Popen(
                ["bash", "-c", cmd],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True,
            )
            self.out_queue.put(("meta", f"[launched detached, pid={proc.pid}]"))
        except OSError as e:
            self.out_queue.put(("err", f"[err] {e}"))

    def _run(self, argv):
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1,
                start_new_session=True,
            )
        except OSError as e:
            self.out_queue.put(("err", f"[err] spawn failed: {e}"))
            return

        def pump(stream, kind):
            try:
                for raw in iter(stream.readline, ""):
                    line = raw.rstrip("\n")
                    if len(line) > self.MAX_LINE_LEN:
                        line = line[:self.MAX_LINE_LEN] + " …"
                    line = "".join(c for c in line if c == "\t" or not _is_control(c))
                    self.out_queue.put((kind, line))
            except (OSError, ValueError):
                pass
            finally:
                try: stream.close()
                except OSError: pass

        t_out = threading.Thread(target=pump, args=(proc.stdout, "out"), daemon=True)
        t_err = threading.Thread(target=pump, args=(proc.stderr, "err"), daemon=True)
        t_out.start(); t_err.start()
        proc.wait()
        t_out.join(timeout=1.0)
        t_err.join(timeout=1.0)
        self.out_queue.put(("meta", f"[exit {proc.returncode}]"))

    def drain(self, limit=500):
        items = []
        try:
            for _ in range(limit):
                items.append(self.out_queue.get_nowait())
        except queue.Empty:
            pass
        return items


# ── Focus constants ─────────────────────────────────────────────────
FOCUS_GRID = 0
FOCUS_CMD  = 1
FOCUS_DESC = 2


# ── Application ─────────────────────────────────────────────────────
class App:
    def __init__(self, stdscr, config_dir: Path):
        self.stdscr = stdscr
        self.dir = config_dir
        self.colors = ColorManager()
        self.colors.init()

        self.theme_name = load_theme_name(self.dir)
        self.theme = THEMES.get(self.theme_name, THEMES["matrix"])

        self.commands = load_commands(self.dir)
        self.button_descs, self.page_descs = load_descriptions(self.dir)

        self.current_page = 1
        self.selected = 0
        self.focus = FOCUS_GRID
        self.edit_cursor = 0

        self.output_lines = []
        self.output_scroll = 0
        self.runner = CommandRunner()

        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.keypad(True)
        try:
            curses.raw()
        except curses.error:
            try: curses.cbreak()
            except curses.error: pass

    # ── Current-slot accessors ──────────────────────────
    def _cur_cmd(self) -> str:
        try:
            return self.commands[self.current_page][self.selected]
        except (KeyError, IndexError):
            return ""

    def _cur_desc(self) -> str:
        try:
            return self.button_descs[self.current_page][self.selected]
        except (KeyError, IndexError):
            return ""

    def _set_cur_cmd(self, v: str):
        try:
            self.commands[self.current_page][self.selected] = _sanitize(v)
        except (KeyError, IndexError):
            pass

    def _set_cur_desc(self, v: str):
        try:
            self.button_descs[self.current_page][self.selected] = _sanitize(v)
        except (KeyError, IndexError):
            pass

    # ── Theme ───────────────────────────────────────────
    def cycle_theme(self):
        i = THEME_ORDER.index(self.theme_name)
        self.theme_name = THEME_ORDER[(i + 1) % len(THEME_ORDER)]
        self.theme = THEMES[self.theme_name]
        save_theme_name(self.dir, self.theme_name)

    # ── Output ──────────────────────────────────────────
    def push_output(self, kind: str, text: str):
        self.output_lines.append((kind, text))
        if len(self.output_lines) > OUTPUT_LINE_CAP + OUTPUT_TRIM_SLOP:
            drop = len(self.output_lines) - OUTPUT_LINE_CAP
            self.output_lines = self.output_lines[drop:]
            self.output_scroll = max(0, self.output_scroll - drop)

    # ── Navigation ──────────────────────────────────────
    def move_selection(self, dx: int, dy: int):
        col = self.selected % GRID_COLS + dx
        row = self.selected // GRID_COLS + dy
        if 0 <= col < GRID_COLS and 0 <= row < GRID_ROWS:
            self.selected = row * GRID_COLS + col

    # ── Drawing ─────────────────────────────────────────
    def _safe_addnstr(self, y, x, s, n, attr=0):
        try:
            self.stdscr.addnstr(y, x, s, n, attr)
        except curses.error:
            pass

    def draw(self):
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        if h < 20 or w < 70:
            self._safe_addnstr(0, 0, f"Terminal too small ({w}x{h}); need 70x20 minimum", w - 1)
            self.stdscr.refresh()
            return

        theme = self.theme
        try:
            self.stdscr.bkgd(" ", self.colors.pair(theme["fg"], theme["bg"]))
        except curses.error:
            pass

        header_h = 2
        edit_h   = 3
        footer_h = 2
        body_top = header_h
        body_h   = h - header_h - edit_h - footer_h
        grid_w   = int(w * 0.6)
        output_x = grid_w
        output_w = w - grid_w

        self.draw_header(0, 0, w, theme)
        self.draw_grid(body_top, 0, body_h, grid_w, theme)
        self.draw_output(body_top, output_x, body_h, output_w, theme)
        self.draw_edit_panel(body_top + body_h, 0, edit_h, w, theme)
        self.draw_footer(h - footer_h, 0, w, theme)

        self.stdscr.refresh()

    def draw_header(self, y, x, w, theme):
        tp = self.colors.pair(theme["title_fg"], theme["bg"])
        bp = self.colors.pair(theme["border"], theme["bg"])
        pd = self.page_descs.get(self.current_page, "")
        left = f" ■ COMMAND BOARD — Page {self.current_page}/{MAX_PAGES}"
        if pd:
            left += f" — {pd}"
        right = f"[{theme['name']}] "
        left = left[:max(0, w - len(right) - 1)]
        pad = " " * max(0, w - len(left) - len(right) - 1)
        self._safe_addnstr(y, x, left + pad + right, w - 1, tp | curses.A_BOLD)
        self._safe_addnstr(y + 1, x, "─" * (w - 1), w - 1, bp)

    def draw_footer(self, y, x, w, theme):
        bp = self.colors.pair(theme["border"], theme["bg"])
        dp = self.colors.pair(theme["dim_fg"], theme["bg"])
        self._safe_addnstr(y, x, "─" * (w - 1), w - 1, bp)
        if self.focus == FOCUS_GRID:
            hints = (" ↵=run  Tab=edit fields  p=page desc  n/b=page±  1-5=page  "
                     "t=theme  c=clear  [/]=scroll  s=save  q=quit")
        else:
            label = "command" if self.focus == FOCUS_CMD else "description"
            hints = f" editing {label}  |  Tab=next  Shift-Tab=prev  Enter/Esc=back to grid  Ctrl+U=clear  Ctrl+C=quit"
        self._safe_addnstr(y + 1, x, hints[:w - 1].ljust(w - 1), w - 1, dp)

    def draw_grid(self, y, x, h, w, theme):
        if h < GRID_ROWS or w < GRID_COLS * 10:
            return
        cell_w = (w - 1) // GRID_COLS
        cell_h = h // GRID_ROWS
        for i in range(NUM_BUTTONS):
            r, c = divmod(i, GRID_COLS)
            self.draw_cell(y + r * cell_h, x + c * cell_w, cell_h, cell_w, i, theme)

    def draw_cell(self, y, x, h, w, idx, theme):
        is_sel = idx == self.selected and self.focus == FOCUS_GRID
        is_sel_dim = idx == self.selected and self.focus != FOCUS_GRID

        if is_sel:
            bg, fg = theme["select_bg"], theme["select_fg"]
        elif idx == 0:
            bg, fg = theme["button1_bg"], theme["button1_fg"]
        else:
            bg, fg = theme["button_bg"], theme["button_fg"]

        btn_attr = self.colors.pair(fg, bg) | (curses.A_BOLD if is_sel else 0)
        border_color = theme["focus_border"] if is_sel else (theme["select_bg"] if is_sel_dim else theme["border"])
        border_pair = self.colors.pair(border_color, theme["bg"])

        desc = self.button_descs[self.current_page][idx].strip()
        cmd = self.commands[self.current_page][idx].strip()
        label = desc if desc else f"Button {idx+1}"

        # Fill cell body
        for row in range(h):
            self._safe_addnstr(y + row, x, " " * (w - 1), w - 1, btn_attr)

        # Border
        try:
            self.stdscr.addstr(y, x, "┌" + "─" * (w - 3) + "┐", border_pair)
            self.stdscr.addstr(y + h - 1, x, "└" + "─" * (w - 3) + "┘", border_pair)
            for row in range(1, h - 1):
                self.stdscr.addstr(y + row, x, "│", border_pair)
                self.stdscr.addstr(y + row, x + w - 2, "│", border_pair)
        except curses.error:
            pass

        # Slot number (dim, top-left)
        num_pair = self.colors.pair(theme["dim_fg"], bg)
        self._safe_addnstr(y + 1, x + 2, f"{idx+1:02d}", 2, num_pair)

        # Label (centered)
        label_clip = label[:max(0, w - 4)]
        label_y = y + h // 2
        label_x = x + max(1, (w - len(label_clip)) // 2)
        self._safe_addnstr(label_y, label_x, label_clip, w - 2, btn_attr)

        # Command preview (if space)
        if cmd and h >= 5:
            preview = cmd[:max(0, w - 4)]
            dim_attr = self.colors.pair(theme["dim_fg"] if not is_sel else fg, bg)
            self._safe_addnstr(y + h - 2, x + 2, preview, w - 4, dim_attr | curses.A_DIM)

    def draw_output(self, y, x, h, w, theme):
        if w < 10 or h < 3:
            return
        bp = self.colors.pair(theme["border"], theme["bg"])
        bg = theme["output_bg"]
        inner_pair = self.colors.pair(theme["output_fg"], bg)

        try:
            self.stdscr.addstr(y, x, "┌" + "─" * (w - 3) + "┐", bp)
            self.stdscr.addstr(y, x + 2, " OUTPUT ", bp | curses.A_BOLD)
            self.stdscr.addstr(y + h - 1, x, "└" + "─" * (w - 3) + "┘", bp)
            for row in range(1, h - 1):
                self.stdscr.addstr(y + row, x, "│", bp)
                self.stdscr.addstr(y + row, x + w - 2, "│", bp)
        except curses.error:
            pass

        inner_h = h - 2
        inner_w = w - 4

        wanted = inner_h + max(0, self.output_scroll)
        wrapped = self._wrap_output_tail(wanted, inner_w)
        start = max(0, len(wrapped) - inner_h - self.output_scroll)
        end = start + inner_h
        visible = wrapped[start:end]

        for row in range(inner_h):
            self._safe_addnstr(y + 1 + row, x + 1, " " * inner_w, inner_w, inner_pair)

        out_pair  = self.colors.pair(theme["output_fg"], bg)
        err_pair  = self.colors.pair(theme["error_fg"], bg)
        cmd_pair  = self.colors.pair(theme["title_fg"], bg)
        meta_pair = self.colors.pair(theme["dim_fg"], bg)

        for i, (kind, line) in enumerate(visible):
            pair = {
                "out": out_pair,
                "err": err_pair | curses.A_BOLD,
                "cmd": cmd_pair | curses.A_BOLD,
                "meta": meta_pair | curses.A_DIM,
            }.get(kind, out_pair)
            self._safe_addnstr(y + 1 + i, x + 2, line, inner_w - 1, pair)

    def _wrap_output_tail(self, wanted: int, width: int):
        if width <= 0:
            return []
        out = []
        for kind, text in reversed(self.output_lines):
            if not text:
                out.insert(0, (kind, ""))
                if len(out) >= wanted:
                    break
                continue
            wrapped = []
            for i in range(0, len(text), width):
                wrapped.append((kind, text[i:i + width]))
            out = wrapped + out
            if len(out) >= wanted:
                break
        return out[-wanted:] if len(out) > wanted else out

    def draw_edit_panel(self, y, x, h, w, theme):
        """Side-by-side cmd/desc edit fields. Always visible and in sync."""
        bp = self.colors.pair(theme["border"], theme["bg"])
        dp = self.colors.pair(theme["dim_fg"], theme["bg"])
        tp = self.colors.pair(theme["title_fg"], theme["bg"])

        # Top separator
        self._safe_addnstr(y, x, "─" * (w - 1), w - 1, bp)

        slot_label = f"  ■ slot {self.selected+1:02d}  "
        labels_w = len("cmd: ") + len("desc: ") + 4
        avail = max(20, w - len(slot_label) - labels_w - 2)
        field_w = max(10, avail // 2)

        self._safe_addnstr(y + 1, x, slot_label, len(slot_label), tp | curses.A_BOLD)
        cx = x + len(slot_label)

        self._safe_addnstr(y + 1, cx, "cmd: ", 5, dp)
        cx += 5
        self._draw_field(y + 1, cx, field_w, self._cur_cmd(),
                         focused=(self.focus == FOCUS_CMD), theme=theme)
        cx += field_w + 2

        self._safe_addnstr(y + 1, cx, "desc: ", 6, dp)
        cx += 6
        self._draw_field(y + 1, cx, field_w, self._cur_desc(),
                         focused=(self.focus == FOCUS_DESC), theme=theme)

        # Bottom separator
        self._safe_addnstr(y + 2, x, "─" * (w - 1), w - 1, bp)

    def _draw_field(self, y, x, w, text, focused, theme):
        if w < 3:
            return
        BLACK = (0, 0, 0)
        field_pair = self.colors.pair(theme["fg"], BLACK)
        border_color = theme["focus_border"] if focused else theme["border"]
        border_pair = self.colors.pair(border_color, theme["bg"])
        bracket_attr = border_pair | (curses.A_BOLD if focused else 0)

        self._safe_addnstr(y, x, "[", 1, bracket_attr)
        self._safe_addnstr(y, x + w - 1, "]", 1, bracket_attr)

        inner_w = w - 2
        if inner_w <= 0:
            return

        cursor = self.edit_cursor if focused else 0
        cursor = min(cursor, len(text))
        start = max(0, cursor - inner_w + 1) if focused else 0
        visible = text[start:start + inner_w]
        padded = visible.ljust(inner_w)
        self._safe_addnstr(y, x + 1, padded, inner_w, field_pair)

        if focused:
            cur_col = x + 1 + (cursor - start)
            if cur_col < x + w - 1:
                cursor_char = text[cursor] if cursor < len(text) else " "
                self._safe_addnstr(y, cur_col, cursor_char, 1,
                                   field_pair | curses.A_REVERSE)

    # ── Input handling ──────────────────────────────────
    def handle_key_grid(self, ch) -> bool:
        if ch == -1:
            return True
        if ch in (3, 27, ord('q')):
            return False
        if ch == 9:
            self.focus = FOCUS_CMD
            self.edit_cursor = len(self._cur_cmd())
            return True
        if ch == curses.KEY_BTAB:
            self.focus = FOCUS_DESC
            self.edit_cursor = len(self._cur_desc())
            return True
        if ch in (curses.KEY_UP, ord('k')):    self.move_selection(0, -1)
        elif ch in (curses.KEY_DOWN, ord('j')): self.move_selection(0, 1)
        elif ch in (curses.KEY_LEFT, ord('h')): self.move_selection(-1, 0)
        elif ch in (curses.KEY_RIGHT, ord('l')):self.move_selection(1, 0)
        elif ch in (10, 13, curses.KEY_ENTER, ord(' ')):
            self.runner.submit(self._cur_cmd())
            self.output_scroll = 0
        elif ch in (ord('n'), curses.KEY_NPAGE, ord('>'), ord('.')):
            if self.current_page < MAX_PAGES: self.current_page += 1
        elif ch in (ord('b'), curses.KEY_PPAGE, ord('<'), ord(',')):
            if self.current_page > 1: self.current_page -= 1
        elif ord('1') <= ch <= ord('5'):
            self.current_page = ch - ord('0')
        elif ch == ord('p'):
            self._prompt_page_desc()
        elif ch == ord('c'):
            self.output_lines.clear()
            self.output_scroll = 0
        elif ch == ord('['):
            self.output_scroll += 5
        elif ch == ord(']'):
            self.output_scroll = max(0, self.output_scroll - 5)
        elif ch == curses.KEY_END:
            self.output_scroll = 0
        elif ch == ord('t'):
            self.cycle_theme()
        elif ch == ord('s'):
            self.save()
        elif ch == ord('r'):
            self.commands = load_commands(self.dir)
            self.button_descs, self.page_descs = load_descriptions(self.dir)
        return True

    def handle_key_field(self, ch) -> bool:
        if ch == -1:
            return True
        if ch == 3:
            return False
        if ch in (10, 13, curses.KEY_ENTER, 27):
            self.focus = FOCUS_GRID
            return True
        if ch == 9:
            if self.focus == FOCUS_CMD:
                self.focus = FOCUS_DESC
                self.edit_cursor = len(self._cur_desc())
            else:
                self.focus = FOCUS_GRID
            return True
        if ch == curses.KEY_BTAB:
            if self.focus == FOCUS_DESC:
                self.focus = FOCUS_CMD
                self.edit_cursor = len(self._cur_cmd())
            else:
                self.focus = FOCUS_GRID
            return True

        def get():
            return self._cur_cmd() if self.focus == FOCUS_CMD else self._cur_desc()
        def put(v):
            if self.focus == FOCUS_CMD: self._set_cur_cmd(v)
            else: self._set_cur_desc(v)

        text = get()
        cur = min(self.edit_cursor, len(text))

        if ch in (curses.KEY_BACKSPACE, 127, 8):
            if cur > 0:
                text = text[:cur - 1] + text[cur:]
                cur -= 1
        elif ch == curses.KEY_DC:
            if cur < len(text):
                text = text[:cur] + text[cur + 1:]
        elif ch == curses.KEY_LEFT:
            cur = max(0, cur - 1)
        elif ch == curses.KEY_RIGHT:
            cur = min(len(text), cur + 1)
        elif ch == curses.KEY_HOME:
            cur = 0
        elif ch == curses.KEY_END:
            cur = len(text)
        elif ch == 21:
            text = ""
            cur = 0
        elif 32 <= ch < 127:
            if len(text) < MAX_FIELD_LEN:
                text = text[:cur] + chr(ch) + text[cur:]
                cur += 1
        elif 128 <= ch < 0x110000:
            try:
                if len(text) < MAX_FIELD_LEN:
                    text = text[:cur] + chr(ch) + text[cur:]
                    cur += 1
            except ValueError:
                pass

        put(text)
        self.edit_cursor = cur
        return True

    def _prompt_page_desc(self):
        current = self.page_descs.get(self.current_page, "")
        result = modal_prompt(self.stdscr, self.colors, self.theme,
                              f"Page {self.current_page} description", current)
        if result is not None:
            self.page_descs[self.current_page] = _sanitize(result)

    # ── Takeover for ! commands ─────────────────────────
    def run_takeover(self, cmd: str):
        try: curses.noraw()
        except curses.error: pass
        curses.endwin()
        try:
            print(f"\n\033[1;33m──── running: {cmd} ────\033[0m\n")
            try:
                rc = subprocess.call(["bash", "-c", cmd])
            except KeyboardInterrupt:
                rc = 130
                print()
            print(f"\n\033[1;33m──── exit {rc} — press Enter to return ────\033[0m")
            try:
                sys.stdin.readline()
            except (EOFError, KeyboardInterrupt):
                pass
        finally:
            try: curses.raw()
            except curses.error: pass
            self.stdscr.clear()
            self.stdscr.refresh()
            curses.doupdate()

    def save(self):
        save_commands(self.dir, self.commands)
        save_descriptions(self.dir, self.button_descs, self.page_descs)
        save_theme_name(self.dir, self.theme_name)

    def run(self):
        FRAME = 0.05
        last = 0.0
        try:
            while True:
                for kind, text in self.runner.drain():
                    if kind == "takeover":
                        self.run_takeover(text)
                        continue
                    self.push_output(kind, text)

                now = time.time()
                if now - last >= FRAME:
                    try: self.draw()
                    except curses.error: pass
                    last = now

                try:
                    ch = self.stdscr.getch()
                except curses.error:
                    ch = -1

                if ch == -1:
                    time.sleep(FRAME / 2)
                    continue

                if self.focus == FOCUS_GRID:
                    ok = self.handle_key_grid(ch)
                else:
                    ok = self.handle_key_field(ch)
                if not ok:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            self.save()


# ── Modal prompt (only used for page description) ──────────────────
def modal_prompt(stdscr, colors, theme, title, initial):
    h, w = stdscr.getmaxyx()
    prompt_h = 3
    prompt_w = min(w - 4, 80)
    y = max(0, h - prompt_h - 3)
    x = max(0, (w - prompt_w) // 2)

    win = curses.newwin(prompt_h, prompt_w, y, x)
    win.keypad(True)

    BLACK = (0, 0, 0)
    border_pair = colors.pair(theme["focus_border"], BLACK)
    title_pair = colors.pair(theme["title_fg"], BLACK)
    input_pair = colors.pair(theme["fg"], BLACK)

    buf = list(initial)
    pos = len(buf)

    curses.curs_set(1)
    try:
        while True:
            try:
                win.erase()
                for r in range(prompt_h):
                    try:
                        win.addstr(r, 0, " " * (prompt_w - 1), input_pair)
                    except curses.error:
                        pass
                win.attron(border_pair)
                win.border()
                win.attroff(border_pair)
                win.attron(title_pair | curses.A_BOLD)
                win.addnstr(0, 2, f" {title} (Enter=OK, Esc=cancel) ", prompt_w - 4)
                win.attroff(title_pair | curses.A_BOLD)

                visible_w = prompt_w - 4
                start = max(0, pos - visible_w + 1)
                display = "".join(buf[start:start + visible_w]).ljust(visible_w)
                win.attron(input_pair)
                win.addnstr(1, 2, display, visible_w)
                win.attroff(input_pair)

                try: win.move(1, 2 + (pos - start))
                except curses.error: pass
                win.refresh()
            except curses.error:
                pass

            ch = win.getch()
            if ch in (10, 13, curses.KEY_ENTER):
                return "".join(buf)
            if ch in (27, 3):
                return None
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                if pos > 0:
                    del buf[pos - 1]; pos -= 1
            elif ch == curses.KEY_DC:
                if pos < len(buf):
                    del buf[pos]
            elif ch == curses.KEY_LEFT:
                pos = max(0, pos - 1)
            elif ch == curses.KEY_RIGHT:
                pos = min(len(buf), pos + 1)
            elif ch == curses.KEY_HOME:
                pos = 0
            elif ch == curses.KEY_END:
                pos = len(buf)
            elif ch == 21:
                buf.clear(); pos = 0
            elif 32 <= ch < 127:
                if len(buf) < MAX_FIELD_LEN:
                    buf.insert(pos, chr(ch)); pos += 1
            elif 128 <= ch < 0x110000:
                try:
                    if len(buf) < MAX_FIELD_LEN:
                        buf.insert(pos, chr(ch)); pos += 1
                except ValueError:
                    pass
    finally:
        curses.curs_set(0)


# ── Entry point ─────────────────────────────────────────────────────
def main(stdscr):
    config_dir = choose_config_dir()
    app = App(stdscr, config_dir)
    app.run()


if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        pass
    sys.exit(0)
