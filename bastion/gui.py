"""The window and the tray icon."""
import os
import threading
import time
from pathlib import Path

from PySide6.QtCore import QObject, QPointF, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QIcon, QPainter, QPainterPath, QPixmap
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
                               QLabel, QLineEdit, QListWidget, QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QStackedWidget, QSystemTrayIcon,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from . import ai, core, engine as E, harden, scanner, telemetry, updater, web
from .core import HIGH, LEVELS, MEDIUM

GOOD, WARN, BAD, DIM = "#4cc38a", "#e0a73c", "#e5534b", "#8b96a5"
COLOURS = [DIM, "#9aa7b8", WARN, "#ee7d3b", BAD]
STYLE = """
* { font-family: 'Segoe UI'; font-size: 13px; color: #e2e8f0; }
QMainWindow, QStackedWidget, QMessageBox { background: #10151c; }
QListWidget { background: #0b0f15; border: none; padding: 10px 6px; outline: 0; }
QListWidget::item { padding: 11px 14px; border-radius: 6px; margin: 2px 4px; }
QListWidget::item:selected { background: #1c2735; color: #fff; }
QFrame#card { background: #171e28; border: 1px solid #222c39; border-radius: 10px; }
QLabel#h1 { font-size: 22px; font-weight: 600; } QLabel#dim { color: #8b96a5; }
QPushButton { background: #22303f; border: 1px solid #2d3d4f; border-radius: 6px; padding: 8px 16px; }
QPushButton:hover { background: #2a3b4e; } QPushButton:disabled { color: #56616f; }
QPushButton#main { background: #1f7a55; border-color: #26946a; font-weight: 600; } QPushButton#main:hover { background: #26946a; }
QTableWidget { background: #141a23; border: 1px solid #222c39; border-radius: 8px; gridline-color: #1d2632; }
QTableWidget::item { padding: 5px; } QTableWidget::item:selected { background: #22324a; }
QHeaderView::section { background: #171e28; border: none; padding: 7px; color: #8b96a5; }
QPlainTextEdit, QLineEdit { background: #141a23; border: 1px solid #222c39; border-radius: 8px; padding: 8px; }
QComboBox { background: #22303f; border: 1px solid #2d3d4f; border-radius: 6px; padding: 6px 10px; }
QComboBox QAbstractItemView { background: #171e28; }
QProgressBar { background: #171e28; border: none; border-radius: 4px; height: 8px; text-align: center; color: transparent; }
QProgressBar::chunk { background: #26946a; border-radius: 4px; }
"""


def shield(colour, size=64):
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    s = size / 64
    path = QPainterPath(QPointF(32 * s, 4 * s))
    path.lineTo(56 * s, 13 * s)
    path.cubicTo(56 * s, 36 * s, 50 * s, 52 * s, 32 * s, 61 * s)
    path.cubicTo(14 * s, 52 * s, 8 * s, 36 * s, 8 * s, 13 * s)
    path.closeSubpath()
    p.fillPath(path, QColor(colour))
    pen = p.pen()
    pen.setColor(QColor("white"))
    pen.setWidthF(5.5 * s)
    pen.setCapStyle(Qt.RoundCap)
    p.setPen(pen)
    p.drawPolyline([QPointF(21 * s, 32 * s), QPointF(29 * s, 41 * s), QPointF(44 * s, 23 * s)])
    p.end()
    return pm


def label(text="", name=None):
    w = QLabel(text)
    w.setWordWrap(True)
    if name:
        w.setObjectName(name)
    return w


def button(text, fn, main=False):
    b = QPushButton(text)
    b.clicked.connect(lambda *_: fn())
    if main:
        b.setObjectName("main")
    return b


def table(heads, stretch):
    t = QTableWidget(0, len(heads))
    t.setHorizontalHeaderLabels(heads)
    t.verticalHeader().hide()
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setShowGrid(False)
    for i in range(len(heads)):
        t.horizontalHeader().setSectionResizeMode(i, QHeaderView.Stretch if i == stretch else QHeaderView.ResizeToContents)
    return t


def fill(t, rows, colours=None):
    t.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, v in enumerate(row):
            it = QTableWidgetItem(str(v))
            if colours and colours[r]:
                it.setForeground(QColor(colours[r])) if c == 0 else None
            t.setItem(r, c, it)


class Bridge(QObject):
    event = Signal(tuple)
    done = Signal(str, object)
    scan = Signal(object)


class Window(QMainWindow):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.bridge = Bridge()
        self.bridge.event.connect(self.on_event)
        self.bridge.done.connect(self.on_done)
        self.bridge.scan.connect(self.on_scan)
        ctx.log.listeners.append(self.bridge.event.emit)
        self.cancel_scan = threading.Event()
        self.scanning = False
        self.quitting = False
        self.setWindowTitle("Bastion")
        self.resize(1060, 680)
        self.setStyleSheet(STYLE)

        self.nav = QListWidget()
        self.nav.setFixedWidth(170)
        self.pages = QStackedWidget()
        for name, make in (("Protection", self.page_home), ("Scan", self.page_scan), ("Alerts", self.page_alerts), ("AI", self.page_ai),
                           ("Quarantine", self.page_quarantine), ("Hardening", self.page_harden), ("Settings", self.page_settings)):
            self.nav.addItem(name)
            self.pages.addWidget(make())
        self.nav.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.nav.setCurrentRow(0)
        body = QWidget()
        h = QHBoxLayout(body)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        h.addWidget(self.nav)
        h.addWidget(self.pages)
        self.setCentralWidget(body)

        self.tray = QSystemTrayIcon(QIcon(shield(GOOD)), self)
        m = QMenu()
        for text, fn in (("Open Bastion", self.bring_up), ("Exit (stops protection)", self.exit_app)):
            a = QAction(text, m)
            a.triggered.connect(fn)
            m.addAction(a)
        self.tray_menu = m
        self.tray.setContextMenu(m)
        self.tray.activated.connect(lambda r: self.bring_up() if r == QSystemTrayIcon.Trigger else None)
        self.tray.messageClicked.connect(lambda: (self.bring_up(), self.nav.setCurrentRow(2)))
        self.tray.show()
        self._colour = None
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(2000)
        self.refresh()
        self.load_alerts()
        self.load_quarantine()

    # ---------------------------------------------------------------- pages
    def page(self, title, sub=""):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(26, 22, 26, 22)
        v.setSpacing(12)
        v.addWidget(label(title, "h1"))
        if sub:
            v.addWidget(label(sub, "dim"))
        return w, v

    def page_home(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(26, 22, 26, 22)
        v.setSpacing(14)
        top = QFrame()
        top.setObjectName("card")
        h = QHBoxLayout(top)
        h.setContentsMargins(22, 18, 22, 18)
        self.badge = QLabel()
        self.headline, self.subline = label("Starting", "h1"), label("", "dim")
        t = QVBoxLayout()
        t.addWidget(self.headline)
        t.addWidget(self.subline)
        h.addWidget(self.badge)
        h.addSpacing(14)
        h.addLayout(t, 1)
        v.addWidget(top)
        self.up_box = QFrame()
        self.up_box.setObjectName("card")
        ub = QHBoxLayout(self.up_box)
        self.up_text = label()
        self.up_text.setTextFormat(Qt.PlainText)
        ub.addWidget(self.up_text, 1)
        self.up_btn = button("Update now", self.update_now, True)
        ub.addWidget(self.up_btn)
        ub.addWidget(button("What's new", lambda: self.ctx.update and os.startfile(self.ctx.update.page)))
        self.up_box.setVisible(False)
        self._told_update = ""
        v.addWidget(self.up_box)
        self.cards, grid = {}, QGridLayout()
        grid.setSpacing(10)
        for i, (n, what) in enumerate((("Files", "New downloads and files"), ("Programs", "What starts and how"), ("Ransomware", "Bait files and mass changes"),
                                       ("Startup", "New auto-start entries"), ("Network", "Known bad servers"), ("USB drives", "Checked when plugged in"), ("Defender", "Windows' own engine"),
                                       ("RAT", "Remote control and spying"), ("Rootkit", "Drivers and hidden programs"), ("AI", "Explains and learns"), ("Scanner", "Daily scan and signatures"), ("Web", "Phishing sites you open"), ("Updates", "Checks once a day"))):
            c = QFrame()
            c.setObjectName("card")
            cv = QVBoxLayout(c)
            st = label("starting")
            cv.addWidget(label(f"<b>{n}</b>"))
            cv.addWidget(label(what, "dim"))
            cv.addWidget(st)
            self.cards[n] = st
            grid.addWidget(c, i // 6, i % 6)
        v.addLayout(grid)
        self.held_box = QFrame()
        self.held_box.setObjectName("card")
        hb = QHBoxLayout(self.held_box)
        self.held_text = label()
        hb.addWidget(self.held_text, 1)
        hb.addWidget(button("Resume", lambda: self.release(False)))
        hb.addWidget(button("End program", lambda: self.release(True)))
        v.addWidget(self.held_box)
        v.addWidget(label("Recent alerts", "dim"))
        self.recent = table(["Level", "When", "What"], 2)
        v.addWidget(self.recent, 1)
        return w

    def page_scan(self):
        w, v = self.page("Scan", "Bastion's own scanner: known malware, signatures, rules and rootkit checks, on many threads. Nothing is removed until you choose.")
        h = QHBoxLayout()
        self.scan_buttons = [button("Full computer scan", lambda: self.scan(), True), button("Downloads, Desktop and Temp", self.scan_usual), button("Choose a folder", self.scan_folder)]
        for b in self.scan_buttons:
            h.addWidget(b)
        self.stop_btn = button("Stop", self.cancel_scan.set)
        self.stop_btn.setEnabled(False)
        h.addWidget(self.stop_btn)
        h.addStretch()
        v.addLayout(h)
        h = QHBoxLayout()
        self.c_fast, self.c_thorough = QCheckBox("Skip files unchanged since the last full scan"), QCheckBox("Also look inside signed programs (slower)")
        self.c_fast.setChecked(True)
        h.addWidget(self.c_fast)
        h.addWidget(self.c_thorough)
        h.addStretch()
        v.addLayout(h)
        self.bar, self.scan_text = QProgressBar(), label("Nothing scanned yet.", "dim")
        v.addWidget(self.bar)
        v.addWidget(self.scan_text)
        h = QHBoxLayout()
        self.link_box = QLineEdit()
        self.link_box.setPlaceholderText("Paste a link to check it before you open it")
        self.link_box.returnPressed.connect(self.check_link)
        h.addWidget(self.link_box, 1)
        h.addWidget(button("Check link", self.check_link))
        v.addLayout(h)
        self.link_text = label("", "dim")
        self.link_text.setTextFormat(Qt.PlainText)          # the link is someone else's text
        self.link_text.setWordWrap(True)
        v.addWidget(self.link_text)
        self.found = table(["Verdict", "File", "Why"], 1)
        v.addWidget(self.found, 1)
        h = QHBoxLayout()
        h.addWidget(button("Quarantine selected", self.quarantine_found))
        h.addWidget(button("Trust selected", self.trust_found))
        h.addStretch()
        v.addLayout(h)
        self.results = []
        return w

    def page_alerts(self):
        w, v = self.page("Alerts", "Everything Bastion noticed, kept for 90 days on this PC only.")
        self.filter = QComboBox()
        self.filter.addItems(["Everything", "Low and up", "Medium and up", "High and up", "Critical"])
        self.filter.setCurrentIndex(2)
        self.filter.currentIndexChanged.connect(lambda *_: self.load_alerts())
        v.addWidget(self.filter)
        self.alerts = table(["Level", "When", "Guard", "What", "Details"], 4)
        v.addWidget(self.alerts, 1)
        h = QHBoxLayout()
        h.addWidget(button("Open file location", self.open_alert))
        h.addWidget(button("Trust this file or program", self.trust_alert))
        h.addWidget(button("Ask the AI about this", self.ai_explain))
        h.addStretch()
        v.addLayout(h)
        return w

    def page_ai(self):
        w, v = self.page("AI", "A model on this PC reads alerts and explains them. Nothing is sent anywhere. It can raise an alarm but never trust, release or delete anything.")
        self.ai_text = label("", "dim")
        v.addWidget(self.ai_text)
        self.ai_table = table(["When", "Opinion", "Alert"], 2)
        self.ai_table.itemSelectionChanged.connect(self.ai_show)
        v.addWidget(self.ai_table, 1)
        self.ai_out = QPlainTextEdit()      # plain text only: what it shows may quote malware
        self.ai_out.setReadOnly(True)
        self.ai_out.setPlaceholderText("Pick an opinion above, or ask a question below.")
        v.addWidget(self.ai_out, 1)
        h = QHBoxLayout()
        self.ai_q = QLineEdit()
        self.ai_q.setMaxLength(600)
        self.ai_q.setPlaceholderText("Ask about this PC's alerts, e.g. What should I deal with first?")
        self.ai_q.returnPressed.connect(self.ai_ask)
        self.ai_go = button("Ask", self.ai_ask, True)
        h.addWidget(self.ai_q, 1)
        h.addWidget(self.ai_go)
        v.addLayout(h)
        c = QCheckBox("Use the AI and learn this PC's habits")
        c.setChecked(self.ctx.settings["ai"])
        c.toggled.connect(lambda on: self.ctx.settings.__setitem__("ai", on))
        v.addWidget(c)
        self._ai_rows = None
        return w

    def ai_refresh(self):
        a = self.ctx.ai
        state = "switched off" if not self.ctx.settings["ai"] else a.note + (f" ({a.model})" if a.model else "")
        self.ai_text.setText(f"Analyst: {state}. Alerts waiting: {a.q.qsize()}.   Habits: {self.ctx.habits.status()}.")
        rows = sorted(a.opinions.items(), reverse=True)
        if rows != self._ai_rows:
            self._ai_rows = rows
            name = {"likely_safe": "Probably harmless", "unsure": "Not sure", "likely_malicious": "Probably dangerous"}
            tint = {"likely_safe": DIM, "unsure": WARN, "likely_malicious": BAD}
            fill(self.ai_table, [(time.strftime("%b %d %H:%M", time.localtime(o["at"])), name[o["verdict"]], o["title"]) for _, o in rows], [tint[o["verdict"]] for _, o in rows])

    def ai_show(self):
        for _, o in self.picked(self.ai_table, self._ai_rows or [])[:1]:
            self.ai_out.setPlainText(ai.explain(o))

    def ai_busy(self, text):
        self.ai_go.setEnabled(False)
        self.ai_out.setPlainText(text)

    def ai_explain(self):
        for r in self.picked(self.alerts, self._alert_rows)[:1]:
            self.nav.setCurrentRow(3)
            self.ai_busy("Reading the alert. The first answer takes longer while the model loads.")
            self.work("ai", lambda: ai.explain(self.ctx.ai.judge(r)))

    def ai_ask(self):
        q = self.ai_q.text().strip()
        if q and self.ai_go.isEnabled():
            c = self.ctx
            extra = {"guards": {g.label: g.state for g in c.guards}, "defender": c.defender, "frozen_programs": [w for _, w in c.held.values()],
                     "protection_layers_off": [r[0] for r in harden.status(c.defender) if not r[1]], "habits": c.habits.status()}
            self.ai_busy("Thinking. The first answer takes longer while the model loads.")
            self.work("ai", lambda: c.ai.ask(q, c.log.latest(12, core.LOW), extra))

    def page_quarantine(self):
        w, v = self.page("Quarantine", "Held files are scrambled so they can't run. Restoring puts one back exactly as it was.")
        self.qtable = table(["When", "File", "Why"], 1)
        v.addWidget(self.qtable, 1)
        h = QHBoxLayout()
        h.addWidget(button("Restore", self.q_restore))
        h.addWidget(button("Delete for good", self.q_delete))
        h.addStretch()
        v.addLayout(h)
        return w

    def page_harden(self):
        w, v = self.page("Hardening", "Defender's advanced layers and Windows settings that close off drive-bys, RATs and rootkits. Windows will ask for administrator approval, and Undo puts back what you had.")
        self.htable = table(["State", "Layer", "Note"], 2)
        v.addWidget(self.htable, 1)
        h = QHBoxLayout()
        self.h_on, self.h_undo = button("Turn on all layers", self.harden_on, True), button("Undo", self.harden_undo)
        h.addWidget(self.h_on)
        h.addWidget(self.h_undo)
        h.addStretch()
        v.addLayout(h)
        h = QHBoxLayout()
        h.addWidget(button("Block dangerous websites (Quad9)", self.dns_on))
        h.addWidget(button("Restore my old DNS", self.dns_off))
        h.addStretch()
        v.addLayout(h)
        self.h_text = label("", "dim")
        v.addWidget(self.h_text)
        return w

    def page_settings(self):
        w, v = self.page("Settings")
        s = self.ctx.settings

        def check(text, on, fn):
            c = QCheckBox(text)
            c.setChecked(on)
            c.toggled.connect(fn)
            v.addWidget(c)
            return c
        check("Act by itself: quarantine known malware, freeze programs caught acting like ransomware, a RAT or a drive-by", s["auto_respond"], lambda on: s.__setitem__("auto_respond", on))
        check("Download public block lists every 6 hours (abuse.ch, Spamhaus, LOLDrivers, YARA Forge; nothing about this PC is sent)", s["intel_updates"], lambda on: s.__setitem__("intel_updates", on))
        self.auto = check("Run 24/7: start with Windows and restart if it stops", core.autostart_on(), self.set_auto)
        check("Check sites I open in my browsers against phishing lists (only site names are looked at, on this PC; nothing is sent)", s["watch_browsing"], lambda on: s.__setitem__("watch_browsing", on))
        check("Check GitHub once a day for a newer Bastion (nothing about you is sent)", s["check_updates"], lambda on: s.__setitem__("check_updates", on))
        h2 = QHBoxLayout()
        h2.addWidget(button("Check for updates now", self.check_updates_now))
        self.upd_text = label(f"Version {core.VERSION}", "dim")
        h2.addWidget(self.upd_text)
        h2.addStretch()
        v.addLayout(h2)
        check("Send an anonymous usage ping (off by default) — a random id and the version only, no IP or personal data, so the author can count how many people use Bastion", s["usage_ping"], lambda on: s.__setitem__("usage_ping", on))
        h = QHBoxLayout()
        h.addWidget(QLabel("Pop up for"))
        c = QComboBox()
        c.addItems([l + " and up" for l in LEVELS[MEDIUM:]])
        c.setCurrentIndex(max(0, s["notify_level"] - MEDIUM))
        c.currentIndexChanged.connect(lambda i: s.__setitem__("notify_level", i + MEDIUM))
        h.addWidget(c)
        h.addStretch()
        v.addLayout(h)
        self.intel_text = label("", "dim")
        v.addWidget(self.intel_text)
        v.addWidget(button("Update block lists now", lambda: self.work("intel", self.ctx.intel.update)), 0, Qt.AlignLeft)
        v.addStretch()
        return w

    # ---------------------------------------------------------------- live state
    def summary(self):
        """(colour, headline, detail): never green unless every guard and Defender are really working."""
        d, gs = self.ctx.defender, self.ctx.guards
        if d and not d["rt"] and not d.get("other"):
            return BAD, "Defender is off", "Turn real-time protection back on in Windows Security now."
        if self.ctx.held:
            return BAD, "A program is frozen", "Decide below whether to resume it or end it."
        down = [g.label for g in gs if not g.is_alive() or g.state.startswith("error")]
        if down:
            return WARN, "Partly protected", "Not working right now: " + ", ".join(down)
        if not gs or d is None or any(g.state == "starting" for g in gs):
            return WARN, "Starting up", "Getting the guards running."
        n = self.ctx.log.count_since(86400, HIGH)
        if n:
            return WARN, "Protected, with alerts to look at", f"{n} high or critical alert(s) in the last 24 hours."
        weak = [r[0] for r in harden.status(d) if not r[1]]
        return GOOD, "Protected", "All guards running" + (f" beside {d['other']}." if d.get("other") else ".") + (f" {len(weak)} extra Defender layer(s) can be turned on under Hardening." if weak else "")

    def refresh(self):
        colour, head, sub = self.summary()
        if colour != self._colour:
            self._colour = colour
            self.badge.setPixmap(shield(colour, 72))
            self.tray.setIcon(QIcon(shield(colour)))
            self.setWindowIcon(QIcon(shield(colour)))
        self.tray.setToolTip("Bastion: " + head)
        self.headline.setText(head)
        self.subline.setText(sub)
        for g in self.ctx.guards:
            ok = g.is_alive() and g.state == "on"
            c = self.cards[g.label]
            c.setText(f"<span style='color:{GOOD if ok else WARN}'>{'On' if ok else g.state}</span>")
        u = self.ctx.update
        self.up_box.setVisible(bool(u))
        if u:
            if not self.up_btn.text().startswith(("Downloading", "Installing")):
                self.up_text.setText(f"Bastion {u.version} is available. You have {core.VERSION}.")
            if self._told_update != u.version:
                self._told_update = u.version
                self.tray.showMessage("Bastion update", f"Bastion {u.version} is available. Open Bastion to update.", QIcon(shield(GOOD)), 9000)
        held = list(self.ctx.held.items())
        self.held_box.setVisible(bool(held))
        if held:
            pid, (p, why) = held[0]
            self.held_text.setText(f"<b>Frozen:</b> process {pid}, {why}")
        rows = self.ctx.log.latest(6, MEDIUM)
        fill(self.recent, [(LEVELS[r[2]], time.strftime("%b %d %H:%M", time.localtime(r[1])), r[4]) for r in rows], [COLOURS[r[2]] for r in rows])
        st = harden.status(self.ctx.defender)
        fill(self.htable, [("On" if on else "Off", n, note) for n, on, note in st], [GOOD if on else WARN for _, on, _ in st])
        self.h_undo.setEnabled(harden.BACKUP.exists())
        self.ai_refresh()
        i = self.ctx.intel
        when = time.strftime("%b %d %H:%M", time.localtime(i.updated)) if i.updated else "never"
        self.intel_text.setText(f"Block lists: {len(i.ips):,} botnet servers, {len(i._lo):,} criminal networks, {len(i.vuln_drivers):,} abusable drivers, {self.ctx.engine.rules.count:,} malware signatures. Updated {when}. Known malware files are recognised by Defender."
                                + ("  Failed: " + ", ".join(i.errors) if i.errors else ""))

    def on_event(self, row):
        if row[2] >= self.ctx.settings["notify_level"]:
            self.tray.showMessage("Bastion: " + LEVELS[row[2]], row[4] + "\n" + row[5][:160], QIcon(shield(COLOURS[row[2]])), 9000)
        if row[2] >= MEDIUM:
            self.load_alerts()
            self.load_quarantine()

    def load_alerts(self):
        rows = self.ctx.log.latest(300, self.filter.currentIndex())
        self._alert_rows = rows
        fill(self.alerts, [(LEVELS[r[2]], time.strftime("%b %d %H:%M", time.localtime(r[1])), r[3], r[4], r[5].replace("\n", "  |  ")) for r in rows], [COLOURS[r[2]] for r in rows])

    def load_quarantine(self):
        self._q = self.ctx.quarantine.items()
        fill(self.qtable, [(time.strftime("%b %d %H:%M", time.localtime(i["at"])), i["path"], i["why"]) for i in self._q])

    # ---------------------------------------------------------------- actions
    def work(self, name, fn):
        def go():
            try:
                out = fn()
            except Exception as e:
                out = e
            self.bridge.done.emit(name, out)
        threading.Thread(target=go, daemon=True).start()

    def say(self, text):
        QMessageBox.information(self, "Bastion", text)

    def ask(self, text):
        return QMessageBox.question(self, "Bastion", text) == QMessageBox.Yes

    def release(self, end):
        if self.ctx.held:
            self.ctx.release(next(iter(self.ctx.held)), end)
            self.refresh()

    def scan_usual(self):
        f = core.folders()
        self.scan([f[n] for n in ("Downloads", "Desktop", "Temp") if n in f])

    def scan_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Folder to scan")
        if d:
            self.scan([Path(d)])

    def busy(self, on):
        self.scanning = on
        for b in self.scan_buttons:
            b.setEnabled(not on)
        self.stop_btn.setEnabled(on)

    def scan(self, roots=None):
        """Bastion's own threaded scan of these folders, or of the whole computer."""
        if self.scanning:
            return
        if not self.ctx.scan_lock.acquire(blocking=False):
            self.scan_text.setText("The daily scan is already running in the background.")
            return
        self.cancel_scan.clear()
        self.busy(True)
        self.bar.setRange(0, 0)
        self.scan_text.setText("Checking running programs and drivers" if roots is None else "Listing files")
        self.results, self._shown = [], 0
        thorough, remember = self.c_thorough.isChecked(), self.c_fast.isChecked()

        def job():
            try:
                if roots is None:
                    return scanner.full(self.ctx, self.cancel_scan, thorough, remember, self.bridge.scan.emit)
                self.ctx.engine.rules.load()
                return scanner.Scanner(self.ctx.engine, self.cancel_scan, thorough, False).run(roots, self.bridge.scan.emit)
            finally:
                self.ctx.scan_lock.release()
        self.work("scan", job)

    def check_link(self):
        level, head, reasons = web.check_link(self.link_box.text(), self.ctx.intel.bad_site)
        self.link_text.setStyleSheet(f"color: {(GOOD, WARN, BAD)[level]}")
        self.link_text.setText(head + ("\n" + "\n".join("- " + r for r in reasons) if reasons else ""))

    def on_scan(self, s):
        if not s.walking:
            done = s.checked + s.unchanged
            self.bar.setRange(0, max(1, done + s.files.qsize()))
            self.bar.setValue(done)
        secs = max(1, time.time() - s.began)
        self.scan_text.setText(f"{s.seen:,} files seen, {s.checked:,} checked, {s.unchanged:,} unchanged, {s.checked / secs:,.0f}/s on {s.checkers} threads, {len(s.found)} found"
                               + ("   waiting for memory" if s.waiting else "   " + s.now[-70:]))
        if len(s.found) != self._shown:
            self.results, self._shown = list(s.found), len(s.found)
            self.show_found()

    def on_done(self, name, out):
        if name == "scan":
            self.busy(False)
            self.bar.setRange(0, 1)
            self.bar.setValue(1)
        if name == "ai":
            self.ai_go.setEnabled(True)
            self.ai_out.setPlainText(f"The AI can't answer now: {out}." if isinstance(out, Exception) else out)
        elif isinstance(out, Exception):
            (self.scan_text if name == "scan" else self.h_text).setText("Failed: " + str(out))
        elif name == "scan":
            self.results = sorted(out.found, key=lambda r: -r.score)
            self.show_found()
            self.scan_text.setText(scanner.summary(out))
        elif name == "update-progress":
            self.up_btn.setText("Installing")
            self.up_text.setText("Waiting for Windows to approve the update")
            return
        elif name == "update":
            self.up_btn.setEnabled(True)
            self.up_btn.setText("Update now")
            self.up_text.setText(f"Update failed: {out}" if isinstance(out, Exception) else "Installing: Bastion will close and start again.")
            return
        elif name == "updatecheck":
            if isinstance(out, Exception):
                self.upd_text.setText(f"Could not reach GitHub: {str(out)[:120]}")
            else:
                self.ctx.update = out
                self.upd_text.setText(f"Bastion {out.version} is available: see the Protection page." if out else f"You have the newest Bastion ({core.VERSION}).")
            return
        elif name == "harden":
            self.h_text.setText("Done. The list updates in a moment." if out[0] else out[1])
            g = next((g for g in self.ctx.guards if g.label == "Defender"), None)
            if out[0] and g:
                self.work("recheck", g.step)
        self.refresh()

    def show_found(self):
        fill(self.found, [(("", "Suspicious, unconfirmed", "Likely dangerous, unconfirmed", "Known malware")[r.verdict], r.path, "; ".join(r.reasons)) for r in self.results], [COLOURS[2 + min(2, r.verdict - 1)] for r in self.results])

    def picked(self, t, items):
        return [items[i.row()] for i in t.selectionModel().selectedRows() if i.row() < len(items)]

    def quarantine_found(self):
        sel = self.picked(self.found, self.results)
        unsure = sum(r.verdict < E.MALWARE for r in sel)
        if not sel or not self.ask(f"Quarantine {len(sel)} file(s)?\n\n" + (f"{unsure} of them are only suspected and may be harmless: home-made tools, game mods and installers often look like this. A program may stop working until you restore its file.\n\n" if unsure else "")
                                   + "Nothing is deleted. You can put them back from the Quarantine page."):
            return
        for r in sel:
            no = E.protected(r.path)
            if no:
                self.say(f"{r.path}\n\nLeft alone: {no}.")
                continue
            try:
                self.ctx.quarantine.put(r.path, "; ".join(r.reasons))
                self.results.remove(r)
            except OSError as e:
                self.say(f"{r.path}\n{e}")
        self.show_found()
        self.load_quarantine()

    def trust_found(self):
        for r in self.picked(self.found, self.results):
            self.ctx.settings.allow(r.sha256 or r.path)
            self.results.remove(r)
        self.show_found()

    def open_alert(self):
        for r in self.picked(self.alerts, self._alert_rows)[:1]:
            p = Path(r[6])
            if p.exists():
                os.startfile(str(p.parent if p.is_file() else p))

    def trust_alert(self):
        for r in self.picked(self.alerts, self._alert_rows)[:1]:
            if r[6] and self.ask(f"Stop checking this?\n\n{r[6]}"):
                self.ctx.settings.allow(r[6])

    def q_restore(self):
        for i in self.picked(self.qtable, self._q):
            if self.ask(f"Put this back? Only do it if you are sure it is safe.\n\n{i['path']}"):
                try:
                    self.ctx.settings.allow(i["sha256"])
                    self.ctx.quarantine.restore(i["id"])
                except OSError as e:
                    self.say(str(e))
        self.load_quarantine()

    def q_delete(self):
        sel = self.picked(self.qtable, self._q)
        if sel and self.ask(f"Permanently delete {len(sel)} file(s)? This cannot be undone. If you are not sure they are malware, leave them here: they cannot run."):
            for i in sel:
                self.ctx.quarantine.delete(i["id"])
        self.load_quarantine()

    def harden_on(self):
        if self.ask("Turn on all layers?\n\nOffice and script attack rules, network protection and strong cloud blocking will block. Protected folders will only log, so games and builds keep working."
                    "\n\nWindows settings: Internet Explorer mode and Remote Desktop/Assistance go off, USB auto-run goes off, "
                    "Windows asks before every administrator change, eight rarely used Windows tools lose internet access, and the firewall blocks uninvited incoming connections."
                    "\n\nUndo reverses it. Windows will ask for administrator approval."):
            self.h_text.setText("Waiting for Windows")
            self.work("harden", lambda: harden.run_elevated(harden.apply_script()))

    def dns_on(self):
        if self.ask("Block dangerous websites for every browser and app on this PC?\n\n"
                    "Your wired and Wi-Fi connections will look up sites through Quad9, a Swiss non-profit service that refuses known malware and phishing sites and does not log your IP address. "
                    "A VPN keeps its own settings. Your old settings are saved, and 'Restore my old DNS' puts them back.\n\nWindows will ask for administrator approval."):
            self.h_text.setText("Waiting for Windows")
            self.work("harden", lambda: harden.run_elevated(harden.dns_block_script()))

    def dns_off(self):
        if self.ask("Put back the DNS settings this PC had before?"):
            self.work("harden", lambda: harden.run_elevated(harden.dns_restore_script()))

    def harden_undo(self):
        if self.ask("Put Defender's settings back as they were before?"):
            self.work("harden", lambda: harden.run_elevated(harden.undo_script()))

    def welcome(self):
        """Once, before anything starts: what Bastion does to this PC, in plain words."""
        s = self.ctx.settings
        if s["welcomed"]:
            return
        s["welcomed"] = True
        if core.autostart_on():
            return
        self.say("Welcome to Bastion.\n\n"
                 "It works beside your antivirus and does not replace it.\n\n"
                 "- It watches new files, programs, start-up entries, drivers and connections on this PC.\n"
                 "- It keeps a few hidden bait files in Documents, Pictures and Downloads to notice ransomware. Please leave them there.\n"
                 "- It downloads public block lists. It sends nothing about you or this PC anywhere.\n"
                 "- It checks the sites you open in your browsers against phishing lists, on this PC only. You can switch this off in Settings.\n"
                 "- It quarantines only files known to be malware, and only freezes programs caught misbehaving. Both can be undone, and both can be switched off in Settings.\n\n"
                 "No program catches everything. Keep Windows updated and keep backups.")
        if telemetry.PING_URL:
            self.ctx.settings["usage_ping"] = self.ask("May Bastion send an anonymous usage ping?\n\nIt would send only a random id and the version number — never your IP, your name or anything about your files — so the author can count how many people use Bastion. You can change this any time in Settings.\n\nThis is optional and off unless you choose Yes.")
        self.auto.setChecked(self.ask("Keep Bastion running all the time? It will start with Windows and start again if something closes it."))

    def update_now(self):
        u = self.ctx.update
        if not u:
            return
        if not core.FROZEN:
            os.startfile(u.page)
            return
        if not self.ask(f"Update to Bastion {u.version}?\n\nIt downloads from this project's GitHub releases, is checked against the checksum GitHub published, "
                        "and Windows will ask for administrator approval. Bastion closes and starts again by itself."):
            return
        self.up_btn.setEnabled(False)
        self.up_btn.setText("Downloading")
        self.up_text.setText(f"Downloading Bastion {u.version}")

        def job():
            path = updater.download(u, str(core.DATA / "updates"))
            self.bridge.done.emit("update-progress", None)
            updater.install(path)
            return path
        self.work("update", job)

    def check_updates_now(self):
        self.upd_text.setText("Asking GitHub")
        self.work("updatecheck", updater.check)

    def set_auto(self, on):
        code, out = core.set_autostart(on)
        if on and code != 0:
            self.say("It will start with Windows, but the restart task could not be made:\n" + out[-300:])

    def bring_up(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, ev):
        if self.quitting:
            return super().closeEvent(ev)
        ev.ignore()
        self.hide()
        self.tray.showMessage("Bastion", "Still protecting this PC. Right-click the shield to exit.", QIcon(shield(GOOD)), 4000)

    def exit_app(self):
        if self.ask("Stop Bastion? Microsoft Defender keeps running, but Bastion's guards stop until you start it again."):
            self.ctx.settings["stopped_by_user"] = True
            self.quitting = True
            for pid in list(self.ctx.held):
                self.ctx.release(pid)
            self.ctx.shutdown()
            self.tray.hide()
            QApplication.quit()
