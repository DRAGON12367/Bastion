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

import math
import zlib

import psutil

from . import ai, core, engine as E, harden, hud, scanner, telemetry, updater, web
from .core import HIGH, LEVELS, MEDIUM

GOOD, WARN, BAD, DIM = "#3fd8ff", "#ffb547", "#ff4d5e", "#7f9bb0"
COLOURS = [DIM, "#9ec3d6", WARN, "#ff8a3d", BAD]
STYLE = """
* { font-family: 'Segoe UI'; font-size: 13px; color: #d8f3ff; }
QMainWindow, QMessageBox { background: qradialgradient(cx:0.5, cy:0.3, radius:1.1, stop:0 #0b1c2a, stop:1 #04080d); }
QStackedWidget, QStackedWidget > QWidget { background: transparent; }
QListWidget { background: rgba(2, 8, 14, 0.55); border: none; border-right: 1px solid #12384c; padding: 14px 6px; outline: 0; font-family: 'Bahnschrift'; font-size: 13px; }
QListWidget::item { padding: 11px 14px; border-radius: 4px; margin: 2px 4px; color: #7fb4cc; }
QListWidget::item:selected { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(63,216,255,0.28), stop:1 rgba(63,216,255,0)); color: #e9fbff; border-left: 3px solid #3fd8ff; }
QListWidget::item:hover { background: #0a1d29; }
QFrame#card { background: rgba(10, 30, 44, 0.78); border: 1px solid #16506a; border-radius: 6px; }
QLabel#h1 { font-family: 'Bahnschrift'; font-size: 22px; font-weight: 600; color: #e9fbff; }
QLabel#brand { font-family: 'Bahnschrift'; font-size: 24px; font-weight: 700; color: #e9fbff; }
QLabel#greet { font-family: 'Bahnschrift'; font-size: 13px; color: #3fd8ff; }
QLabel#clock { font-family: 'Cascadia Mono', Consolas; font-size: 13px; color: #9fdcf0; qproperty-alignment: AlignRight; }
QLabel#chip { font-family: 'Bahnschrift'; font-size: 12px; font-weight: 600; padding: 5px 12px; border-radius: 3px; background: rgba(4, 14, 22, 0.8); }
QWidget#tile { background: rgba(10, 34, 50, 0.55); border: 1px solid #14465e; border-left: 2px solid #3fd8ff; }
QWidget#tile:hover { background: rgba(20, 60, 84, 0.7); }
QLabel#tilename { font-family: 'Bahnschrift'; font-size: 11px; font-weight: 600; color: #e9fbff; }
QLabel#tilestate { font-family: 'Cascadia Mono', Consolas; font-size: 10px; } QLabel#dim { color: #7f9bb0; }
QLabel#metric { font-family: 'Bahnschrift'; font-size: 26px; font-weight: 300; color: #3fd8ff; }
QLabel#mlabel { font-family: 'Bahnschrift'; font-size: 10px; color: #5f8aa0; font-weight: 600; }
QPushButton { font-family: 'Bahnschrift'; background: #0b2231; border: 1px solid #1c5a77; border-radius: 4px; padding: 8px 16px; color: #bfeeff; }
QPushButton:hover { background: #10324a; border-color: #3fd8ff; } QPushButton:disabled { color: #3f5868; border-color: #173445; }
QPushButton#main { background: #0d4a63; border-color: #3fd8ff; font-weight: 600; color: #e9fbff; } QPushButton#main:hover { background: #136182; }
QTableWidget { background: rgba(4, 14, 22, 0.6); border: 1px solid #16506a; border-radius: 6px; gridline-color: #0f2a3a; }
QTableWidget::item { padding: 5px; } QTableWidget::item:selected { background: #10324a; }
QHeaderView::section { background: #08192a; border: none; border-bottom: 1px solid #16506a; padding: 7px; color: #5f8aa0; }
QPlainTextEdit, QLineEdit { background: rgba(4, 12, 20, 0.9); border: 1px solid #16506a; border-radius: 6px; padding: 8px; }
QPlainTextEdit#feed { font-family: 'Cascadia Mono', Consolas; font-size: 12px; border-color: #1c5a77; }
QLineEdit:focus { border-color: #3fd8ff; }
QComboBox { background: #0b2231; border: 1px solid #1c5a77; border-radius: 4px; padding: 6px 10px; }
QComboBox QAbstractItemView { background: #08192a; }
QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid #1c5a77; border-radius: 3px; background: #050a10; }
QCheckBox::indicator:checked { background: #3fd8ff; border-color: #3fd8ff; }
QProgressBar { background: #08192a; border: 1px solid #16506a; border-radius: 4px; height: 8px; text-align: center; color: transparent; }
QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0d6f93, stop:1 #3fd8ff); border-radius: 3px; }
QScrollBar:vertical { background: transparent; width: 8px; } QScrollBar::handle:vertical { background: #16506a; border-radius: 4px; min-height: 24px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
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
        self.resize(1280, 820)
        self.setStyleSheet(STYLE)
        self.started = time.time()
        self._states, self._beat = {}, 0

        self.nav = QListWidget()
        self.nav.setFixedWidth(190)
        self.pages = QStackedWidget()
        for glyph, name, make in (("\u25c8", "Protection", self.page_home), ("\u25ce", "Scan", self.page_scan), ("\u25b2", "Alerts", self.page_alerts), ("\u2726", "AI", self.page_ai),
                                  ("\u25a3", "Quarantine", self.page_quarantine), ("\u2b22", "Hardening", self.page_harden), ("\u2699", "Settings", self.page_settings)):
            self.nav.addItem(f"{glyph}   {name.upper()}")
            self.pages.addWidget(make())
        self.nav.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.nav.setCurrentRow(0)

        head = QHBoxLayout()
        head.setContentsMargins(22, 14, 22, 6)
        brand = QVBoxLayout()
        brand.setSpacing(0)
        brand.addWidget(label("B A S T I O N", "brand"))
        sub = label(f"AUTONOMOUS DEFENSE GRID  //  BUILD {core.VERSION}", "mlabel")
        sub.setWordWrap(False)
        brand.addWidget(sub)
        head.addLayout(brand)
        head.addStretch()
        self.chip = label("", "chip")
        self.clock = label("", "clock")
        head.addWidget(self.chip)
        head.addSpacing(18)
        head.addWidget(self.clock)

        body = hud.Backdrop()
        outer = QVBoxLayout(body)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addLayout(head)
        h = QHBoxLayout()
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        h.addWidget(self.nav)
        h.addWidget(self.pages)
        outer.addLayout(h, 1)
        self.setCentralWidget(body)

        self._net = None
        psutil.cpu_percent(None)
        self.fast = QTimer(self)
        self.fast.timeout.connect(self.tick)
        self.fast.start(1000)

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
        v.setContentsMargins(22, 14, 26, 22)
        v.setSpacing(12)
        v.addWidget(label("// " + title.upper(), "h1"))
        if sub:
            v.addWidget(label(sub, "dim"))
        return w, v

    def page_home(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(22, 10, 26, 18)
        v.setSpacing(12)

        top = hud.Panel("core status")
        h = QHBoxLayout(top)
        h.setContentsMargins(20, 22, 20, 16)
        self.reactor = hud.Reactor(180)
        self.headline, self.subline = label("Starting", "h1"), label("", "dim")
        self.greet = label("", "greet")
        t = QVBoxLayout()
        t.addWidget(self.greet)
        t.addWidget(self.headline)
        t.addWidget(self.subline)
        m = QHBoxLayout()
        self.metrics = {}
        for key in ("SYSTEMS", "SIGNATURES", "ALERTS 24H", "UPTIME"):
            box = QVBoxLayout()
            box.setSpacing(0)
            val = label("--", "metric")
            box.addWidget(val)
            box.addWidget(label(key, "mlabel"))
            self.metrics[key] = val
            m.addLayout(box)
            m.addSpacing(22)
        m.addStretch()
        t.addSpacing(10)
        t.addLayout(m)
        t.addStretch()
        self.radar = hud.Radar(180)
        h.addWidget(self.reactor)
        h.addSpacing(18)
        h.addLayout(t, 1)
        h.addWidget(self.radar)
        v.addWidget(top)

        self.up_box = hud.Panel("update", WARN)
        ub = QHBoxLayout(self.up_box)
        ub.setContentsMargins(18, 20, 18, 12)
        self.up_text = label()
        self.up_text.setTextFormat(Qt.PlainText)
        ub.addWidget(self.up_text, 1)
        self.up_btn = button("Update now", self.update_now, True)
        ub.addWidget(self.up_btn)
        ub.addWidget(button("What's new", lambda: self.ctx.update and os.startfile(self.ctx.update.page)))
        self.up_box.setVisible(False)
        self._told_update = ""
        v.addWidget(self.up_box)

        self.held_box = hud.Panel("containment", BAD)
        hb = QHBoxLayout(self.held_box)
        hb.setContentsMargins(18, 20, 18, 12)
        self.held_text = label()
        hb.addWidget(self.held_text, 1)
        hb.addWidget(button("Resume", lambda: self.release(False)))
        hb.addWidget(button("End program", lambda: self.release(True)))
        v.addWidget(self.held_box)

        tele = hud.Panel("system telemetry")
        th = QHBoxLayout(tele)
        th.setContentsMargins(18, 22, 18, 10)
        th.setSpacing(22)
        self.g_cpu, self.g_mem, self.g_net = hud.Graph("PROCESSOR"), hud.Graph("MEMORY", "#7cf0c8"), hud.Graph("NETWORK", "#b48cff")
        for g in (self.g_cpu, self.g_mem, self.g_net):
            th.addWidget(g, 1)
        v.addWidget(tele)

        mods = hud.Panel("defense modules")
        grid = QGridLayout(mods)
        grid.setContentsMargins(16, 24, 16, 12)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(6)
        self.cards, self.tiles = {}, {}
        for i, (n, what) in enumerate((("Files", "New downloads and files"), ("Programs", "What starts and how"), ("Ransomware", "Bait files and mass changes"),
                                       ("Startup", "New auto-start entries"), ("Network", "Known bad servers"), ("USB drives", "Checked when plugged in"), ("Defender", "Windows' own engine"),
                                       ("RAT", "Remote control and spying"), ("Rootkit", "Drivers and hidden programs"), ("Firewall", "Firewall, DNS and malware check-ins"), ("AI", "Explains and learns"), ("Scanner", "Daily scan and signatures"), ("Web", "Phishing sites you open"), ("Updates", "Checks once a day"))):
            tile = QWidget()
            tile.setObjectName("tile")
            tile.setAttribute(Qt.WA_StyledBackground)
            tile.setToolTip(what)
            tv = QVBoxLayout(tile)
            tv.setContentsMargins(10, 6, 10, 6)
            tv.setSpacing(0)
            tv.addWidget(label(n.upper(), "tilename"))
            st = label("STARTING", "tilestate")
            tv.addWidget(st)
            self.cards[n], self.tiles[n] = st, tile
            grid.addWidget(tile, i // 7, i % 7)
        v.addWidget(mods)

        low = QHBoxLayout()
        low.setSpacing(12)
        a = hud.Panel("live feed")
        al = QVBoxLayout(a)
        al.setContentsMargins(10, 22, 10, 10)
        self.feed = hud.Feed()
        al.addWidget(self.feed, 1)
        b = hud.Panel("recent alerts")
        bl = QVBoxLayout(b)
        bl.setContentsMargins(10, 22, 10, 10)
        self.recent = table(["Level", "When", "What"], 2)
        bl.addWidget(self.recent, 1)
        low.addWidget(a, 3)
        low.addWidget(b, 2)
        v.addLayout(low, 1)
        self.feed.say("bastion", f"Bastion {core.VERSION} online. Bringing guards up.")
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
        h = QHBoxLayout()
        h.addWidget(button("Strict mode: block new, rare programs", self.strict_on))
        h.addWidget(button("Turn strict mode off", self.strict_off))
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
        h3 = QHBoxLayout()
        h3.addWidget(QLabel("abuse.ch Auth-Key (optional)"))
        self.key_box = QLineEdit(s["abusech_key"])
        self.key_box.setEchoMode(QLineEdit.Password)
        self.key_box.setPlaceholderText("Free from auth.abuse.ch: adds millions of known-malware fingerprints and malware sites")
        self.key_box.editingFinished.connect(self.set_key)
        h3.addWidget(self.key_box, 1)
        h3.addWidget(button("Get a free key", lambda: os.startfile("https://auth.abuse.ch/")))
        v.addLayout(h3)
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
            self.tray.setIcon(QIcon(shield(colour)))
            self.setWindowIcon(QIcon(shield(colour)))
        self.tray.setToolTip("Bastion: " + head)
        self.headline.setText(head)
        self.subline.setText(sub)
        self.hud_refresh(colour, head)
        for g in self.ctx.guards:
            ok = g.is_alive() and g.state == "on"
            c = self.cards[g.label]
            c.setText(f"<span style='color:{GOOD if ok else WARN}'>\u25cf {'ONLINE' if ok else g.state.upper()[:22]}</span>")
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
        self.intel_text.setText(f"Block lists: {len(i.ips):,} botnet servers, {len(i._lo):,} criminal networks, {len(i.vuln_drivers):,} abusable drivers, {self.ctx.engine.rules.count:,} malware signatures, {len(i.phish) + len(i.phish_live):,} phishing sites" + (f", {getattr(i, 'bazaar', 0):,} MalwareBazaar fingerprints, {len(i.malsites):,} malware sites" if i.auth_key else "") + f". Updated {when}. Known malware files are recognised by Defender."
                                + ("  Failed: " + ", ".join(i.errors) if i.errors else ""))

    def tick(self):
        if not self.isVisible():
            return
        self.clock.setText(time.strftime("%H:%M:%S") + "\n" + time.strftime("%a %d %b %Y").upper())
        cpu = psutil.cpu_percent(None)
        mem = psutil.virtual_memory().percent
        n = psutil.net_io_counters()
        now = (time.monotonic(), n.bytes_recv + n.bytes_sent)
        rate = 0.0
        if self._net:
            rate = max(0.0, (now[1] - self._net[1]) / max(0.2, now[0] - self._net[0]))
        self._net = now
        self.g_cpu.push(cpu / 100, f"{cpu:4.0f}%")
        self.g_mem.push(mem / 100, f"{mem:4.0f}%")
        self.g_net.push(min(1.0, math.log10(1 + rate / 1024) / 5), f"{rate / 1048576:,.2f} MB/s" if rate >= 1048576 else f"{rate / 1024:,.0f} KB/s")

    def hud_refresh(self, colour, head):
        """Reactor, metrics and feed lines: all from real guard state, nothing invented."""
        gs = self.ctx.guards
        up = sum(g.is_alive() and g.state == "on" for g in gs)
        word = {GOOD: "SECURE", WARN: "STANDBY" if head.startswith("Starting") else "CAUTION", BAD: "ALERT"}[colour]
        self.reactor.set_state(colour, "SCANNING" if self.scanning else word, self.scanning)
        self.chip.setText(f"\u25cf {('SCANNING' if self.scanning else word)}")
        self.chip.setStyleSheet(f"color: {colour}; border: 1px solid {colour};")
        now = time.time()
        self.radar.set_blips([((zlib.crc32((r[3] or "").encode() + r[4].encode()) % 360), 0.12 + 0.85 * min(1.0, (now - r[1]) / 86400), QColor(COLOURS[r[2]]))
                              for r in self.ctx.log.latest(40, core.LOW) if now - r[1] < 86400])
        hr = time.localtime().tm_hour
        self.greet.setText(("Good morning." if 5 <= hr < 12 else "Good afternoon." if 12 <= hr < 18 else "Good evening.") + f" {up} of {len(gs)} systems online.")
        secs = int(time.time() - self.started)
        n24 = self.ctx.log.count_since(86400, HIGH)
        for k, val in (("SYSTEMS", f"{up}/{len(gs)}"), ("SIGNATURES", f"{self.ctx.engine.rules.count:,}"), ("ALERTS 24H", str(n24)),
                       ("UPTIME", f"{secs // 3600:02d}:{secs // 60 % 60:02d}")):
            self.metrics[k].setText(val)
        self.metrics["ALERTS 24H"].setStyleSheet(f"color: {BAD if n24 else GOOD}")
        for g in gs:
            st = g.state if g.is_alive() else "stopped"
            if self._states.get(g.label) != st:
                if g.label in self._states or st != "starting":
                    self.feed.say(g.label, "online" if st == "on" else st, GOOD if st == "on" else WARN)
                self._states[g.label] = st
        self._beat += 1
        if self._beat % 30 == 0:        # about once a minute
            self.feed.say("status", f"{up}/{len(gs)} guards running. {head}.", colour)

    def on_event(self, row):
        self.feed.say(row[3] or "alert", f"{LEVELS[row[2]]}: {row[4]}", COLOURS[row[2]])
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

    def set_key(self):
        key = self.key_box.text().strip()
        if key != self.ctx.settings["abusech_key"]:
            self.ctx.settings["abusech_key"] = key
            self.ctx.intel.auth_key = key
            self.work("intel", self.ctx.intel.update)

    def strict_on(self):
        if self.ask("Turn on strict mode?\n\nDefender will block programs that are new and rare worldwide until its cloud vouches for them, use its strictest cloud "
                    "blocking, and hold suspicious files for up to 60 seconds while it checks. This stops most brand-new malware before it runs.\n\n"
                    "It can also block programs you build yourself, small tools and new game mods. If that happens, turn strict mode off here.\n\nWindows will ask for administrator approval."):
            self.h_text.setText("Waiting for Windows")
            self.work("harden", lambda: harden.run_elevated(harden.strict_on_script()))

    def strict_off(self):
        if self.ask("Turn strict mode off and put back the settings you had?"):
            self.work("harden", lambda: harden.run_elevated(harden.strict_off_script()))

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
