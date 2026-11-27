"""The live HUD: an animated reactor core that shows the protection state, and a typed-out feed of what the guards are doing.

Everything shown is real state from the guards and the alert log. The animation only runs while the window is on screen."""
import math
import time
from collections import deque

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QConicalGradient, QFont, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap, QPolygonF, QRadialGradient, QTextCharFormat
from PySide6.QtWidgets import QPlainTextEdit, QSizePolicy, QWidget

MONO = "Cascadia Mono, Consolas"


def tint(colour, alpha):
    c = QColor(colour)
    c.setAlpha(alpha)
    return c


class Reactor(QWidget):
    """Rotating rings, a radar sweep and a pulsing core in the colour of the current state."""

    def __init__(self, size=190):
        super().__init__()
        self.setFixedSize(size, size)
        self.colour, self.word, self.busy = QColor("#3fd8ff"), "ONLINE", False
        self.t0 = time.monotonic()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update)

    def set_state(self, colour, word, busy=False):
        self.colour, self.word, self.busy = QColor(colour), word, busy
        self.update()

    def showEvent(self, ev):
        self.timer.start(33)
        super().showEvent(ev)

    def hideEvent(self, ev):
        self.timer.stop()
        super().hideEvent(ev)

    def paintEvent(self, ev):
        t = time.monotonic() - self.t0
        speed = 2.4 if self.busy else 1.0
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w = self.width()
        c = QPointF(w / 2, w / 2)
        r = w / 2 - 4
        col = self.colour

        glow = QRadialGradient(c, r)
        glow.setColorAt(0, tint(col, 70))
        glow.setColorAt(0.55, tint(col, 18))
        glow.setColorAt(1, tint(col, 0))
        p.setPen(Qt.NoPen)
        p.setBrush(glow)
        p.drawEllipse(c, r, r)

        # outer tick ring, slowly turning
        p.save()
        p.translate(c)
        p.rotate(t * 8 * speed)
        for i in range(72):
            major = i % 6 == 0
            p.setPen(QPen(tint(col, 210 if major else 90), 2 if major else 1))
            p.drawLine(QPointF(0, -r), QPointF(0, -r + (9 if major else 5)))
            p.rotate(5)
        p.restore()

        def arcs(radius, width, segments, gap, angle, alpha):
            box = QRectF(c.x() - radius, c.y() - radius, 2 * radius, 2 * radius)
            pen = QPen(tint(col, alpha), width)
            pen.setCapStyle(Qt.FlatCap)
            p.setPen(pen)
            p.setBrush(Qt.NoBrush)
            span = 360 / segments
            for i in range(segments):
                p.drawArc(box, int((angle + i * span) * 16), int((span - gap) * 16))

        arcs(r - 16, 3, 3, 28, -t * 30 * speed, 200)
        arcs(r - 26, 6, 12, 9, t * 18 * speed, 120)
        arcs(r - 38, 1.5, 1, 0, 0, 90)

        # radar sweep
        sweep = QConicalGradient(c, -t * 90 * speed)
        sweep.setColorAt(0, tint(col, 120))
        sweep.setColorAt(0.18, tint(col, 0))
        sweep.setColorAt(1, tint(col, 0))
        p.setPen(Qt.NoPen)
        p.setBrush(sweep)
        p.drawEllipse(c, r - 40, r - 40)

        # pulsing core
        pulse = 0.5 + 0.5 * math.sin(t * (5 if self.busy else 2.2))
        core = r * (0.30 + 0.03 * pulse)
        g = QRadialGradient(c, core)
        g.setColorAt(0, QColor(255, 255, 255, 235))
        g.setColorAt(0.35, tint(col, 230))
        g.setColorAt(1, tint(col, 25))
        p.setBrush(g)
        p.drawEllipse(c, core, core)
        p.setPen(QPen(tint(col, 160 + int(80 * pulse)), 2))
        p.setBrush(Qt.NoBrush)
        p.drawEllipse(c, core + 6, core + 6)

        f = QFont("Segoe UI", max(7, int(w / 22)))
        f.setBold(True)
        f.setLetterSpacing(QFont.AbsoluteSpacing, 2)
        p.setFont(f)
        p.setPen(QColor("#e9fbff"))
        p.drawText(QRectF(0, c.y() + core + 10, w, 20), Qt.AlignHCenter | Qt.AlignTop, self.word)
        p.end()


class Feed(QPlainTextEdit):
    """A terminal-style log that types each new line out a few characters at a time."""

    def __init__(self):
        super().__init__()
        self.setReadOnly(True)          # plain text only: lines can quote file names written by malware
        self.setObjectName("feed")
        self.setMaximumBlockCount(300)
        self.setFont(QFont(MONO.split(",")[0], 10))
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.queue = deque(maxlen=40)
        self.line = None
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(16)

    def say(self, tag, text, colour="#3fd8ff"):
        self.queue.append((f"[{time.strftime('%H:%M:%S')}] {tag.upper():<9}", " " + " ".join(str(text).split())[:220], colour))

    def tick(self):
        if self.line is None:
            if not self.queue:
                return
            head, body, colour = self.queue.popleft()
            if self.document().characterCount() > 1:
                self.write("\n", "#3fd8ff")
            self.write(head, colour)
            self.line = [body, colour]
        body, colour = self.line
        n = 3 if len(self.queue) < 3 and self.isVisible() else len(body)     # catch up at once when busy or hidden
        self.write(body[:n], "#c9e7f2")
        self.line[0] = body[n:]
        if not self.line[0]:
            self.line = None

    def write(self, text, colour):
        cur = self.textCursor()
        cur.movePosition(cur.MoveOperation.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(colour))
        cur.insertText(text, fmt)
        self.setTextCursor(cur)
        self.ensureCursorVisible()


# ---------------------------------------------------------------- the HUD shell
CYAN = "#3fd8ff"


class Backdrop(QWidget):
    """The window's background: a deep gradient, a faint hex grid, a slow scanning beam and frame brackets."""

    def __init__(self):
        super().__init__()
        self.grid = None
        self.t0 = time.monotonic()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update)

    def showEvent(self, ev):
        self.timer.start(50)
        super().showEvent(ev)

    def hideEvent(self, ev):
        self.timer.stop()
        super().hideEvent(ev)

    def hexes(self):
        pm = QPixmap(self.size())
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(QPen(QColor(63, 216, 255, 16), 1))
        s = 22.0
        dx, dy = s * math.sqrt(3), s * 1.5
        for r in range(int(self.height() / dy) + 2):
            for c in range(int(self.width() / dx) + 2):
                cx, cy = c * dx + (dx / 2 if r % 2 else 0), r * dy
                p.drawPolygon(QPolygonF([QPointF(cx + s * math.cos(math.radians(60 * k + 30)), cy + s * math.sin(math.radians(60 * k + 30))) for k in range(6)]))
        p.end()
        return pm

    def paintEvent(self, ev):
        p = QPainter(self)
        w, h = self.width(), self.height()
        g = QRadialGradient(QPointF(w * 0.45, h * 0.25), max(w, h))
        g.setColorAt(0, QColor("#0c2233"))
        g.setColorAt(0.6, QColor("#050c14"))
        g.setColorAt(1, QColor("#020407"))
        p.fillRect(self.rect(), g)
        if self.grid is None or self.grid.size() != self.size():
            self.grid = self.hexes()
        p.drawPixmap(0, 0, self.grid)
        y = ((time.monotonic() - self.t0) * 70) % (h + 240) - 120
        beam = QLinearGradient(0, y - 120, 0, y + 6)
        beam.setColorAt(0, QColor(63, 216, 255, 0))
        beam.setColorAt(0.95, QColor(63, 216, 255, 22))
        beam.setColorAt(1, QColor(63, 216, 255, 70))
        p.fillRect(QRectF(0, y - 120, w, 126), beam)
        p.setPen(QPen(QColor(63, 216, 255, 140), 2))
        L = 28
        for x, y0, sx, sy in ((3, 3, 1, 1), (w - 3, 3, -1, 1), (3, h - 3, 1, -1), (w - 3, h - 3, -1, -1)):
            p.drawLine(QPointF(x, y0), QPointF(x + sx * L, y0))
            p.drawLine(QPointF(x, y0), QPointF(x, y0 + sy * L))
        p.end()


class Panel(QWidget):
    """A chamfered glass panel with glowing corner brackets and an optional small title."""

    def __init__(self, title="", accent=CYAN):
        super().__init__()
        self.title, self.accent = title.upper(), QColor(accent)

    def set_accent(self, colour):
        if QColor(colour) != self.accent:
            self.accent = QColor(colour)
            self.update()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h, k = self.width() - 1, self.height() - 1, 12
        path = QPainterPath(QPointF(k, 0.5))
        for x, y in ((w, 0.5), (w, h - k), (w - k, h), (0.5, h), (0.5, k)):
            path.lineTo(x, y)
        path.closeSubpath()
        p.fillPath(path, QColor(6, 22, 34, 205))
        p.setPen(QPen(QColor(22, 80, 106), 1))
        p.drawPath(path)
        a = self.accent
        p.setPen(QPen(a, 2))
        L = 16
        p.drawLine(QPointF(k, 1), QPointF(k + L * 2, 1))
        p.drawLine(QPointF(w - L, 1), QPointF(w, 1))
        p.drawLine(QPointF(w, 1), QPointF(w, L))
        p.drawLine(QPointF(1, h), QPointF(L, h))
        p.drawLine(QPointF(1, h), QPointF(1, h - L))
        p.drawLine(QPointF(w - k, h), QPointF(w - k - L * 2, h))
        if self.title:
            f = QFont("Bahnschrift", 8)
            f.setLetterSpacing(QFont.AbsoluteSpacing, 2)
            p.setFont(f)
            p.setPen(tint(a, 200))
            p.drawText(QPointF(k + L * 2 + 8, 12), self.title)
        p.end()


class Graph(QWidget):
    """A live line graph of the last minute of one real reading (CPU, memory, network)."""

    def __init__(self, name, colour=CYAN):
        super().__init__()
        self.name, self.colour, self.text = name, QColor(colour), "--"
        self.values = deque([0.0] * 60, maxlen=60)
        self.setMinimumHeight(64)

    def push(self, fraction, text):
        self.values.append(max(0.0, min(1.0, fraction)))
        self.text = text
        self.update()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h, top = self.width(), self.height(), 18
        p.setPen(QPen(QColor(22, 80, 106, 120), 1, Qt.DotLine))
        for i in range(1, 4):
            y = top + (h - top) * i / 4
            p.drawLine(QPointF(0, y), QPointF(w, y))
        n = len(self.values)
        pts = [QPointF(w * i / (n - 1), h - 2 - (h - top - 2) * v) for i, v in enumerate(self.values)]
        line = QPainterPath(pts[0])
        for q in pts[1:]:
            line.lineTo(q)
        area = QPainterPath(line)
        area.lineTo(w, h)
        area.lineTo(0, h)
        area.closeSubpath()
        g = QLinearGradient(0, top, 0, h)
        g.setColorAt(0, tint(self.colour, 110))
        g.setColorAt(1, tint(self.colour, 0))
        p.fillPath(area, g)
        p.setPen(QPen(self.colour, 1.6))
        p.setBrush(Qt.NoBrush)
        p.drawPath(line)
        p.setBrush(self.colour)
        p.drawEllipse(pts[-1], 2.5, 2.5)
        f = QFont("Bahnschrift", 8)
        f.setLetterSpacing(QFont.AbsoluteSpacing, 2)
        p.setFont(f)
        p.setPen(QColor("#5f8aa0"))
        p.drawText(QPointF(0, 11), self.name)
        p.setFont(QFont(MONO.split(",")[0], 10))
        p.setPen(QColor("#e9fbff"))
        p.drawText(QRectF(0, 0, w, 14), Qt.AlignRight | Qt.AlignVCenter, self.text)
        p.end()


class Radar(QWidget):
    """Threat radar: each blip is a real alert from the last 24 hours. Newer alerts sit nearer the centre; the colour is its level."""

    def __init__(self, size=170):
        super().__init__()
        self.setFixedSize(size, size)
        self.blips = []
        self.t0 = time.monotonic()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update)
        self.setToolTip("Alerts from the last 24 hours. Newer ones sit nearer the centre.")

    def set_blips(self, blips):
        self.blips = blips

    def showEvent(self, ev):
        self.timer.start(40)
        super().showEvent(ev)

    def hideEvent(self, ev):
        self.timer.stop()
        super().hideEvent(ev)

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w = self.width()
        c, r = QPointF(w / 2, w / 2 - 6), w / 2 - 14
        cyan = QColor(CYAN)
        p.setBrush(QColor(4, 14, 22, 200))
        p.setPen(QPen(tint(cyan, 150), 1.5))
        p.drawEllipse(c, r, r)
        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(tint(cyan, 45), 1))
        for k in (0.25, 0.5, 0.75):
            p.drawEllipse(c, r * k, r * k)
        p.drawLine(QPointF(c.x() - r, c.y()), QPointF(c.x() + r, c.y()))
        p.drawLine(QPointF(c.x(), c.y() - r), QPointF(c.x(), c.y() + r))
        ang = ((time.monotonic() - self.t0) * 80) % 360
        sweep = QConicalGradient(c, -ang)     # turns clockwise, trail behind the beam
        sweep.setColorAt(0, tint(cyan, 120))
        sweep.setColorAt(0.12, tint(cyan, 0))
        sweep.setColorAt(1, tint(cyan, 0))
        p.setPen(Qt.NoPen)
        p.setBrush(sweep)
        p.drawEllipse(c, r, r)
        for a, d, colour in self.blips:
            behind = (a + ang) % 360            # degrees since the beam passed this blip
            glow = max(70, 255 - int(behind * 0.7))
            x = c.x() + math.cos(math.radians(a)) * r * d
            y = c.y() - math.sin(math.radians(a)) * r * d
            p.setBrush(tint(colour, glow // 3))
            p.drawEllipse(QPointF(x, y), 7, 7)
            p.setBrush(tint(colour, glow))
            p.drawEllipse(QPointF(x, y), 3, 3)
        f = QFont("Bahnschrift", 7)
        f.setLetterSpacing(QFont.AbsoluteSpacing, 2)
        p.setFont(f)
        p.setPen(tint(cyan, 170))
        p.drawText(QRectF(0, w - 12, w, 12), Qt.AlignHCenter, f"THREATS 24H : {len(self.blips)}")
        p.end()
