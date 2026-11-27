"""The live HUD: an animated reactor core that shows the protection state, and a typed-out feed of what the guards are doing.

Everything shown is real state from the guards and the alert log. The animation only runs while the window is on screen."""
import math
import time
from collections import deque

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QConicalGradient, QFont, QPainter, QPen, QRadialGradient, QTextCharFormat
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
