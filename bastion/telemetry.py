"""Optional, opt-in, anonymous usage ping. OFF by default.

When the owner turns it on, Bastion tells a counting server you run (PING_URL) two things: a random id made on this PC, and the app version.
That is all. No IP address is sent on purpose or stored by the server; no file name, path, user name, alert or anything about this PC ever leaves it.
The random id lets the server count how many PCs run Bastion and how many are active, without knowing whose they are. It is not sent anywhere until the owner says yes."""
import threading
import time
import uuid

import requests

from . import core

# Set this to the address of your own counter (the Cloudflare Worker in server/). Empty means nothing is ever sent, whatever the setting says.
PING_URL = ""
EVERY = 6 * 3600


def install_id(settings):
    """A random id for this install, made once and kept. Not tied to the PC, the user or anything about them."""
    if not settings["install_id"]:
        settings["install_id"] = uuid.uuid4().hex
    return settings["install_id"]


class Pinger(threading.Thread):
    """Sends one tiny ping at startup and every few hours, only while the owner has turned it on."""

    def __init__(self, ctx):
        super().__init__(daemon=True, name="usage ping")
        self.ctx = ctx
        self.web = requests.Session()
        self.web.trust_env = False      # never through a proxy that could add data
        self.last = 0.0

    def tick(self):
        """Send one ping if it is turned on, a counter address is set, and enough time has passed. Never raises."""
        if not (PING_URL and self.ctx.settings["usage_ping"] and time.time() - self.last > EVERY):
            return
        self.last = time.time()
        try:
            self.web.post(PING_URL, json={"id": install_id(self.ctx.settings), "version": core.VERSION}, timeout=15)
        except requests.RequestException:
            pass                    # a count is never worth bothering the owner about

    def run(self):
        while not self.ctx.stop.is_set():
            self.tick()
            self.ctx.stop.wait(300)
