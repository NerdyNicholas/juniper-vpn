
import time
import logging
import shlex
import subprocess
import os
import signal

logger = logging.getLogger(__name__)

class OpenConnect:
    """
    Starts and stops the open connect vpn client in juniper mode.
    """

    def __init__(self, cert):
        self.cert = cert
        self.proc = None

    def isRunning(self):
        try:
            if not self.proc is None:
                self.proc.poll()
                if self.proc.returncode is None:
                    return True
        except:
            pass
        return False

    def start(self, host, dsid):
        self.stop()
        # --reconnect-timeout 30
        # -U,--setuid=USER drop privileges after connecting, to become user USER
        # --no-cert-check
        cmd = "gksudo -- openconnect -v --juniper -C 'DSID=%s' --no-cert-check %s" % (dsid, host)
        logger.debug("Starting openconnect with command: %s", dsid) #cmd.replace(dsid, "*"))
        cmd = shlex.split(cmd)
        self.proc = subprocess.Popen(cmd)

    def stop(self):
        # SIGINT -  performs a clean shutdown by logging the session off, disconnecting from the gateway, and running the vpnc-script to restore the network configuration.
        # SIGHUP - disconnects from the gateway and runs the vpnc-script, but does not log the session off; this allows for reconnection later using --cookie.
        # SIGUSR2 - forces an immediate disconnection and reconnection; this can be used to quickly recover from LAN IP address changes.
        # SIGTERM - exits immediately without logging off or running vpnc-script.

        cmd = "gksudo -- killall -SIGINT openconnect"
        logger.debug("Stopping openconnect with command: %s", cmd)
        cmd = shlex.split(cmd)
        self.proc = subprocess.Popen(cmd)

        if self.isRunning():
            self.proc.terminate()
            time.sleep(1)
            if self.isRunning():
                logger.error("Failed to stop open connect")
        self.proc = None
