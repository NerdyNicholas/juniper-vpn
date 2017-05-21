
import time
import logging
import shlex
import subprocess
import os
import signal

logger = logging.getLogger(__name__)

class Ncui:
    """
    Starts and stops the ncui_wrapper.
    The juniper ncui library is executed using a ncui wrapper which
    loads the ncui libray and calls the main function in the library.
    """

    def __init__(self, path, cert):
        self.jndir = path
        self.ncdir = os.path.join(self.jndir, "network_connect/")
        self.cert = cert

        # the ncui wrapper has to be run from the network_connect directory
        self.ncui = os.path.join(self.ncdir, "ncui_wrapper")

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
        cmd = "%s -h %s -c DSID=%s -f %s" % (self.ncui, host, dsid, self.cert)
        logger.debug("Starting ncui with command: %s", cmd.replace(dsid,"*"))
        cmd = shlex.split(cmd)
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, cwd=self.ncdir)
        # send <enter> to Password prompt that pops up after
        # starting the NCUI binary
        self.proc.stdin.write("\n")

    def stop(self):
        if self.isRunning():
            self.proc.terminate()
            time.sleep(1)
            if self.isRunning():
                logger.error("Failed to stop ncui")
        self.proc = None

        # second kill any processes we didn"t start
        try:
            pids = map(int, subprocess.check_output(["pidof", "ncui_wrapper"]).split())
            for pid in pids:
                os.kill(pid, signal.SIGTERM)
            if len(pids) > 0:
                time.sleep(1)
            pids = map(int, subprocess.check_output(["pidof", "ncui_wrapper"]).split())
            for pid in pids:
                os.kill(pid, signal.SIGKILL)
            if len(pids) > 0:
                time.sleep(1)
        except:
            # if no pids are found, will throw an exception or if pid doesn"t exist for kill
            pass

