
import subprocess
import shlex
import re
from datetime import timedelta, datetime
import netifaces
import logging
from ncui import Ncui

logger = logging.getLogger(__name__)

class VpnConnection:

    def __init__(self, jndir, devname='tun'):
        self.jndir = jndir
        self.devname = devname
        self.host = ""
        self.ip = ""
        self.bytesSent = 0
        self.bytesRecv = 0
        self.duration = timedelta()
        self.startDateTime = datetime.fromtimestamp(0)
        self.devUp = False
        self.ncui = Ncui(self.jndir)

    def setHost(self, host):
        self.host = host

    def connect(self, dsid):
        self.ncui.start(self.host, dsid)
        self.updateDevInfo()
        self.startDateTime = datetime.now()
        #if self.devUp:
            #self.fixRoutes()

    def disconnect(self):
        self.ncui.stop()
        self.updateDevInfo()

    def getConnectionInfo(self):
        info = {
            "host": self.host,
            "ip": self.ip,
            "bytesSent": self.bytesSent,
            "bytesRecv": self.bytesRecv,
            "duration": self.duration,
        }
        return info

    def getDevInfo(self, dev):
        info = []
        with open("/proc/net/dev", mode="r") as devs:
            for line in devs:
                match = re.match(r"^\s*(%s[0-9])" % dev, line)
                if not match is None:
                    info = line.split()
                    break
        try:
            name = info[0].split(":")[0]
            ipaddr = netifaces.ifaddresses(name)[netifaces.AF_INET][0]['addr']
            # ip, bytes recv, bytes sent
            devInfo = (ipaddr, int(info[1]), int(info[9]))
            return devInfo
        except:
            return ()

    def updateDevInfo(self):
        devInfo = self.getDevInfo(self.devname)
        if len(devInfo) >= 3:
            self.ip = devInfo[0]
            self.bytesRecv = devInfo[1]
            self.bytesSent = devInfo[2]
            self.duration = datetime.now() - self.startDateTime
            self.devUp = True
        else:
            self.ip = ""
            self.bytesRecv = ""
            self.bytesSent = ""
            self.duration = timedelta(0)
            self.devUp = False
        return self.devUp

    def isDevUp(self):
        return self.devUp

    def getGateway(self):
        try:
            gateway = netifaces.gateways()['default'][netifaces.AF_INET]
            return gateway
        except:
            return ""

    def checkGateway(self):
        return len(self.getGateway()) > 0

    def pingCheck(self, ipaddr):
        try:
            cmd = "ping -c 1 -W 2 %s >/dev/null 2>&1" % ipaddr
            cmd = shlex.split(cmd)
            subprocess.check_output(cmd)
            return True
        except:
            return False

    def fixRoutes(self):
        try:
            cmd = "/bin/bash -c \"ip route | grep 'metric 10' | grep -v default\""
            cmd = shlex.split(cmd)
            output = subprocess.check_output(cmd)
        except subprocess.CalledProcessError as cpe:
            output = cpe.output

        for line in output.split('\n'):
            newRoute = line.replace("metric 10", "metric 0")
            cmd = "ip route replace %s" % newRoute
            cmd = shlex.split(cmd)
            retcode = subprocess.call(cmd)
            if retcode != 0:
                logger.error("Error fixing hijacked route: %d = %s ", retcode, cmd)
