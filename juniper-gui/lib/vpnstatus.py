
import logging


class VpnStatus:
    """
    Observable class containing sign in status and
    vpn connection information
    """

    def __init__(self):
        # signin status parameters
        self.signin = {
            "status" : "",
            "hostCheck" : "",
            "first": "",
            "last": "",
            "expired": "",
            "idle": ""
        }

        # connection parameters
        self.connection = {
            "status": "",
            "host": "",
            "ip": "",
            "bytesSent": "",
            "bytesRecv": "",
            "duration": "",
            "keepAlive": ""
        }

        self.error = ""
        self.isError = False
        self.obsv = lambda: None

    def setObserver(self, obsv):
        self.obsv = obsv

    def notify(self):
        self.obsv()

    def setSignStatus(self, status, hostCheck, first, last, expired, idle):
        if len(status) > 0:
            self.signin["status"] = status

        self.signin["first"] = first
        self.signin["last"] = last
        self.signin["expired"] = expired
        self.signin["idle"] = idle

        if hostCheck:
            self.signin['hostCheck'] = 'Running'
        else:
            self.signin['hostCheck'] = 'Not Running'

        self.notify()

    def setConnectionInfo(self, host, ip, sent, recv, duration):
        self.connection["host"] = host
        self.connection["ip"] = ip
        self.connection["bytesSent"] = sent
        self.connection["bytesRecv"] = recv
        self.connection["duration"] = duration
        self.notify()

    def setConnectionStatus(self, status):
        self.connection["status"] = status
        self.notify()

    def setKeepAliveStatus(self, keepAlive):
        self.connection["keepAlive"] = keepAlive
        self.notify()

    def setError(self, error):
        self.error = error
        self.isError = True
        self.notify()

    def getAndClearError(self):
        #TODO: lock
        self.isError = False
        return self.error






