
import os
import time
import threading
import logging
from datetime import datetime, timedelta
from enum import Enum

from lib.vpnweb import VpnWeb
from lib.vpnconnection import VpnConnection
from lib.vpnstatus import VpnStatus

logger = logging.getLogger(__name__)

class Waiter:

    def __init__(self, td):
        self.td = td
        self.dt = datetime.now()

    def reset(self):
        self.dt = datetime.now()

    def elapse(self):
        self.dt = datetime.now() - self.td

    def isElapsed(self):
        return datetime.now() > (self.dt + self.td)

class JuniperClient:
    """
    Class to sign in/out, run host checker, and connect to a Juniper VPN.
    """

    def __init__(self):
        self.jndir = os.path.expanduser("~/.juniper_networks/")
        self.vpnCon = VpnConnection(self.jndir)
        self.vpnStatus = VpnStatus()
        self.vpnWeb = VpnWeb(self.jndir, self.vpnStatus)

        self.stop = False

        self.connectStatus = ""
        self.connectThread = None
        self.connectState = Enum('connectState', 'Wait SignIn SignOut NetworkWait Connected Connecting ConnectWait ConnectFailed Disconnect')
        self.cmdState = self.connectState.Wait
        self.state = self.connectState.Wait
        self.keepAlive = False
        self.keepAliveStatus = ""

        self.waitNetwork = Waiter(timedelta(seconds=10))
        self.waitConnected = Waiter(timedelta(seconds=5))
        self.waitKeepAlive = Waiter(timedelta(seconds=30))
        self.waitRestart = Waiter(timedelta(seconds=60))

    def startConnectThread(self):
        if self.connectThread is None:
            self.connectThread = threading.Thread(target=self.connectThreadRun)
            self.connectThread.start()

    def stopConnectThread(self):
        self.stop = True
        if not self.connectThread is None:
            self.connectThread.join(2)

    def setConfig(self, host, port, urlnum, realm):
        self.vpnWeb.setConfig(host, port, urlnum, realm)
        self.vpnCon.setHost(host)

    def setKeepAlive(self, keepAlive):
        if keepAlive is True:
            self.keepAlive = True
        else:
            self.keepAlive = False
            self.vpnStatus.setKeepAliveStatus("")

    def signIn(self, username, pin, token):
        self.vpnWeb.setCredentials(username, pin, token)
        self.cmdState = self.connectState.SignIn

    def signOut(self):
        self.cmdState = self.connectState.SignOut

    def getSignInStatus(self):
        return self.vpnStatus.signin

    def disconnect(self):
        self.cmdState = self.connectState.Disconnect

    def connect(self):
        self.cmdState = self.connectState.Connecting

    def updateConnectInfo(self):
        info = self.vpnCon.getConnectionInfo()
        self.vpnStatus.setConnectionInfo(info["host"], info["ip"], info["bytesSent"], info["bytesRecv"], info["duration"])

    def doWait(self):
        if self.cmdState == self.connectState.Connecting:
            self.waitNetwork.elapse()
            self.state = self.connectState.NetworkWait
        elif self.cmdState == self.connectState.Disconnect:
            self.state = self.cmdState
        elif self.cmdState == self.connectState.SignIn:
            self.state = self.cmdState
        elif self.cmdState == self.connectState.SignOut:
            self.state = self.cmdState
        elif self.vpnCon.isDevUp():
            self.state = self.connectState.Connected

    def doSignIn(self):
        # by default, go back to wait state if sign in fails
        # or we are already signed in
        self.cmdState = self.connectState.Wait
        self.state = self.connectState.Wait
        try:
            if self.vpnWeb.checkSignIn():
                self.vpnStatus.setError("Already signed in")
            else:
                self.vpnWeb.signInWithCredentials()
                if self.vpnWeb.checkSignIn():
                    # go straight to connecting since if sign in passed, network is up
                    self.state = self.connectState.Connecting
        except Exception as e:
            self.vpnStatus.setError(e)
            logger.exception(e)

    def doSignOut(self):
        self.state = self.connectState.Disconnect
        self.cmdState = self.connectState.Wait
        try:
            self.vpnWeb.signOut()
            if self.vpnWeb.checkSignIn():
                self.vpnStatus.setError("Sign out failed")
        except Exception as e:
            self.vpnStatus.setError(e)
            logger.exception(e)

    def doNetworkWait(self):
        if self.waitNetwork.isElapsed():
            self.waitNetwork.reset()
            if not self.vpnCon.checkGateway():
                self.vpnStatus.setConnectionStatus("Waiting For Network")
            elif self.vpnWeb.checkSignInAndError() != 0:
                self.vpnStatus.setConnectionStatus("Sign In Check Failed")
                self.state = self.connectState.Wait
                self.cmdState = self.connectState.Wait
            else:
                self.state = self.connectState.Connecting

    def doConnect(self):
        self.vpnStatus.setConnectionStatus("Connecting")
        self.vpnCon.connect(self.vpnWeb.dsid)
        self.waitConnected.reset()
        self.state = self.connectState.ConnectWait

    def doConnectWait(self):
        if self.vpnCon.isDevUp():
            self.vpnStatus.setConnectionStatus("Connected")
            self.waitKeepAlive.reset()
            self.state = self.connectState.Connected
        elif self.waitConnected.isElapsed():
            self.vpnStatus.setConnectionStatus("Failed to Connect")
            self.vpnCon.disconnect()
            self.state = self.connectState.ConnectFailed

    def doConnected(self):
        self.updateConnectInfo()
        if not self.vpnCon.isDevUp():
            self.vpnStatus.setConnectionStatus("Connection Lost")
            self.vpnCon.disconnect()
            self.state = self.connectState.ConnectFailed
        elif self.keepAlive and self.waitKeepAlive.isElapsed():
            self.waitKeepAlive.reset()
            self.vpnStatus.setKeepAliveStatus("Checking Connection")
            # connection is up but may not be passing data, check it
            if not self.vpnCon.checkGateway():
                self.vpnStatus.setConnectionStatus("Network Lost")
                self.vpnStatus.setKeepAliveStatus("Gateway Check Failed")
                self.vpnCon.disconnect()
                self.waitRestart.reset()
                self.state = self.connectState.ConnectFailed
            elif self.vpnWeb.checkSignInAndError() != 0:
                self.vpnStatus.setConnectionStatus("Disconnected by Keep Alive")
                self.vpnStatus.setKeepAliveStatus("Sign In Check Failed")
                self.vpnCon.disconnect()
                self.waitRestart.reset()
                self.state = self.connectState.ConnectFailed
            else:
                self.vpnStatus.setKeepAliveStatus("Checks passed")

        # ignore commanded states for sign in, wait, and connect

    def doConnectFailed(self):
        if self.keepAlive:
            # update keep alive status with "waiting to restart connection"
            if self.waitRestart.isElapsed():
                self.vpnStatus.setKeepAliveStatus("Restarting Connection")
                self.state = self.connectState.NetworkWait
        else:
            # keep alive isn't set so go back to wait state
            self.state = self.connectState.Wait
            self.cmdState = self.connectState.Wait

    def doDisconnect(self):
        self.vpnCon.disconnect()
        self.vpnStatus.setConnectionStatus("Disconnected")
        self.state = self.connectState.Wait
        self.cmdState = self.connectState.Wait

    def connectThreadRun(self):
        self.stop = False
        self.state = self.connectState.Wait
        self.vpnStatus.setConnectionStatus("Disconnected")
        while self.stop is False:
            self.vpnCon.updateDevInfo()

            # if disconnect or signout is commanded in any state, do it
            if self.cmdState == self.connectState.Disconnect:
                self.state = self.connectState.Disconnect
            elif self.cmdState == self.connectState.SignOut:
                self.state = self.connectState.SignOut

            if self.state == self.connectState.Wait:
                self.doWait()
            elif self.state == self.connectState.SignIn:
                self.doSignIn()
            elif self.state == self.connectState.SignOut:
                self.doSignOut()
            elif self.state == self.connectState.NetworkWait:
                self.doNetworkWait()
            elif self.state == self.connectState.Connecting:
                self.doConnect()
            elif self.state == self.connectState.ConnectWait:
                self.doConnectWait()
            elif self.state == self.connectState.Connected:
                self.doConnected()
            elif self.state == self.connectState.ConnectFailed:
                self.doConnectFailed()
            elif self.state == self.connectState.Disconnect:
                self.doDisconnect()
            time.sleep(0.5)
        self.vpnCon.disconnect()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    jc = JuniperClient()
    #jc.checkSignIn()
    #print jc.signInStatus
