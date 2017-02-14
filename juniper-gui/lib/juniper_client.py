
import os
import time
import threading
import logging
from enum import Enum
from datetime import datetime, timedelta

from lib.vpnweb import VpnWeb
from lib.vpnconnection import VpnConnection

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


class JuniperClientInterface:
    """ Class that should be inherited from and overridden to get status callbacks """
    def __init__(self):
        pass

    def onSignInStatusUpdated(self, status):
        pass

    def onConnectionInfoUpdated(self, info):
        pass

    def onSslCertChanged(self, newcert, oldcert=None):
        pass

    def onError(self, error):
        pass

class JuniperClient:
    """
    Class to sign in/out, run host checker, and connect to a Juniper VPN.
    """

    def __init__(self, intf=None):
        self.jndir = os.path.expanduser("~/.juniper_networks/")
        self.vpnCon = VpnConnection(self.jndir)
        self.vpnWeb = VpnWeb(self.jndir)

        self.stop = False

        self.connectStatus = ""
        self.connectThread = None
        self.intf = JuniperClientInterface()
        if not intf is None:
            self.intf = intf
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
            self.keepAliveStatus = ""
            self.updateConnectInfo(self.connectStatus, "")

    def signIn(self, username, pin, token):
        self.vpnWeb.setCredentials(username, pin, token)
        self.cmdState = self.connectState.SignIn

    def signOut(self):
        self.cmdState = self.connectState.SignOut

    def getSignInStatus(self):
        return self.vpnWeb.getSignInStatus()

    def disconnect(self):
        self.cmdState = self.connectState.Disconnect

    def connect(self):
        self.cmdState = self.connectState.Connecting

    def updateConnectInfo(self, status, keepAlive=None):
        self.connectStatus = status
        if not keepAlive is None:
            self.keepAliveStatus = keepAlive
        info = self.vpnCon.getConnectionInfo()
        info["status"] = status
        info["keepAlive"] = self.keepAliveStatus
        self.intf.onConnectionInfoUpdated(info)

    def updateSignInStatus(self, status=""):
        sis = self.vpnWeb.getSignInStatus()
        if len(status) > 0:
            sis["status"] = status
        self.intf.onSignInStatusUpdated(sis)

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
                self.intf.onError("Already signed in")
            else:
                self.vpnWeb.signInWithCredentials()
                if self.vpnWeb.checkSignIn():
                    # go straight to connecting since if sign in passed, network is up
                    self.state = self.connectState.Connecting
        except Exception as e:
            self.updateSignInStatus("Sign In Exception")
            self.intf.onError(e)

    def doSignOut(self):
        self.state = self.connectState.Disconnect
        self.cmdState = self.connectState.Wait
        try:
            self.vpnWeb.signOut()
            if self.vpnWeb.checkSignIn():
                self.intf.onError("Sign out failed")
        except Exception as e:
            self.intf.onError(e)
            self.updateSignInStatus("Sign Out Exception")

    def doNetworkWait(self):
        if self.waitNetwork.isElapsed():
            self.waitNetwork.reset()
            if not self.vpnCon.checkGateway():
                self.updateConnectInfo("Waiting On Network")
            elif self.vpnWeb.checkSignInAndError() != 0:
                self.updateConnectInfo("Sign In Check Failed")
                self.state = self.connectState.Wait
                self.cmdState = self.connectState.Wait
            else:
                self.updateConnectInfo("Network Up")
                self.state = self.connectState.Connecting

    def doConnect(self):
        self.updateConnectInfo("Connecting")
        self.vpnCon.connect(self.vpnWeb.dsid)
        self.waitConnected.reset()
        self.state = self.connectState.ConnectWait

    def doConnectWait(self):
        if self.vpnCon.isDevUp():
            self.updateConnectInfo("Connected")
            self.waitKeepAlive.reset()
            self.state = self.connectState.Connected
        elif self.waitConnected.isElapsed():
            self.updateConnectInfo("Failed to Connect")
            self.vpnCon.disconnect()
            self.state = self.connectState.ConnectFailed

    def doConnected(self):
        self.updateConnectInfo(self.connectStatus)
        if not self.vpnCon.isDevUp():
            self.updateConnectInfo("Connection Lost")
            self.vpnCon.disconnect()
            self.state = self.connectState.ConnectFailed
        elif self.keepAlive and self.waitKeepAlive.isElapsed():
            self.waitKeepAlive.reset()
            self.updateConnectInfo(self.connectStatus, "Checking Connection")
            # connection is up but may not be passing data, check it
            if not self.vpnCon.checkGateway():
                self.updateConnectInfo("Network Lost", "Gateway Check Failed")
                self.vpnCon.disconnect()
                self.state = self.connectState.ConnectFailed
            elif self.vpnWeb.checkSignInAndError() != 0:
                self.updateConnectInfo("Disconnected by Keep Alive", "Sign In Check Failed")
                self.vpnCon.disconnect()
                self.state = self.connectState.ConnectFailed
            else:
                self.updateConnectInfo(self.connectStatus, "Checks succeeded")

        # ignore commanded states for sign in, wait, and connect

    def doConnectFailed(self):
        # if keep alive is set, retry connection
        self.waitRestart.reset()
        if self.keepAlive:
            # update keep alive status with "waiting to restart connection"
            if self.waitRestart.isElapsed():
                self.updateConnectInfo(self.connectStatus, "Restarting Connection")
                self.state = self.connectState.NetworkWait
        else:
            # keep alive isn't set so go back to wait state
            self.state = self.connectState.Wait
            self.cmdState = self.connectState.Wait

    def doDisconnect(self):
        self.vpnCon.disconnect()
        self.updateConnectInfo("Disconnected")
        self.state = self.connectState.Wait
        self.cmdState = self.connectState.Wait

    def connectThreadRun(self):
        self.stop = False
        self.state = self.connectState.Wait
        self.vpnWeb.checkSignIn()
        self.updateConnectInfo("Disconnected")
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
    jc.updateConnectInfo('idk')
