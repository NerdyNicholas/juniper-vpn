import sys
from PyQt4 import QtGui, QtCore
from PyQt4.QtCore import QObject

from juniper_client import JuniperClient

import os
import sqlite3
import ConfigParser
import time
from datetime import datetime, timedelta

import threading
import Queue

class SystemTrayIcon(QtGui.QSystemTrayIcon):

    def __init__(self, icon, app, parent=None):
        QtGui.QSystemTrayIcon.__init__(self, icon, parent)
        self.menu = QtGui.QMenu(parent)
        self.exitAction = self.menu.addAction("Exit")
        self.exitAction.triggered.connect(QtCore.QCoreApplication.instance().quit)
        self.setContextMenu(self.menu)


#class ConfigDialog(QtGui.

class BrowserLoginInfo():
    '''Reads cookies from firefox to get DSID value and determine if a user is logged in'''

    loginStateMap = [
        [0, 1, 2, 3],
        ["Logged In", "Not Logged In", "Logged Out", "Automatically Logged Out"]
    ]

    def __init__(self, profileIni = None, profileName = None, cookiesDb = None, loginDur = 3600 * 24):
        self.profileIni = profileIni
        self.profileName = profileName
        self.cookiesDb = cookiesDb
        self.loginDur = loginDur

        self.firstAccessDt = datetime.fromtimestamp(0)
        self.DSFirstAccess = None
        self.DSID = None

    def loadProfileInfo(self):
        self.ffUserDir = os.path.expanduser("~/.mozilla/firefox/")
        self.cookiesDb = os.path.join(self.getProfilePath(self.ffUserDir + "profiles.ini", self.profileName ),  "cookies.sqlite")
        print self.cookiesDb

    def getProfilePath(self, profilesIniPath, profileName = None):
        useDefault = True
        if not profileName is None:
            useDefault = False
        try:
            profiles = ConfigParser.ConfigParser()
            profiles.read(profilesIniPath)
            for section in profiles.sections():
                if not profiles.has_option(section, "Path"):
                    continue
                if useDefault and profiles.has_option(section, "Default"):
                    if profiles.get(section, "Default") == "1":
                        return os.path.join(os.path.dirname(profilesIniPath), profiles.get(section, "Path"))
                elif profiles.has_option(section, "Name") and profiles.get(section, "Name") == profileName:
                    return os.path.join(os.path.dirname(profilesIniPath), profiles.get(section, "Path"))
        except Exception as e:
            raise Exception("Failed to load browser profile, error = %s", e)
            print e

        return ""

    def loadLoginInfo(self):
        if not os.path.exists(self.cookiesDb):
            return
        con = sqlite3.connect(self.cookiesDb)
        cur = con.cursor()
        cur.execute("SELECT value FROM moz_cookies where name='DSFirstAccess'")
        res = cur.fetchone()
        if not res is None:
            self.DSFirstAccess = res[0]
            self.setFirstAccess(self.DSFirstAccess)
        else:
            self.DSFirstAccess = None
            self.setFirstAccess("0")
        cur.execute("SELECT value FROM moz_cookies where name='DSID'")
        res = cur.fetchone()
        if not res is None:
            self.DSID = res[0]
        else:
            self.DSID = None
        con.close()

    def setFirstAccess(self, DSFirstAccess):
        firstAccessInt = int(DSFirstAccess)
        dt = datetime.fromtimestamp(firstAccessInt)
        self.firstAccessDt = dt

    def getTimeUntilLogout(self):
        logoutDt = self.firstAccessDt + timedelta(seconds=self.loginDur)
        if logoutDt > datetime.now():
            return logoutDt - datetime.now()
        return timedelta()

    def getLoginStatus(self):
        if self.DSID is None or self.DSFirstAccess is None:
            return 1 # not logged in or couldn't read browser info
        if self.firstAccessDt == datetime.fromtimestamp(0):
            return 2 # logged out
        if self.getTimeUntilLogout() == timedelta():
            return 3 # auto logged out
        if self.getTimeUntilLogout() > timedelta():
            return 0 # logged in

    def getLoginStatusString(self):
        status = self.getLoginStatus()
        try:
            index = self.loginStateMap[0].index(status)
            return self.loginStateMap[1][index]
        except:
            return "Unknown"

class UpdateThread(QtCore.QThread):
    browserInfoUpdated = QtCore.pyqtSignal()

    def __init__(self):
        QtCore.QThread.__init__(self)
        self.stop = False

    def stop(self):
        self.stop = True

    def run(self):
        biupdated = datetime.now()
        while not self.stop:
            time.sleep(1)


class MainWindow(QtGui.QMainWindow):

    browserInfoUpdated = QtCore.pyqtSignal()
    connectInfoUpdated = QtCore.pyqtSignal(object)

    def __init__(self, app):
        super(MainWindow, self).__init__()
        self.app = app
        self.buildUi()

        self.configFile = os.path.expanduser("~/.config/junipergui/junipergui.ini")

        self.exitOnClose = False

        self.jc = JuniperClient()
        self.bi = BrowserLoginInfo('')

        self.biUpdated = datetime.fromtimestamp(0)
        self.ciUpdated = datetime.fromtimestamp(0)

        self.browserInfoUpdated.connect(self.onBrowserLoginInfoUpdated)
        self.connectInfoUpdated.connect(self.onConnectionInfoUpdate)

        self.updateTimer = QtCore.QTimer()
        self.updateTimer.timeout.connect(self.onUpdateTimer)
        self.updateTimer.start(1000)

        self.connectInfoThread = threading.Thread(target = self.connectInfoThreadRun)
        self.connectInfoThread.start()

    def buildUi(self):
        # create tabs
        self.tabs = QtGui.QTabWidget()
        self.tabSignIn = QtGui.QWidget()
        self.tabConnect = QtGui.QWidget()
        self.tabLog = QtGui.QWidget()

        self.buildSignInTab()
        self.buildConnectionInfo()
        #self.buildBrowserInfo()
        self.buildConfigTab()

        self.tabConnectLayout = QtGui.QVBoxLayout()
        #self.tabConnectLayout.addWidget(self.bgBrowserLogin)
        self.tabConnectLayout.addWidget(self.gbConnectInfo)
        self.tabConnect.setLayout(self.tabConnectLayout)

        self.tabSignIn.setLayout(self.sitab)

        self.tabs.addTab(self.tabSignIn, "Sign In")
        self.tabs.addTab(self.tabConnect, "Connection")
        self.tabs.addTab(self.tabConfig, "Config")
        self.tabs.addTab(self.tabLog, "Log")
        self.setCentralWidget(self.tabs)

        self.loadTrayIcon()

        self.setGeometry(300, 300, 300, 250)
        self.setWindowTitle("Juniper VPN GUI")
        self.show()

        self.btnConnect.clicked.connect(self.connect)
        self.btnDisconnect.clicked.connect(self.disconnect)

    def buildSignInTab(self):
        self.sitab = {};

        self.buildSignInForm()
        self.buildSignInStatus()

        self.sitab = QtGui.QVBoxLayout()
        self.sitab.addWidget(self.qtsis['gb'])
        self.sitab.addLayout(self.tabSignInLayout)

    def buildSignInForm(self):
        # create widgets for logging in
        self.lblUser = QtGui.QLabel()
        self.lblUser.setText("Username:")
        self.leUser = QtGui.QLineEdit()
        self.lblPin = QtGui.QLabel()
        self.lblPin.setText("Pin:")
        self.lePin = QtGui.QLineEdit()
        self.lePin.setMaxLength(8)
        self.lePin.setEchoMode(QtGui.QLineEdit.Password)
        self.lblToken = QtGui.QLabel()
        self.lblToken.setText("Token:")
        self.leToken = QtGui.QLineEdit()
        self.btnSignIn = QtGui.QPushButton("Sign In")
        self.btnSignOut = QtGui.QPushButton("Sign Out")

        self.btnSignIn.clicked.connect(self.signIn)
        #self.btnSignOut.clicked.connect(self.signOut)

        # buttons layout
        self.btnsSignIn = QtGui.QHBoxLayout()
        self.btnsSignIn.addWidget(self.btnSignIn)
        self.btnsSignIn.addWidget(self.btnSignOut)

        # create layout for sign in widgets
        self.tabSignInLayout = QtGui.QGridLayout()
        self.tabSignInLayout.addWidget(self.lblUser, 0, 0)
        self.tabSignInLayout.addWidget(self.leUser, 0, 1)
        self.tabSignInLayout.addWidget(self.lblPin, 1, 0)
        self.tabSignInLayout.addWidget(self.lePin, 1, 1)
        self.tabSignInLayout.addWidget(self.lblToken, 2, 0)
        self.tabSignInLayout.addWidget(self.leToken, 2, 1)
        self.tabSignInLayout.addLayout(self.btnsSignIn, 3, 0, 1, 2)

    def buildSignInStatus(self):
        self.qtsis = {}
        self.qtsis['lblStatus'] = QtGui.QLabel('Status:')
        self.qtsis['lblStatusValue'] = QtGui.QLabel()
        self.qtsis['lblFirstAccess'] = QtGui.QLabel('Sign In Date Time:')
        self.qtsis['lblFirstAccessValue'] = QtGui.QLabel()
        self.qtsis['lblLastAccess'] = QtGui.QLabel('Last Access:')
        self.qtsis['lblLastAccessValue'] = QtGui.QLabel()
        self.qtsis['lblTimeLeft'] = QtGui.QLabel('Time Until Auto Sign Out:')
        self.qtsis['lblTimeLeftValue'] = QtGui.QLabel()

        self.qtsis['layout'] = QtGui.QGridLayout()
        self.qtsis['layout'].addWidget(self.qtsis['lblStatus'], 0, 0)
        self.qtsis['layout'].addWidget(self.qtsis['lblStatusValue'], 0, 1)
        self.qtsis['layout'].addWidget(self.qtsis['lblFirstAccess'], 1, 0)
        self.qtsis['layout'].addWidget(self.qtsis['lblFirstAccessValue'], 1, 1)
        self.qtsis['layout'].addWidget(self.qtsis['lblLastAccess'], 2, 0)
        self.qtsis['layout'].addWidget(self.qtsis['lblLastAccessValue'], 2, 1)
        self.qtsis['layout'].addWidget(self.qtsis['lblTimeLeft'], 3, 0)
        self.qtsis['layout'].addWidget(self.qtsis['lblTimeLeftValue'], 3, 1)

        self.qtsis['gb'] = QtGui.QGroupBox('Sign In Status')
        self.qtsis['gb'].setLayout(self.qtsis['layout'])

    def buildBrowserInfo(self):
        # create label widgets to show login info from cookies
        self.bgBrowserLogin = QtGui.QGroupBox("Browser Login Status")
        self.lblBrowserStatus = QtGui.QLabel("Status:")
        self.lblBrowserStatusValue = QtGui.QLabel()
        self.lblBrowserLogin = QtGui.QLabel("Login Date Time:")
        self.lblBrowserLoginValue = QtGui.QLabel()
        self.lblBrowserLogout = QtGui.QLabel("Time Until Auto Logout:")
        self.lblBrowserLogoutValue = QtGui.QLabel()

        # create layout for labels
        self.browserLoginLayout = QtGui.QGridLayout()
        self.browserLoginLayout.addWidget(self.lblBrowserStatus, 0, 0)
        self.browserLoginLayout.addWidget(self.lblBrowserStatusValue, 0, 1)
        self.browserLoginLayout.addWidget(self.lblBrowserLogin, 1, 0)
        self.browserLoginLayout.addWidget(self.lblBrowserLoginValue, 1, 1)
        self.browserLoginLayout.addWidget(self.lblBrowserLogout, 2, 0)
        self.browserLoginLayout.addWidget(self.lblBrowserLogoutValue, 2, 1)

        self.bgBrowserLogin.setLayout(self.browserLoginLayout)

    def buildConnectionInfo(self):
        # create widgets
        self.lblConHost = QtGui.QLabel("Host:")
        self.lblConHostValue = QtGui.QLabel()
        self.lblConStatus = QtGui.QLabel("Status:")
        self.lblConStatusValue = QtGui.QLabel()
        self.lblConIp = QtGui.QLabel("IP:")
        self.lblConIpValue = QtGui.QLabel()
        self.lblBytesRecv = QtGui.QLabel("Bytes Received:")
        self.lblBytesRecvValue = QtGui.QLabel()
        self.lblBytesSent = QtGui.QLabel("Bytes Sent:")
        self.lblBytesSentValue = QtGui.QLabel()
        self.lblDuration = QtGui.QLabel("Duration:")
        self.lblDurationValue = QtGui.QLabel()
        self.lblKeepAlive = QtGui.QLabel("Keep Alive Status:")
        self.lblKeepAliveValue = QtGui.QLabel()

        self.btnConnect = QtGui.QPushButton("Connect")
        self.btnDisconnect = QtGui.QPushButton("Disconnect")

        # connection info layout
        self.connectInfoLayout = QtGui.QGridLayout()
        self.connectInfoLayout.addWidget(self.lblConHost, 0, 0)
        self.connectInfoLayout.addWidget(self.lblConHostValue, 0, 1)
        self.connectInfoLayout.addWidget(self.lblConStatus, 1, 0)
        self.connectInfoLayout.addWidget(self.lblConStatusValue, 1, 1)
        self.connectInfoLayout.addWidget(self.lblConIp, 2, 0)
        self.connectInfoLayout.addWidget(self.lblConIpValue, 2, 1)
        self.connectInfoLayout.addWidget(self.lblBytesSent, 3, 0)
        self.connectInfoLayout.addWidget(self.lblBytesSentValue, 3, 1)
        self.connectInfoLayout.addWidget(self.lblBytesRecv, 4, 0)
        self.connectInfoLayout.addWidget(self.lblBytesRecvValue, 4, 1)
        self.connectInfoLayout.addWidget(self.lblDuration, 5, 0)
        self.connectInfoLayout.addWidget(self.lblDurationValue, 5, 1)
        self.connectInfoLayout.addWidget(self.lblKeepAlive, 6, 0)
        self.connectInfoLayout.addWidget(self.lblKeepAliveValue, 6, 1)

        # buttons layout
        self.btnsLayout = QtGui.QHBoxLayout()
        self.btnsLayout.addWidget(self.btnConnect)
        self.btnsLayout.addWidget(self.btnDisconnect)

        self.connectInfoLayout.addLayout(self.btnsLayout, 7, 0, 1, 2)

        self.gbConnectInfo = QtGui.QGroupBox("Connection Info")
        self.gbConnectInfo.setLayout(self.connectInfoLayout)

    def buildConfigTab(self):
        self.configUiProperties = [
            ["cookiesDb", "Path to firefox cookies database:"],
            ["timeLogout", "Time until auto logout (hours):"],
            ["vpnHost", "Host name of vpn server:"],
            ["vpnPort", "Port to vpn server:"],
            ["sslCert", "Path and file name of SSL cert:"],
            ["keepAlive", "Time in seconds to check VPN connection and reconnect:"]
        ]
        self.configUi = {}
        self.layConfig = QtGui.QGridLayout()
        for row in range(0, len(self.configUiProperties)  - 1):
            name = self.configUiProperties[row][0]
            label = self.configUiProperties[row][1]
            self.configUi[name] = {}
            self.configUi[name]["label"] = QtGui.QLabel(label)
            self.configUi[name]["edit"] = QtGui.QLineEdit()
            self.layConfig.addWidget(self.configUi[name]["label"], row, 0)
            self.layConfig.addWidget(self.configUi[name]["edit"], row, 1)
        self.btnSaveConfig = QtGui.QPushButton("Save")
        self.layConfig.addWidget(self.btnSaveConfig, row + 1, 0)
        self.tabConfig = QtGui.QWidget(parent=self)
        self.tabConfig.setLayout(self.layConfig)

    def loadTrayIcon(self):
        #self.trayIcon = QtGui.QIcon(self.style().standardPixmap(QtGui.QStyle.SP_ComputerIcon))
        self.trayIcon = QtGui.QIcon("networkconnect.gif")
        self.tray = QtGui.QSystemTrayIcon(self.trayIcon)
        self.trayMenu = QtGui.QMenu()
        self.trayExitAction = self.trayMenu.addAction("Exit")
        self.trayConnectAction = self.trayMenu.addAction("Connect")
        self.trayDisconnectAction = self.trayMenu.addAction("Disconnect")
        #self.traySignoutAction = self.trayMenu.addAction("Sign out")
        self.trayShowAction = self.trayMenu.addAction("Show UI")

        self.trayConnectAction.triggered.connect(self.connect)
        self.trayDisconnectAction.triggered.connect(self.disconnect)
        #self.traySignoutAction.triggered.connect(self.signout)
        self.trayExitAction.triggered.connect(self.exitAction)
        self.trayShowAction.triggered.connect(lambda: (self.activateWindow(), self.show(), self.raise_()))

        self.tray.activated.connect(self.trayIconActivated)
        self.tray.setContextMenu(self.trayMenu)
        self.tray.show()

    def exitAction(self):
        self.jc.disconnect()
        self.jc.stopConnectThread()
        self.stop()
        QtGui.QApplication.quit()

    def trayIconActivated(self, reason):
        if reason == QtGui.QSystemTrayIcon.Context:
            self.tray.contextMenu().show()
        elif reason == QtGui.QSystemTrayIcon.Trigger:
            self.show()
            self.raise_()

    def closeEvent(self, event):
        if self.exitOnClose:
            self.trayIcon.hide()
            del self.trayIcon
            event.accept()
        else:
            self.hide()
            event.setAccepted(True)
            event.ignore()

    def loadConfig(self):
        if not os.path.exists(os.path.dirname(self.configFile)):
            os.mkdir(os.path.dirname(self.configFile), mode=0755)
        if not os.path.exists(self.configFile):
            config = ConfigParser.RawConfigParser()
            config.add_section("junipergui")
            config.set(self.section, "cookiesDb", "")
            config.set(self.section, "timeLogout", "12")
            config.set(self.section, "vpnHost", "vpn.example.com")
            config.set(self.section, "vpnPort", "443")
            config.set(self.section, "sslCert", os.path.join(os.path.dirname(self.configFile), "ssl.crt"))
            config.set(self.section, "keepAlive", "30")
            with open(self.configFile, 'wb') as configFd:
                config.write(configFd)
            self.config = config

    def updateBrowserLoginInfo(self):
        self.bi.loadProfileInfo()
        self.bi.loadLoginInfo()

    def signIn(self):
        pass

    def connect(self):
        w = QtGui.QWidget()
        
        if not self.jc.checkForNcui():
            QtGui.QMessageBox.critical(w, "Error Connecting", "The ncui binary does not exist at %s. It must be created with the command: %s")
        try:
            if self.bi.getLoginStatus() != 0:
                QtGui.QMessageBox.critical(w, "Error Connecting", "You must login to the vpn website using firefox before you can connect.")
            else:
                self.jc.connect(self.bi.DSID)
        except Exception as e:
            QtGui.QMessageBox.critical(w, "Error Connecting", "An error was encountered when connecting: %s"  % e)

    def disconnect(self):
        self.jc.disconnect()

    def signout(self):
        pass

    def stop(self):
        self.stopConnectInfoThread = True
        self.updateTimer.stop()
        self.jc.stopConnectThread()

    def connectInfoThreadRun(self):
        self.stopConnectInfoThread = False
        while not self.stopConnectInfoThread:
            try:
                ci = self.jc.queueCi.get(timeout=1)
                self.connectInfoUpdated.emit(ci)
            except Queue.Empty:
                pass

    def onUpdateTimer(self):
        # reload browser log info every minute so that we
        # don't hammer on the cookies DB while FF uses it
        if (self.biUpdated + timedelta(seconds=60)) < datetime.now():
            self.biUpdated = datetime.now()
            self.bi.loadProfileInfo()
            self.bi.loadLoginInfo()
        # update the browser info every time so that the
        # logout time keeps counting down
        self.browserInfoUpdated.emit()

    def onBrowserLoginInfoUpdated(self):
        loginStatus = self.bi.getLoginStatus()
        loginString = self.bi.getLoginStatusString()
        self.lblBrowserStatusValue.setText(loginString)
        if loginStatus == 0:
            self.lblBrowserLoginValue.setText(self.bi.firstAccessDt.isoformat())
            lodt = self.bi.getTimeUntilLogout()
            # remove microseconds from log out time
            logoutstr = str(lodt).split(".")[0]
            self.lblBrowserLogoutValue.setText(logoutstr)
        else:
            self.lblBrowserLoginValue.setText("")
            self.lblBrowserLogoutValue.setText("")

    def onConnectionInfoUpdate(self, connectInfo):
        if connectInfo.status != self.lblConStatusValue.text():
            self.tray.showMessage("Juniper VPN", connectInfo.status)
        self.lblConHostValue.setText(connectInfo.host)
        self.lblConStatusValue.setText(connectInfo.status)
        self.lblConIpValue.setText(connectInfo.ip)
        self.lblBytesRecvValue.setText(str(connectInfo.bytesRecv))
        self.lblBytesSentValue.setText(str(connectInfo.bytesSent))
        self.lblDurationValue.setText(str(connectInfo.duration))
        self.lblKeepAliveValue.setText(connectInfo.keepAliveStatus)

def main():
    #QtGui.QApplication.setStyle("plastique")
    app = QtGui.QApplication(sys.argv)
    mw = MainWindow(app)
    ret = app.exec_()
    app.deleteLater()
    sys.exit(ret)

if __name__ == '__main__':
    main()
