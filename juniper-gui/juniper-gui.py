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

    connectInfoUpdated = QtCore.pyqtSignal(object)

    def __init__(self, app):
        super(MainWindow, self).__init__()
        self.app = app
        self.buildUi()

        self.configFile = os.path.expanduser("~/.config/junipergui/junipergui.ini")
        self.loadConfig()
        self.updateConfigTab()

        self.exitOnClose = False

        self.jc = JuniperClient()

        self.ciUpdated = datetime.fromtimestamp(0)
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
        self.buildConfigTab()

        self.tabConnectLayout = QtGui.QVBoxLayout()
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
        fields = [
            ["vpnHost", "Host name of vpn server:", 255, 0],
            ["vpnPort", "Port to vpn server:", 5, 50],
            ["autoLogout", "Time until auto logout (hours):", 5, 50],
            ["keepAlive", "Time in seconds to check VPN connection and reconnect:", 5, 50]
        ]
        self.configUi = {}
        self.configUi['layout'] = QtGui.QGridLayout()
        for row in range(0 , len(fields)):
            self.configUi[fields[row][0]] = {
                'label': QtGui.QLabel(fields[row][1]),
                'edit': QtGui.QLineEdit()}
            self.configUi[fields[row][0]]['edit'].setMaxLength(fields[row][2])
            if fields[row][3] > 0:
                self.configUi[fields[row][0]]['edit'].setMaximumWidth(fields[row][3])
            self.configUi['layout'].addWidget(self.configUi[fields[row][0]]["label"], row * 2, 0)
            self.configUi['layout'].addWidget(self.configUi[fields[row][0]]["edit"], (row * 2) + 1, 0)

        self.configUi['btnSave'] = QtGui.QPushButton("Save")
        self.configUi['btnSave'].clicked.connect(self.saveConfig)

        self.configUi['layout'].addWidget(self.configUi['btnSave'], (row * 2) + 2, 0)
        self.tabConfig = QtGui.QWidget(parent=self)
        self.tabConfig.setLayout(self.configUi['layout'])

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

        defaults = {
            'vpnHost': 'vpn.example.com',
            'vpnPort': '443',
            'keepAlive': '60',
            'autoLogout': '24',
        }
        config = ConfigParser.RawConfigParser(defaults)
        config.read(self.configFile)
        if not config.has_section('junipergui'):
            config.add_section("junipergui")
        self.config = config
    
    def saveConfig(self):
        self.config.set('junipergui', 'vpnHost', self.configUi['vpnHost']['edit'].text())
        self.config.set('junipergui', 'vpnPort', self.configUi['vpnPort']['edit'].text())
        self.config.set('junipergui', 'keepAlive', self.configUi['keepAlive']['edit'].text())
        self.config.set('junipergui', 'autoLogout', self.configUi['autoLogout']['edit'].text())
        with open(self.configFile, 'w') as configFd:
            self.config.write(configFd)

    def updateConfigTab(self):
        self.configUi['vpnHost']['edit'].setText(self.config.get('junipergui', 'vpnHost'))
        self.configUi['vpnPort']['edit'].setText(self.config.get('junipergui', 'vpnPort'))
        self.configUi['keepAlive']['edit'].setText(self.config.get('junipergui', 'keepAlive'))
        self.configUi['autoLogout']['edit'].setText(self.config.get('junipergui', 'autoLogout'))

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
        pass

    def onBrowserLoginInfoUpdated(self):
        pass

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
