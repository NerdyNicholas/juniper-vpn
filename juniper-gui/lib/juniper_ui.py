import sys, traceback, logging
import os
import ConfigParser
import time
from datetime import datetime, timedelta

from PyQt4 import QtGui, QtCore
from PyQt4.QtCore import QObject

from juniper_client import JuniperClient
from util import BackgroundThread

class SystemTrayIcon(QtGui.QSystemTrayIcon):

    def __init__(self, icon, app, parent=None):
        QtGui.QSystemTrayIcon.__init__(self, icon, parent)
        self.menu = QtGui.QMenu(parent)
        self.exitAction = self.menu.addAction("Exit")
        self.exitAction.triggered.connect(QtCore.QCoreApplication.instance().quit)
        self.setContextMenu(self.menu)

class MainWindow(QtGui.QMainWindow):

    connectInfoUpdated = QtCore.pyqtSignal(object)
    signInStatusUpdated = QtCore.pyqtSignal(object)
    errorEncountered = QtCore.pyqtSignal(object)

    def __init__(self, app, res):
        super(MainWindow, self).__init__()
        self.app = app
        self.res = res
        self.buildUi()

        # load the config, update the config tab
        self.configFile = os.path.expanduser("~/.config/junipergui/junipergui.ini")
        self.loadConfig()
        self.updateConfigTab()

        self.bgSignInThread = None
        self.exitOnClose = False

        self.jc = JuniperClient()
        self.jc.statusUpdatedCb = self.onJuniperClientUpdated
        self.setJuniperConfig()

        self.ciUpdated = datetime.fromtimestamp(0)
        self.connectInfoUpdated.connect(self.onConnectionInfoUpdate)
        self.signInStatusUpdated.connect(self.onSignInStatusUpdated)
        self.errorEncountered.connect(self.onErrorEncountered)

        self.updateTimer = QtCore.QTimer()
        self.updateTimer.timeout.connect(self.onUpdateTimer)
        self.updateTimer.start(1000)

        self.jc.startConnectThread()

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
        self.buildSignInForm()
        self.buildSignInStatus()

        self.sitab = QtGui.QVBoxLayout()
        self.sitab.addWidget(self.qtsis['gb'])
        self.sitab.addWidget(self.qtsif['gb'])

    def buildSignInForm(self):
        self.qtsif = {}
        # create widgets for logging in
        self.qtsif['lblUser'] = QtGui.QLabel("Username:")
        self.qtsif['leUser'] = QtGui.QLineEdit()
        self.qtsif['lblPin'] = QtGui.QLabel("Pin:")
        self.qtsif['lePin'] = QtGui.QLineEdit()
        self.qtsif['lePin'].setMaxLength(8)
        self.qtsif['lePin'].setMaximumWidth(75)
        self.qtsif['lePin'].setEchoMode(QtGui.QLineEdit.Password)
        self.qtsif['lblToken'] = QtGui.QLabel("Token:")
        self.qtsif['leToken'] = QtGui.QLineEdit()
        self.qtsif['leToken'].setMaxLength(12)
        self.qtsif['leToken'].setMaximumWidth(75)
        self.qtsif['btnSignIn'] = QtGui.QPushButton("Sign In")
        self.qtsif['btnSignOut'] = QtGui.QPushButton("Sign Out")

        self.qtsif['btnSignIn'].clicked.connect(self.signIn)
        self.qtsif['btnSignOut'].clicked.connect(self.signOut)

        # buttons layout
        self.qtsif['btnsLayout'] = QtGui.QHBoxLayout()
        self.qtsif['btnsLayout'].addWidget(self.qtsif['btnSignIn'])
        self.qtsif['btnsLayout'].addWidget(self.qtsif['btnSignOut'])

        # create layout for sign in widgets
        self.qtsif['layout'] = QtGui.QGridLayout()
        self.qtsif['layout'].addWidget(self.qtsif['lblUser'], 0, 0)
        self.qtsif['layout'].addWidget(self.qtsif['leUser'], 0, 1)
        self.qtsif['layout'].addWidget(self.qtsif['lblPin'], 1, 0)
        self.qtsif['layout'].addWidget(self.qtsif['lePin'], 1, 1)
        self.qtsif['layout'].addWidget(self.qtsif['lblToken'], 2, 0)
        self.qtsif['layout'].addWidget(self.qtsif['leToken'], 2, 1)
        self.qtsif['layout'].addLayout(self.qtsif['btnsLayout'], 3, 0, 1, 2)

        self.qtsif['gb'] = QtGui.QGroupBox('Sign In Credentials')
        self.qtsif['gb'].setLayout(self.qtsif['layout'])

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
        self.trayIcon = QtGui.QIcon(os.path.join(self.res, "networkconnect.gif"))
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

    def setJuniperConfig(self):
        vpnHost = self.config.get('junipergui', 'vpnHost')
        vpnPort = int(self.config.get('junipergui', 'vpnPort'))
        self.jc.setConfig(vpnHost, vpnPort, 'url_15', 'realm')

    def showError(self, title, text):
        w = QtGui.QWidget()
        QtGui.QMessageBox.critical(w, title, text)

    def signIn(self):
        if not self.bgSignInThread is None:
            self.showError("Error Signing In", "Sign in/out already in progress")
            return
        self.bgSignInThread = BackgroundThread(self.signInBg, onFinish=self.onSignInFinished, onError=self.onErrorEncountered)

    def signInBg(self):
        if  not self.jc.checkSignIn():
            self.jc.signIn(self.qtsif['leUser'].text(), self.qtsif['lePin'].text(), self.qtsif['leToken'].text())
            self.connect()
        else:
            self.errorEncountered.emit("You appear to already be signed in, Sign Out before signing in again")

    def onSignInFinished(self):
        self.bgSignInThread = None

    def onErrorEncountered(self, e):
        self.showError( "Error", "An error was encountered:\n%s"  % e)

    def signOut(self):
        if not self.bgSignInThread is None:
            self.showError("Error Signing Out", "Sign in/out already in progress")
            return
        self.bgSignInThread = BackgroundThread(self.signOutBg, onFinish=self.onSignInFinished, onError=self.onErrorEncountered)

    def signOutBg(self):
        self.jc.checkSignIn()
        self.jc.signOut()

    def connect(self):
        if not self.jc.checkForNcui():
            self.showError("Error Connecting", "The ncui wrapper does not exist.")
        try:
            if  not self.jc.checkSignIn():
                self.showError("Error Connecting", "You must sign in before you can connect.")
            else:
                self.jc.connect()
        except Exception as e:
            self.showError("Error Connecting", "An error was encountered when connecting: %s"  % e)
            print e
            traceback.print_exc()

    def disconnect(self):
        self.jc.disconnect()

    def stop(self):
        self.updateTimer.stop()
        self.jc.stopConnectThread()

    def onJuniperClientUpdated(self, connectInfo, signInStatus):
        self.connectInfoUpdated.emit(connectInfo)
        self.signInStatusUpdated.emit(signInStatus)

    def onUpdateTimer(self):
        self.signInStatusUpdated.emit(self.jc.getSignInStatus())

    def onSignInStatusUpdated(self, signInStatus):
        if self.qtsis['lblStatusValue'].text() != signInStatus['status']:
            self.tray.showMessage("Juniper VPN", signInStatus['status'])
        self.qtsis['lblStatusValue'].setText(signInStatus['status'])
        self.qtsis['lblFirstAccessValue'].setText(signInStatus['first'])
        self.qtsis['lblLastAccessValue'].setText(signInStatus['last'])

    def onConnectionInfoUpdate(self, connectInfo):
        if connectInfo.status != self.lblConStatusValue.text():
            self.tray.showMessage("Juniper VPN", connectInfo.status)
        self.lblConHostValue.setText(connectInfo.host)
        self.lblConStatusValue.setText(connectInfo.status)
        self.lblConIpValue.setText(connectInfo.ip)
        self.lblBytesRecvValue.setText(str(connectInfo.bytesRecv))
        self.lblBytesSentValue.setText(str(connectInfo.bytesSent))
        self.lblDurationValue.setText(str(connectInfo.duration).split('.')[0])
        self.lblKeepAliveValue.setText(connectInfo.keepAliveStatus)
