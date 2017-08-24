

import os
import subprocess
import shlex

class SudoCmd:
    gui = 1
    guiTerm = 2
    term = 3

    def __init__(self, cmd, path, func, typ):
        self.cmd = cmd
        self.path = path
        self.func = func
        self.type = typ

    def getFullCmd(self):
        return os.path.join(self.path, self.cmd)

class Sudo:
    """Runs a command using sudo."""

    def __init__(self, cmds, pwd, message="", graphical=False):

        self.cmds = cmds
        self.pwd = pwd
        self.message = message
        self.graphical = graphical

        self.sudoCmds = [
            SudoCmd("gksudo", "", self.gksu, SudoCmd.gui),
            SudoCmd("kdesudo", "", self.kdesu, SudoCmd.gui),
            SudoCmd("gksu", "", self.gksu, SudoCmd.gui),
            SudoCmd("kdesu", "", self.kdesu, SudoCmd.gui),
            SudoCmd("pkexec", "", self.pkexec, SudoCmd.gui),
            SudoCmd("xterm", "", self.xterm, SudoCmd.guiTerm),
            SudoCmd("gnome-terminal", "", self.gnometerm, SudoCmd.guiTerm),
            SudoCmd("xfce-terminal", "", self.xfceterm, SudoCmd.guiTerm),
            SudoCmd("sudo", "", self.sudo, SudoCmd.term),
            SudoCmd("su", "", self.su, SudoCmd.term)
        ]

        self.sudoPaths = (
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin"
        )

        self.sudoCmd = None
        self.sudoTermCmd = None
        self.findSudo()

    def execute(self):
        if self.sudoCmd is None and self.sudoTermCmd is None:
            raise Exception("No sudo command found")
        if self.sudoCmd:
            self.sudoCmd.func()
        else:
            self.sudoTermCmd.func()

    def findSudo(self):
        # loop through possible paths and set path for every sudo command found
        for path in self.sudoPaths:
            for sudocmd in self.sudoCmds:
                fullcmd = os.path.join(path, sudocmd.cmd)
                if os.path.exists(fullcmd):
                    sudocmd.path = path
                    # if no sudo command has been found yet
                    # set the first gui and terminal ones found
                    if self.sudoCmd is None and sudocmd.type != SudoCmd.term:
                        self.sudoCmd = sudocmd
                    elif self.sudoTermCmd is None and sudocmd.type == SudoCmd.term:
                        self.sudoTermCmd = sudocmd

    def gksu(self):
        # --mesage
        cmd = shlex.split("{0} --message \"{1}\" {2}".format(self.sudoCmd.getFullCmd(), self.message, self.cmds))
        subprocess.check_output(cmd)

    def kdesu(self):
        pass

    def pkexec(self):
        cmd = shlex.split("{0} {2}".format(self.sudoCmd.getFullCmd(), self.cmds))
        subprocess.check_output(cmd)

    def xterm(self):
        pass

    def gnometerm(self):
        pass

    def xfceterm(self):
        pass

    def sudo(self):
        pass

    def su(self):
        pass

