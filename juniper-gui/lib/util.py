
import traceback

from PyQt4 import QtCore

class BackgroundThread(QtCore.QThread):
    """
    Executes callback function in qt thread with
    signals for started, finished, and EOFError
    """

    started = QtCore.pyqtSignal()
    finished = QtCore.pyqtSignal()
    errored = QtCore.pyqtSignal(object)

    def __init__(self, bgFunction, onStart=None, onFinish=None, onError=None):
        QtCore.QThread.__init__(self)
        self.bgFunction = bgFunction
        if not onStart is None:
            self.started.connect(onStart)
        if not onFinish is None:
            self.finished.connect(onFinish)
        if not onError is None:
            self.errored.connect(onError)
        self.start()

    def run(self):
        self.started.emit()
        try:
            self.bgFunction()
        except Exception as e:
            print e
            traceback.print_exc()
            self.errored.emit(e)
        finally:
            self.finished.emit()

