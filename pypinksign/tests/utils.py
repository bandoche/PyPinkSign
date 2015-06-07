"""
Test tools
"""
import unittest
import tempfile
import shutil

from skeleton import Var
import os


class Mock(object):
    """Basic mock object"""

    def __init__(self):
        self.return_value = None
        self.side_effect = None
        self.call_args_list = []

    def __call__(self, *args, **kw):
        self.call_args_list.append((args, kw,))

        if self.side_effect is not None:
            return self.side_effect(*args, **kw)
        elif self.return_value is not None:
            return self.return_value
        else:
            raise Exception("No return value or side effect set.")

    @property
    def call_count(self):
        """
        Return number of time the mock object has been called
        """
        return len(self.call_args_list)

    @property
    def called(self):
        """Check if the mock object has been called"""
        return self.call_count > 0


class TempDir(object):
    """
    Wrapper class around tempfile.mkdtemp compatible with the "with statement"
    """

    def __init__(self):
        self.path = None

    def create(self):
        """
        Create temporary directory.

        set the path attribute to the this directory path

        """
        self.path = tempfile.mkdtemp()
        return self

    def remove(self):
        """
        remove temporary directory.
        """
        shutil.rmtree(self.path)

    def join(self, *args):
        return os.path.join(self.path, *args)

    def exists(self, *args):
        return os.path.exists(self.join(*args))

    __enter__ = create

    def __exit__(self, exc_type, value, traceback):
        self.remove()


class TestCase(unittest.TestCase):
    """
    Basic test case.
    """

    def setUp(self):
        """
        Mock Var._prompt
        """
        super(TestCase, self).setUp()
        self.input_mock = Mock()
        self._input = Var._prompt
        Var._prompt = self.input_mock

    def tearDown(self):
        """
        Reset Var._prompt and remove the temporary directory.
        """
        super(TestCase, self).tearDown()
        Var._prompt = self._input
