"""
Tests the BDS, GPL and LGPL skeleton
"""
import subprocess
import sys
import unittest

from skeleton.examples.basicpackage import BasicPackage, main
from skeleton.examples.licenses import (
    BSD, BSD_THIRD_CLAUSE, GPL, LGPL, NoLicense, LicenseChoice,
    )
from skeleton.examples.mkmodule import BasicModule
from skeleton.tests.utils import TestCase, TempDir


class TestBSD(TestCase):
    """Tests skeleton.example.license.BSD."""

    def test_write_2clause(self):
        """Tests write of a 2-clauses BSD license."""
        skel = BSD(author='Damien Lebrun', organization='')

        with TempDir() as tmp:
            skel.write(tmp.path)

            self.assertEqual(skel['third_clause'], '')
            self.assertTrue(tmp.exists('LICENSE'))

    def test_write_3clause(self):
        """Tests write of a 3-clauses BSD license."""
        skel = BSD(author='Damien Lebrun', organization='Foo inc')

        with TempDir() as tmp:
            skel.write(tmp.path)

            self.assertEqual(
                skel['third_clause'],
                BSD_THIRD_CLAUSE.format(organization='Foo inc')
                )
            self.assertTrue(tmp.exists('LICENSE'))


class TestGPL(TestCase):
    """Tests skeleton.example.license.GPL."""

    def test_write(self):
        """Tests write of a GPL skeleton"""
        skel = GPL(author='Damien Lebrun', project_name='Foo')

        with TempDir() as tmp:
            skel.write(tmp.path)

            self.assertTrue(tmp.exists('LICENSE'))
            self.assertTrue(tmp.exists('COPYING'))


class TestLGPL(TestCase):
    """Tests skeleton.example.license.LGPL."""

    def test_write(self):
        """Tests write of a LGPL skeleton"""
        skel = LGPL(author='Damien Lebrun', project_name='Foo')

        with TempDir() as tmp:
            skel.write(tmp.path)

            self.assertTrue(tmp.exists('LICENSE'))
            self.assertTrue(tmp.exists('COPYING'))
            self.assertTrue(tmp.exists('COPYING.LESSER'))


class TestNoLicense(TestCase):
    """Tests the NoLicense skeleton."""

    def test_write(self):
        """Tests write of a NoLicense skeleton"""
        skel = NoLicense(author='Damien Lebrun')

        with TempDir() as tmp:
            skel.write(tmp.path)

            self.assertTrue(tmp.exists('LICENSE'))


class TestLicenseChoice(TestCase):
    """Tests the LicenseChoice skeleton."""

    def test_licence_skel_default(self):
        """Tests the default license_ske property"""
        skel = LicenseChoice(author='Damien Lebrun', project_name='Foo')

        self.assertTrue(isinstance(skel.license_skel, NoLicense))
        self.assertEqual(skel.license_skel['author'], 'Damien Lebrun')

    def test_bsd_licence_skel(self):
        """Tests for a BSD license_ske property"""
        skel = LicenseChoice(
            author='Damien Lebrun', project_name='Foo', license='BSD'
            )

        self.assertTrue(isinstance(skel.license_skel, BSD))

    def test_gpl_licence_skel(self):
        """Tests for a GPL license_ske property"""
        skel = LicenseChoice(
            author='Damien Lebrun', project_name='Foo', license='GPL'
            )
        self.assertTrue(isinstance(skel.license_skel, GPL))

    def test_lgpl_licence_skel(self):
        """Tests for a LGPL license_ske property"""
        skel = LicenseChoice(
            author='Damien Lebrun', project_name='Foo', license='LGPL'
            )

        self.assertTrue(isinstance(skel.license_skel, LGPL))

    def test_lgpl_run(self):
        """Tests run of a LicenceChoice with license set to "LGPL"
        """
        resps = ['Foo', 'Damien Lebrun', 'dinoboff@gmail.com', 'LGPL', ]
        self.input_mock.side_effect = lambda x: resps.pop(0)

        skel = LicenseChoice()
        with TempDir() as tmp:
            skel.run(tmp.path)

            self.assertTrue(tmp.exists('LICENSE'))
            self.assertTrue(tmp.exists('COPYING'))
            self.assertTrue(tmp.exists('COPYING.LESSER'))

    def test_lgpl_write(self):
        """Tests write of a LicenceChoice with license set to "LGPL"
        """
        skel = LicenseChoice(
            author='Damien Lebrun', project_name='Foo', license='LGPL'
            )
        with TempDir() as tmp:
            skel.write(tmp.path)

            self.assertTrue(tmp.exists('LICENSE'))
            self.assertTrue(tmp.exists('COPYING'))
            self.assertTrue(tmp.exists('COPYING.LESSER'))

    def test_lgpl_write_fails(self):
        """Tests write of a LicenceChoice fails if a key is missing
        """
        skel = LicenseChoice(author='Damien Lebrun', license='LGPL')

        with TempDir() as tmp:
            self.assertRaises(KeyError, skel.write, tmp.path)


class TestBasicModule(TestCase):
    """Tests BasicModule Skeleton
    """

    def test_write(self):
        """Tests BasicModule.write()
        """
        skel = BasicModule(
            module_name='foo',
            author='Damien Lebrun',
            author_email='dinoboff@gmail.com',
            )

        with TempDir() as tmp:
            skel.write(tmp.path)

            self.assertTrue(tmp.exists('README.rst'))
            self.assertTrue(tmp.exists('setup.py'))
            self.assertTrue(tmp.exists('foo.py'))


class TestBasicPackage(TestCase):
    """Tests the BasicPackage Skeleton
    """

    def test_write(self):
        """Tests skeleton.examples.basicpackage.BasicPackage with a single package
        """
        skel = BasicPackage(
            project_name='foo',
            package_name='foo',
            author='Damien Lebrun',
            author_email='dinoboff@gmail.com'
            )

        with TempDir() as tmp:
            skel.write(tmp.path)

            self.assertEqual(skel['ns_packages'], [])
            self.assertEqual(skel['packages'], ['foo'])

            self.assertTrue(tmp.exists('distribute_setup.py'))
            self.assertTrue(tmp.exists('MANIFEST.in'))
            self.assertTrue(tmp.exists('README.rst'))
            self.assertTrue(tmp.exists('LICENSE'))
            self.assertTrue(tmp.exists('setup.py'))
            self.assertTrue(tmp.exists('foo/__init__.py'))

    def test_write_with_bsd(self):
        """Tests skeleton.examples.basicpackage.BasicPackage add BSD license
        """
        skel = BasicPackage(
            project_name='foo',
            package_name='foo',
            author='Damien Lebrun',
            author_email='dinoboff@gmail.com',
            license='BSD'
            )

        with TempDir() as tmp:
            skel.write(tmp.path)
            self.assertTrue(tmp.exists('LICENSE'))

            fragment = """
            Redistributions of source code must retain the above copyright notice
            """.strip()
            with open(tmp.join('LICENSE')) as license_file:
                content = license_file.read()
                self.assertTrue(fragment in content)

    def test_write_namespaces(self):
        """Tests skeleton.examples.basicpackage.BasicPackage with namespaces
        """
        skel = BasicPackage(
            project_name='foo.bar.baz',
            package_name='foo.bar.baz',
            author='Damien Lebrun',
            author_email='dinoboff@gmail.com'
            )

        with TempDir() as tmp:
            skel.write(tmp.path)

            self.assertEqual(set(skel['ns_packages']), set(['foo', 'foo.bar']))
            self.assertEqual(
                set(skel['packages']),
                set(['foo', 'foo.bar', 'foo.bar.baz']))

            self.assertTrue(tmp.exists('distribute_setup.py'))
            self.assertTrue(tmp.exists('MANIFEST.in'))
            self.assertTrue(tmp.exists('README.rst'))
            self.assertTrue(tmp.exists('LICENSE'))
            self.assertTrue(tmp.exists('setup.py'))
            self.assertTrue(tmp.exists('foo/__init__.py'))
            self.assertTrue(tmp.exists('foo/bar/__init__.py'))
            self.assertTrue(tmp.exists('foo/bar/baz/__init__.py'))

    def test_main(self):
        """Tests basicpackage.main()"""
        resps = ['foo', 'foo', 'Damien Lebrun', 'dinoboff@gmail.com', 'BSD', '']
        self.input_mock.side_effect = lambda x: resps.pop(0)

        with TempDir() as tmp:
            main([tmp.path])

            self.assertTrue(tmp.exists('distribute_setup.py'))
            self.assertTrue(tmp.exists('MANIFEST.in'))
            self.assertTrue(tmp.exists('README.rst'))
            self.assertTrue(tmp.exists('foo/__init__.py'))

            setup = tmp.join('setup.py')
            # Test egg_info can be run
            proc = subprocess.Popen(
                [sys.executable, setup, 'egg_info'],
                shell=False,
                stdout=subprocess.PIPE)
            self.assertEqual(proc.wait(), 0)

            # Test classifiers
            proc = subprocess.Popen(
                [sys.executable, setup, '--classifiers'],
                shell=False,
                stdout=subprocess.PIPE)
            self.assertEqual(proc.wait(), 0)
            classifiers = proc.stdout.read().decode().splitlines()
            self.assertTrue(
                "License :: OSI Approved" in classifiers)
            self.assertTrue(
                "License :: OSI Approved :: BSD License" in classifiers)


def suite():
    """Get all licence releated test"""
    tests = unittest.TestSuite()
    tests.addTest(unittest.TestLoader().loadTestsFromTestCase(TestBSD))
    tests.addTest(unittest.TestLoader().loadTestsFromTestCase(TestGPL))
    tests.addTest(unittest.TestLoader().loadTestsFromTestCase(TestLGPL))
    tests.addTest(unittest.TestLoader().loadTestsFromTestCase(TestNoLicense))
    tests.addTest(unittest.TestLoader().loadTestsFromTestCase(TestBasicModule))
    tests.addTest(unittest.TestLoader().loadTestsFromTestCase(TestBasicPackage))
    return tests

if __name__ == "__main__":
    unittest.main()
