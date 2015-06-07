"""
Skeleton to create a basic package and the virtualenwrapper.project extension
to add it a template.
"""

from __future__ import with_statement

import logging
import os

from skeleton import Skeleton, Var
from skeleton.utils import get_loggger, insert_into_file
from skeleton.examples.licenses import LicenseChoice


_LOG = get_loggger(__name__)

NS_HEADER = """
__import__('pkg_resources').declare_namespace(__name__)
"""


class BasicPackage(Skeleton):
    """Create a new package package (with namespace support) with the setup.py,
    README.rst and MANIFEST.in files already setup.

    Require the following variables:

    - project_name;
    - package_name;
    - author;
    - and author_email.

    Todo: Allow to set a global defaults for author and author_email.
    Todo: Better README.rst content like Having a basic Installation and
    requirement section.
    Todo: Setup a test package and the distribute use_2to3 option.
    """

    src = 'basic-package'
    variables = [
        Var('project_name'),
        Var('package_name'),
        Var('author'),
        Var('author_email'),
        ]
    required_skeletons = [
        LicenseChoice,
        ]
    licence_classifiers = {
            'BSD': 'License :: OSI Approved :: BSD License',
            'GPL': ('License :: OSI Approved :: '
                        'GNU General Public License (GPL)'),
            'LGPL': ('License :: OSI Approved :: '
                        'GNU Library or Lesser General Public License (LGPL)'),
        }

    def write(self, dst_dir, run_dry=False):
        """Create package(s) dynamically.

        Overwrite the write method to add the NSPackages and Packages entry
        before skeleton write, and create the list of package they hold after
        the skeleton write.

        """
        self._set_packages_and_namespaces()
        super(BasicPackage, self).write(dst_dir, run_dry=run_dry)
        self._create_packages(dst_dir)
        self._add_classifier(dst_dir)

    def _set_packages_and_namespaces(self):
        """
        Create a list of package and namespaces suitable for setuptools.
        """
        self['ns_packages'] = []
        self['packages'] = [self['package_name']]

        # Add parent package to the list of package and namespaces
        current_ns = []
        package_parts = self['package_name'].split('.')
        for part in package_parts[:-1]:
            current_ns.append(part)
            parent_package = '.'.join(current_ns)
            self['ns_packages'].append(parent_package)
            self['packages'].append(parent_package)

    def _create_packages(self, dst_dir):
        """
        Create a packages listed in self['Packages']
        """
        packages = self.get('packages', [])
        packages.sort()
        for package in packages:
            init_body = ''
            if package in self.get('ns_packages', []):
                init_body = NS_HEADER
            self._create_package(dst_dir, package, init_body)

    def _create_package(self, dst_dir, package, init_body=''):
        """Create a package - directory and __init__.py file.

        The parent package should already exist.

        """
        package_part = package.split('.')
        path = os.path.join(dst_dir, *package_part)
        _LOG.info("Creating package %s" % package)
        if self.run_dry:
            return
        os.mkdir(path)
        with open(os.path.join(path, '__init__.py'), 'w') as init_file:
            init_file.write(init_body)

    def _add_classifier(self, dst_dir):
        """Add license classifiers

        """
        setup = os.path.join(dst_dir, 'setup.py')
        license_name = self.get('license', '').upper()
        if license_name not in self.licence_classifiers:
            return
        classifiers = [
            "License :: OSI Approved",
            self.licence_classifiers[license_name],
            ]

        insert_into_file(
            setup,
            "Classifiers",
            '\n'.join(['%r,' % cla for cla in classifiers])
            )


def virtualenv_warpper_hook(*args, **kw):
    """
    Create a new package package (with namespace support)
    with the setup.py, README.rst and MANIFEST.in files already setup.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s - %(message)s"
        )
    BasicPackage().run('src/')


def main(argv=None):
    """Bootstrap BasicPackage."""
    BasicPackage.cmd(argv)

if __name__ == '__main__':
    main()
