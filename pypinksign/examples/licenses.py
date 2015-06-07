"""
Skeletons for BSD, GPL and LGPL licenses.
"""

from skeleton import Skeleton, Var


BSD_THIRD_CLAUSE = """
    - Neither the name of the {organization} nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.
"""


class NoLicense(Skeleton):
    """Had the a license with copyright notice only.

    """
    src = 'licenses/no-license'
    variables = [
        Var('author'),
        ]


class BSD(Skeleton):
    """Adds a 2 or 3 clauses BSD License.

    Requires author and organization variables.

    Sets a ThirdClause variable.

    """

    src = 'licenses/bsd'
    variables = [
        Var('author'),
        Var('organization',
            default='',
            description="required for a 3 clauses-BSD license - "
                "leave it empty for a 2 clauses-BSD license."
            ),
        ]

    def write(self, dst_dir, run_dry=False):
        """Set the ThirdClause if an organization name has been given.

        """
        if self.get('organization'):
            self['third_clause'] = self.template_formatter(BSD_THIRD_CLAUSE)
        else:
            self['third_clause'] = ''
        super(BSD, self).write(dst_dir, run_dry=run_dry)


class GPL(Skeleton):
    """
    Adds a GPL notice and the GPLv3 license.

    Requires Author and ProjectName variables.

    """

    src = 'licenses/gpl'
    variables = [
        Var('author'),
        Var('project_name'),
        ]


class LGPL(GPL):
    """Add a LGPL Notice and the GPLv3 and LGPLv3 licenses

    Requires Author and ProjectName variables.

    """
    src = 'licenses/lgpl'


class LicenseChoice(Skeleton):
    """Let the use pick the licence

    """
    variables = [
        Var('project_name'),
        Var('author'),
        Var('author_email'),
        Var('license', description='BSD/GPL/LGPL/other', default=''),
        ]

    supported_licenses = {
        'BSD' : BSD,
        'GPL' : GPL,
        'LGPL': LGPL
        }
    default_license = NoLicense
    _licence_skel = None

    @property
    def license_skel(self):
        """Return the skeleton for the set License.

        """
        if self._licence_skel is None:
            self._licence_skel = self.supported_licenses.get(
                self.get('license').upper(),
                self.default_license
                )(self)
        return self._licence_skel

    def check_variables(self):
        """Check variables of the license skeleton.

        """
        super(LicenseChoice, self).check_variables()
        self.license_skel.check_variables()

    def get_missing_variables(self):
        """Prompt for the license skeleton variables.

        """
        super(LicenseChoice, self).get_missing_variables()
        self.license_skel.get_missing_variables()

    def write(self, dst, run_dry=False):
        """Apply the license skeleton

        """
        self.license_skel.write(dst, run_dry=run_dry)
