"""
Tests for skeleton core components

"""
import datetime
import unittest

from skeleton.tests.utils import TestCase, TempDir
from skeleton.core import Skeleton, Var, TemplateKeyError, FileNameKeyError, \
    Bool


THIS_YEAR = datetime.datetime.utcnow().year


class WithDefault(Skeleton):
    """Skeleton with variables with default"""
    variables = [Var('foo'), Var('bar', default=2), Var('baz')]


class WithRequirement(Skeleton):
    """Skeleton with other skeleton required"""
    variables = [Var('foo', default=1)]
    required_skeletons = [WithDefault, ]


class Static(Skeleton):
    """Skeleton with only static files:

    - foo.txt
    - bar/baz.txt

    """
    src = 'skeletons/static'


class DynamicContent(Static):
    """Skeleton dynamic content (bar/bax.txt_tmpl)"""
    src = 'skeletons/dynamic-content'
    variables = [
        Var('baz', 'Dummy variable'),
        ]


class DynamicFileName(Static):
    """Skeleton with a dynamic file name (bar/${baz}.txt)"""
    src = 'skeletons/dynamic-file-name'


class Required(Static):
    """Just a ${FileName}.txt file"""
    src = "skeletons/required"
    variables = [Var('file_name') ]


class StaticWithRequirement(Static):
    """Adds the requirment to the Static class"""
    required_skeletons = [Required]


class MissingVariable(DynamicContent):
    """We forgot to declare the variable "baz"
    """
    variables = []


class MissingVariableForFileName(DynamicFileName):
    """We forgot to declare the variable "baz"
    """
    variables = []


class TestSkeleton(TestCase):
    """Tests new implementation of Skeleton"""

    def test_skeleton_mapping(self):
        """Tests Skeleton is a Mapping class"""
        skel = Skeleton(foo=1)
        skel['bar'] = 2
        skel['baz'] = 3
        del skel['baz']

        self.assertTrue('foo' in skel)
        self.assertTrue('bar' in skel)
        self.assertFalse('baz' in skel)

        self.assertEqual(skel['foo'], 1)
        self.assertEqual(skel['bar'], 2)
        self.assertRaises(KeyError, skel.__getitem__, 'baz')

        self.assertEqual(skel.get('foo'), 1)
        self.assertEqual(skel.get('bar'), 2)
        self.assertEqual(skel.get('baz'), None)
        self.assertEqual(skel.get('baz', 3), 3)

        self.assertEqual(dict(skel), dict(foo=1, bar=2, year=THIS_YEAR))
        self.assertEqual(dict(**skel), dict(foo=1, bar=2, year=THIS_YEAR))

    def test_mapping_with_default(self):
        """Tests Skeleton correct map default value"""
        # foo is set, bar has a default, baz is not set and has no default
        skel = WithDefault(foo=1)

        self.assertTrue('foo' in skel)
        self.assertTrue('bar' in skel)
        self.assertFalse('baz' in skel)

        self.assertEqual(skel['foo'], 1)
        self.assertEqual(skel['bar'], 2)
        self.assertRaises(KeyError, skel.__getitem__, 'baz')

        self.assertEqual(skel.get('foo'), 1)
        self.assertEqual(skel.get('bar'), 2)
        self.assertEqual(skel.get('baz'), None)
        self.assertEqual(skel.get('baz', 3), 3)

        self.assertEqual(dict(skel), dict(foo=1, bar=2, year=THIS_YEAR))
        self.assertEqual(dict(**skel), dict(foo=1, bar=2, year=THIS_YEAR))

    def test_requirement_instances(self):
        """Tests skeleton and required skeletons hold the same set_variables
        """
        # For skel, foo is not set but has default set to 1
        skel = WithRequirement()

        # required_skel has foo set to 1 (get it from skel), bar is not set but
        # has a default set to 2; baz is not set and no default
        required_skel = skel.required_skeletons_instances[0]

        self.assertEqual(len(skel.required_skeletons_instances), 1)
        self.assertTrue(isinstance(required_skel, WithDefault))

        self.assertEqual(skel['foo'], 1)
        self.assertEqual(required_skel['foo'], 1)

        self.assertEqual(skel.get('bar'), None)
        self.assertEqual(required_skel['bar'], 2)

        # both skeleton should have baz set to 3
        required_skel['baz'] = 3

        self.assertEqual(skel['baz'], 3)
        self.assertEqual(required_skel['baz'], 3)

    def test_default_variables(self):
        """Tests Skeleton set the default Year variable."""
        skel = Skeleton()
        self.assertTrue('year' in skel)

    def test_check_var_with_default_var(self):
        """Tests Skeleton.check_va() on no set variables with defaults"""
        skel = WithDefault(foo=1, baz=3)
        try:
            skel.check_variables()
        except KeyError:
            self.fail("check_variables() should not raise KayError "
                "if the missing variable has a default.")

    def test_check_var_fails(self):
        """Tests Skeleton.check_var() on exception to raise."""
        skel = WithDefault(foo=1)
        self.assertRaises(KeyError, skel.check_variables)

    def test_get_variables_with_default(self):
        """Tests prompt of variable with default"""
        resps = ['', '1', '', '3']
        self.input_mock.side_effect = lambda x: resps.pop(0)

        skel = WithDefault()

        skel.get_missing_variables()
        self.assertEqual(self.input_mock.call_count, 4)
        self.assertEqual(skel['foo'], '1')
        self.assertEqual(skel['bar'], 2)
        self.assertEqual(skel['baz'], '3')

    def test_write_without_src(self):
        """tests skeleton src pointing to a missing folder"""
        skel = Skeleton()
        with TempDir() as tmp_dir:
            self.assertRaises(AttributeError, skel.write, tmp_dir.path)

    def test_write_missing_variable(self):
        """Tests write raise KeyError if a variable is not set."""
        skel = MissingVariable()
        with TempDir() as tmp_dir:
            try:
                skel.write(tmp_dir.path)
                self.fail("An exception should be raised")
            except (TemplateKeyError,), exc:
                self.assertTrue(exc.file_path.endswith('bar/baz.txt_tmpl'))
                self.assertEqual(exc.variable_name, 'baz')

    def test_write_create_dst_dir(self):
        """tests Skeleton.write() create the missing dst directory"""
        skel = Static()
        with TempDir() as tmp_dir:
            skel.write(tmp_dir.join('missing-dir'))
            self.assertEqual(
                open(tmp_dir.join('missing-dir/foo.txt')).read().strip(),
                'foo'
                )
            self.assertEqual(
                open(tmp_dir.join('missing-dir/bar/baz.txt')).read().strip(),
                'baz'
                )

    def test_write_static_file(self):
        """Tests Skeleton.write() with static file"""
        skel = Static()
        with TempDir() as tmp_dir:
            skel.write(tmp_dir.path)
            self.assertEqual(
                open(tmp_dir.join('foo.txt')).read().strip(),
                'foo'
                )
            self.assertEqual(
                open(tmp_dir.join('bar/baz.txt')).read().strip(),
                'baz'
                )

    def test_write_dynamic_content(self):
        """Tests Skeleton.write() with dynamic content."""
        skel = DynamicContent(baz="<replaced>")
        with TempDir() as tmp_dir:
            skel.write(tmp_dir.path)
            self.assertEqual(
                open(tmp_dir.join('foo.txt')).read().strip(),
                'foo'
                )
            self.assertEqual(
                open(tmp_dir.join('bar/baz.txt')).read().strip(),
                'foo <replaced> bar'
                )

    def test_write_dynamic_file_names(self):
        """Tests Skeleton.write() with dynamic file name"""
        skel = DynamicFileName(baz="replaced-name")
        with TempDir() as tmp_dir:
            skel.write(tmp_dir.path)
            self.assertEqual(
                open(tmp_dir.join('foo.txt')).read().strip(),
                'foo'
                )
            self.assertEqual(
                open(tmp_dir.join('bar/replaced-name.txt')).read().strip(),
                'baz'
                )

    def test_write_file_name_fails(self):
        """Tests Skeleton.write() with dynamic file name fails"""
        skel = MissingVariableForFileName()
        with TempDir() as tmp_dir:
            try:
                skel.write(tmp_dir.path)
                self.fail("An exception should be raised")
            except (FileNameKeyError,), exc:
                self.assertTrue(exc.file_path.endswith('bar/{baz}.txt'))
                self.assertEqual(exc.variable_name, 'baz')

    def test_run_with_var(self):
        """Tests Skeleton.run() with dynamic content and variable prompt."""
        resps = ['<input replacement>']
        self.input_mock.side_effect = lambda x: resps.pop(0)

        skel = DynamicContent()

        with TempDir() as tmp_dir:
            skel.run(tmp_dir.path)

            self.assertEqual(
                open(tmp_dir.join('foo.txt')).read().strip(),
                'foo'
                )
            self.assertEqual(
                open(tmp_dir.join('bar/baz.txt')).read().strip(),
                'foo <input replacement> bar'
                )

    def test_write_required_skel(self):
        """Tests it write the of required """
        skel = StaticWithRequirement(file_name="fooz")
        with TempDir() as tmp_dir:
            skel.write(tmp_dir.path)

            self.assertTrue(tmp_dir.exists('foo.txt'))
            self.assertTrue(tmp_dir.exists('bar/baz.txt'))
            self.assertTrue(tmp_dir.exists('fooz.txt'))

    def test_overwrite_required_skel(self):
        """Tests it write the of required """
        skel = StaticWithRequirement(file_name="foo")
        with TempDir() as tmp_dir:
            skel.write(tmp_dir.path)

            with open(tmp_dir.join('foo.txt')) as foo_file:
                self.assertEqual(foo_file.read().strip(), 'foo')


class TestVar(TestCase):
    """Tests for skeleton.Var"""

    def test_repr(self):
        """Tests Var representation"""
        var = Var('foo', description='dummy var')
        self.assertEqual(repr(var), '<Var foo default=None>')

    def test_full_description(self):
        """Tests Var full description (complete)"""
        var = Var('foo', description='dummy var')
        self.assertEqual(var.full_description, 'Foo (dummy var)')

    def test_basic_full_description(self):
        """Tests Var full description (missing description)"""
        var = Var('foo')
        self.assertEqual(var.full_description, 'Foo')

    def test_pep8_name(self):
        """Tests Var full description (missing description)"""
        var = Var('foo_bar')
        self.assertEqual(var.full_description, 'Foo Bar')

    def test_prompt(self):
        """Tests Var.prompt()"""
        var = Var('foo')
        self.assertEqual(var.prompt, 'Enter Foo: ')

    def test_do_prompt(self):
        """Tests Var.do_prompt()
        """
        resps = ['', 'bar']
        self.input_mock.side_effect = lambda x: resps.pop(0)

        var = Var('foo')
        self.assertEqual(var.do_prompt(), 'bar')
        self.assertEqual(self.input_mock.call_count, 2)

    def test_prompt_with_default(self):
        """Tests Var.prompt with default"""
        var = Var('foo', default='baz')
        self.assertEqual(var.prompt, """Enter Foo ['baz']: """)

    def test_do_prompt_with_default(self):
        """Tests Var.do_prompt() with default"""
        resps = ['']
        self.input_mock.side_effect = lambda x: resps.pop(0)

        var = Var('foo', default='baz')
        self.assertEqual(var.do_prompt(), 'baz')
        self.assertEqual(self.input_mock.call_count, 1)

    def test_prompt_empty_default(self):
        """Tests Var.prompt with empty default"""
        var = Var('foo', default='')
        self.assertEqual(var.prompt, """Enter Foo ['']: """)

    def test_do_prompt_empty_default(self):
        """Tests Var.do_prompt() with empty default"""
        resps = ['']
        self.input_mock.side_effect = lambda x: resps.pop(0)

        var = Var('foo', default='')
        self.assertEqual(var.do_prompt(), '')
        self.assertEqual(self.input_mock.call_count, 1)


class TestBool(TestCase):
    """Tests for skeleton.core.Bool"""

    def test_full_description(self):
        """Tests Bool full description (complete)"""
        var = Bool('foo', description='dummy var')
        self.assertEqual(var.full_description, 'Foo (dummy var - y/N)')

    def test_basic_full_description(self):
        """Tests Bool full description (complete)"""
        var = Bool('foo')
        self.assertEqual(var.full_description, 'Foo (y/N)')

    def test_prompt_true(self):
        """Tests Bool.prompt for True"""
        var = Bool('foo')
        self.assertEqual(var.prompt, 'Enter Foo (y/N): ')

    def test_do_prompt_true(self):
        """Tests Bool.do_prompt() for True"""
        resps = ['', 'y']
        self.input_mock.side_effect = lambda x: resps.pop(0)

        var = Bool('foo')
        self.assertEqual(var.do_prompt(), True)
        self.assertEqual(self.input_mock.call_count, 2)

    def test_do_prompt_false(self):
        """Tests Bool.do_prompt() for False"""
        resps = ['', 'n']
        self.input_mock.side_effect = lambda x: resps.pop(0)

        var = Bool('foo')
        self.assertEqual(var.do_prompt(), False)
        self.assertEqual(self.input_mock.call_count, 2)

    def test_prompt_with_default(self):
        """Tests Bool.prompt with default"""
        var = Bool('foo', default=True)
        self.assertEqual(var.prompt, "Enter Foo (y/N) ['y']: ")

    def test_do_prompt_with_default(self):
        """Tests Bool.do_prompt() with default"""
        resps = ['', ]
        self.input_mock.side_effect = lambda x: resps.pop(0)

        var = Bool('foo', default=False)
        self.assertEqual(var.do_prompt(), False)
        self.assertEqual(self.input_mock.call_count, 1)

    def test_do_prompt_default_overwritten(self):
        """Tests Bool.do_prompt() with default"""
        resps = ['y', ]
        self.input_mock.side_effect = lambda x: resps.pop(0)

        var = Bool('foo', default=False)
        self.assertEqual(var.do_prompt(), True)
        self.assertEqual(self.input_mock.call_count, 1)


class TestDefaultTemplate(unittest.TestCase):
    """Tests for the default template formatter"""

    def test_template_formatter(self):
        """Tests template formatting"""
        skel = Skeleton(bar="substituted")
        self.assertEqual(
            skel.template_formatter("""foo {bar} baz"""),
            """foo substituted baz""")

    def test_formatter_raise_key_error(self):
        """Tests template formatting a variable not set"""
        skel = Skeleton(bar="substituted")
        self.assertRaises(KeyError,
            skel.template_formatter, """foo {bar} {fooz} baz""")

    def test_template_use_default(self):
        """Tests the template uses the default value if the variable is not set
        """
        skel = WithDefault(foo=1, baz=3)
        self.assertEqual(
            skel.template_formatter("""{foo} {bar} {baz}"""),
            """1 2 3""")


def suite():
    """Get all licence releated test"""
    tests = unittest.TestSuite()
    tests.addTest(unittest.TestLoader().loadTestsFromTestCase(TestSkeleton))
    tests.addTest(unittest.TestLoader().loadTestsFromTestCase(TestVar))
    tests.addTest(unittest.TestLoader().loadTestsFromTestCase(TestBool))
    tests.addTest(
        unittest.TestLoader().loadTestsFromTestCase(TestDefaultTemplate))
    return tests

if __name__ == "__main__":
    unittest.main()
