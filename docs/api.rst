===
API
===


.. automodule:: skeleton
    :members:


Skeleton
--------

.. autoclass:: skeleton.Skeleton
    :members: run, template_formatter, cmd, configure_parser, src, variables, file_encoding, required_skeletons
    
    .. automethod:: check_variables()
    .. automethod:: get_missing_variables()
    .. automethod:: write(dst_dir, run_dry=False)


Variable Types
--------------

.. autoclass:: skeleton.Var
    :members: display_name, full_description, prompt, do_prompt, validate
    
.. autoclass:: skeleton.Bool
    :members: full_description, prompt, validate
    :inherited-members: display_name, validate
    

Utils
-----

.. autofunction:: skeleton.insert_into_file


Exceptions
----------

.. autoclass:: skeleton.FileNameKeyError
    :members: variable_name, file_path

.. autoclass:: skeleton.TemplateKeyError
    :members: variable_name, file_path
