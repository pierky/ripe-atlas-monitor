How to contribute
=================

Here a brief guide to contributing to this tool:

- fork it on GitHub and create your own repository;

- install it using the "editable" installation or clone it locally on your machine (`virtualenv <https://virtualenv.pypa.io/en/latest/installation.html>`_ usage is strongly suggested);

  .. code:: bash

      $ # pip "editable" installation
      $ pip install -e git+https://github.com/YOUR_USERNAME/ripe-atlas-monitor.git
      
      $ # manual cloning from GitHub (you have to care about dependencies)
      $ git clone https://github.com/YOUR_USERNAME/ripe-atlas-monitor.git
      $ export PYTHONPATH="/path/to/your/ripe-atlas-monitor"

- run the tests in order to be sure that everything is fine;

  .. code:: bash

      $ nosetests -vs

- finally, start making your changes and, possibly, add test units and docs to make the merging process easier.

Once you have done, please run tests again:

.. code:: bash

    $ tox

If everything is fine, push to your fork and `create a pull request <https://help.github.com/articles/using-pull-requests/>`_.
