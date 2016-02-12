Requirements & Installation
===========================

Requirements
++++++++++++

This is a tool written in Python for Linux environments; currently, only Python 2.7 is supported but there are plans to have it working in version 3 too. Windows is not supported at all.

It is based on two RIPE NCC packages: `RIPE Atlas Sagan <https://github.com/RIPE-NCC/ripe.atlas.sagan>`_ and `RIPE Atlas Cousteau <https://github.com/RIPE-NCC/ripe-atlas-cousteau>`_, both available on GitHub and PyPI. It also has some other dependencies, they are reported in the `setup.py` file and managed by the `pip` installer.

Some libraries need to be compiled and they require a compiler and development libraries for Python.

- On **Debian/Ubuntu** the following system packages need to be installed:

  .. code:: bash

      $ sudo apt-get install python-dev libffi-dev libssl-dev

  Since ``pip`` and ``virtualenv`` are also strongly suggested, you may need to install them too:

  .. code:: bash

      $ sudo apt-get install python-virtualenv python-pip

- On **CentOS**, the following packages are needed:

  .. code:: bash

      $ sudo yum install gcc libffi-devel openssl-devel

      $ # for pip and virtualenv:
      $ sudo yum install epel-release
      $ sudo yum install python-pip python-virtualenv

Installation
++++++++++++

Even if you can manually install it and run it as a system package, ``pip`` installation and ``virtualenv`` use are strongly recommended to ease installation and dependencies management and to have it running within an isolated environment.

More: `pip installation <https://pip.pypa.io/en/stable/installing/>`_, `virtualenv installation <https://virtualenv.pypa.io/en/latest/installation.html>`_.

Setup a virtualenv
------------------

Virtualenv usage is `documented here <https://virtualenv.pypa.io/en/latest/userguide.html>`_, but the following should be enough in most cases:

.. code:: bash

    $ mkdir ripe-atlas-monitor
    $ cd ripe-atlas-monitor
    $ virtualenv venv
    $ source venv/bin/activate

Installation from PyPI
----------------------

Python ``pip`` can install packages both globally (system wide) and on a per-user basis. To avoid conflicts with other packages, the second way is the preferred one. It can be achieved using the ``virtualenv`` tool (the preferred way) or passing the ``--user`` argument to ``pip``, so that the package will be installed within the ``$HOME/.local`` directory.

.. code:: bash

    $ # using virtualenv
    $ pip install ripe-atlas-monitor
    
    $ # in your user's local dir
    $ pip install --user ripe-atlas-monitor

Installation from GitHub
------------------------

If you just want to use the latest code on the ``master`` branch on GitHub, you can install it with

.. code:: bash

    $ pip install git+https://github.com/pierky/ripe-atlas-monitor.git

"Editable" installation
~~~~~~~~~~~~~~~~~~~~~~~

If you want to contribute to the code, you can clone the repository and install it using the ``-e`` argument of ``pip``; you'll have it installed in a local directory where you can edit it and see the results without having to install it every time:

.. code:: bash

    $ pip install -e git+https://github.com/YOUR_USERNAME/ripe-atlas-monitor.git#egg=ripe-atlas-monitor

See also: :doc:`CONTRIBUTING`.

Bash autocomplete
-----------------

To enable bash autocomplete, register the **ripe-atlas-monitor** script and update your shell preferences:

.. code:: bash

    eval "$(register-python-argcomplete ripe-atlas-monitor)"

If you want it to be enabled on every access, you can it to your ``.bashrc`` file.
