QuickStart
==========

Step 1: install dependencies
----------------------------

Some libraries **ripe-atlas-monitor** depends on need to be compiled and require a compiler and Python's dev libraries:

.. code:: bash

    $ # on Debian/Ubuntu:
    $ sudo apt-get install python-dev libffi-dev libssl-dev

    $ # on CentOS:
    $ sudo yum install gcc libffi-devel openssl-devel

Strongly suggested: install ``pip`` and setup a virtualenv:

.. code:: bash

    $ # on Debian/Ubuntu:
    $ sudo apt-get install python-virtualenv

    $ # on CentOS:
    $ sudo yum install epel-release
    $ sudo yum install python-pip python-virtualenv 

    $ # setup a virtualenv
    $ mkdir ripe-atlas-monitor
    $ cd ripe-atlas-monitor
    $ virtualenv venv
    $ source venv/bin/activate

More: ``virtualenv`` `installation <https://virtualenv.pypa.io/en/latest/installation.html>`_ and `usage <https://virtualenv.pypa.io/en/latest/userguide.html>`_.

Step 2: install ripe-atlas-monitor
----------------------------------

Install latest **ripe-atlas-monitor** version from PyPI:

.. code:: bash

    $ pip install ripe-atlas-monitor

    $ # to enable bash autocomplete:
    $ eval "$(register-python-argcomplete ripe-atlas-monitor)"

More: :doc:`installation options <INSTALL>`.

Step 3: global configuration
----------------------------

Create the ``var`` directory and let the config file to be inizialized; set (at least) the ``var`` parameter:

.. code:: bash

    $ # directory where ripe-atlas-monitor can write a bunch of data
    $ mkdir var
    $ ripe-atlas-monitor init-config

.. code:: yaml

    var: /path/to/ripe-atlas-monitor/var

More: :doc:`global configuration options <CONFIG>`.

Step 4: create a new monitor and customize its configuration
------------------------------------------------------------

The ``analyze`` command can help you defining your rules by giving an overview of the results for a specific measurement, as elaborated by **ripe-atlas-monitor**:

.. code:: bash

    $ ripe-atlas-monitor analyze --measurement-id 1234567890

More: :doc:`Results analysis <COMMANDS>`.

Once you have a clear idea how your rules should look like, create and edit a new monitor:

.. code:: bash

    $ ripe-atlas-monitor init-monitor -m MonitorName

More: :doc:`how monitors work <MONITORS>` and :doc:`syntax <SYNTAX>`.

Alternatively, you can take a look at the sample monitors provided within the `examples <https://github.com/pierky/ripe-atlas-monitor/tree/master/examples>`_ directory.

Step 5: run the brand new monitor
---------------------------------

.. code:: bash

    $ ripe-atlas-monitor run -m MonitorName --latest -vvv

More: :doc:`execution modes and options <COMMANDS>`.
