QuickStart
==========

- Step 0 (not mandatory but strongly suggested): setup a virtualenv.

  .. code:: bash

    $ # if virtualenv is not already installed...

    $ # on Debian/Ubuntu:
    $ sudo apt-get install python-virtualenv
    $ # using pip:
    $ sudo pip install virtualenv
    
    $ mkdir ripe-atlas-monitor
    $ cd ripe-atlas-monitor
    $ virtualenv venv
    $ source venv/bin/activate

  More: virtualenv `installation <https://virtualenv.pypa.io/en/latest/installation.html>`_ and `usage <https://virtualenv.pypa.io/en/latest/userguide.html>`_.

- Step 1: install **ripe-atlas-monitor** and its requirements.

  Some libraries **ripe-atlas-monitor** depends on need to be compiled and require a compiler and Python's dev libraries.

  .. code:: bash

      $ # on Debian/Ubuntu:
      $ sudo apt-get install python-dev libffi-dev libssl-dev

      $ pip install ripe-atlas-monitor

  More: :doc:`installation options <INSTALL>`.

- Step 2: global configuration.

  .. code:: bash

      $ # directory where ripe-atlas-monitor can write a bunch of data
      $ mkdir var
      $ ripe-atlas-monitor init-config

  Edit the config file and set (at least) the ``var`` parameter:

  .. code:: yaml

      var: /path/to/ripe-atlas-monitor/var

  More: :doc:`global configuration options <CONFIG>`.

- Step 3: create a new monitor and customize its configuration.

  .. code:: bash

      $ ripe-atlas-monitor init-monitor -m MonitorName

  More: :doc:`how monitors work <MONITORS>` and :doc:`syntax <SYNTAX>`.

- Step 4: run the brand new monitor to process measurement's latest results.

  .. code:: bash

      $ ripe-atlas-monitor run -m MonitorName --latest -vvv

  More: :doc:`execution modes and options <COMMANDS>`.
