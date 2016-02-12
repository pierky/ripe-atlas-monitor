QuickStart
==========

- Step 1: install dependencies.

  Some libraries **ripe-atlas-monitor** depends on need to be compiled and require a compiler and Python's dev libraries.

  .. code:: bash

      $ # on Debian/Ubuntu:
      $ sudo apt-get install python-dev libffi-dev libssl-dev

      $ # on CentOS:
      $ sudo yum install gcc libffi-devel openssl-devel

      $ # strongly suggested: install pip and setup a virtualenv

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

  More: virtualenv `installation <https://virtualenv.pypa.io/en/latest/installation.html>`_ and `usage <https://virtualenv.pypa.io/en/latest/userguide.html>`_.


- Step 2: install **ripe-atlas-monitor**.

  .. code:: bash

      $ pip install ripe-atlas-monitor

      $ # to enable bash autocomplete:
      $ eval "$(register-python-argcomplete ripe-atlas-monitor)"

  More: :doc:`installation options <INSTALL>`.


- Step 3: global configuration.

  .. code:: bash

      $ # directory where ripe-atlas-monitor can write a bunch of data
      $ mkdir var
      $ ripe-atlas-monitor init-config

  Edit the config file and set (at least) the ``var`` parameter:

  .. code:: yaml

      var: /path/to/ripe-atlas-monitor/var

  More: :doc:`global configuration options <CONFIG>`.


- Step 4: create a new monitor and customize its configuration.

  .. code:: bash

      $ ripe-atlas-monitor init-monitor -m MonitorName

  More: :doc:`how monitors work <MONITORS>` and :doc:`syntax <SYNTAX>`.

  The ``analyze`` command can give you an overview of the results for a specific measurement, as elaborated by **ripe-atlas-monitor**:

  .. code:: bash

      $ ripe-atlas-monitor analyze --measurement-id 1234567890

  Alternatively, you can take a look at the sample monitors provided within the `examples <https://github.com/pierky/ripe-atlas-monitor/tree/master/examples>`_ directory.


- Step 5: run the brand new monitor to process measurement's latest results.

  .. code:: bash

      $ ripe-atlas-monitor run -m MonitorName --latest -vvv

  More: :doc:`execution modes and options <COMMANDS>`.
