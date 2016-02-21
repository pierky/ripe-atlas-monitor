Commands
========

Monitors' configuration management
----------------------------------

Some commands can be used to manage monitors' configuration:

- ``init-monitor``: initializes a new monitor configuration by cloning the template file;

- ``edit-monitor``: opens the monitor's configuration file with the default text editor (``$EDITOR`` or ``misc.editor`` global config option);

- ``check-monitor``: verifies that the monitor's configuration syntax is valid and conforming to the measurement's type. The ``-v`` argument can be used to display an explanatory description of the given configuration as interpreted by the program.

.. code:: bash

    $ ripe-atlas-monitor [init-monitor | edit-monitor | check-monitor] -m MonitorName

Results analysis
----------------

The ``analyze`` command can be used to have an overview of results received from a measurement and how they are elaborated by **ripe-atlas-monitor**:

.. code:: bash

    $ ripe-atlas-monitor analyze --measurement-id 1234567890

    $ ripe-atlas-monitor analyze -m MonitorName

The ``--key`` argument can be used to provide a RIPE Atlas key to fetch the results. Other arguments may be used to display statistics about probes distribution and to show sub-results, grouping them by country or by source AS: the ``--help`` will show all of these options.

Execution modes
---------------

There are some ways this tool can be executed, depending on how many concurrent monitors you want to run and which measurement results you want to consider.

The ``-v`` argument is common to all the scenarios and allow to set the verbosity level:

- 0: only warnings and errors are produced;
- 1 (``-v``): messages from logging actions are produced;
- 2 (``-vv``): results from matching rules are produced too;
- 3 (``-vvv``): information messages are logged (internal decisions about rules and results processing);
- 4 (``-vvvv``): debug messages are logged too, useful to debug monitors' configurations.

Single monitor: ``run`` command
*******************************

The ``run`` command allows to execute a single monitor. It is mostly useful to process one-off measurements or to debug monitors' configurations.

.. code:: bash

    $ ripe-atlas-monitor run -m MonitorName -vvv

In this mode, the ``--start``, ``--stop`` and ``--latest`` arguments allow to set the time frame for the measurement's results to download, unless the monitor has the ``stream`` option set to use `RIPE Atlas result streaming <https://atlas.ripe.net/docs/result-streaming/>`_.

Time frame options
~~~~~~~~~~~~~~~~~~

By default, for measurements which are still running, results are fetched continously every *measurement's interval* seconds, starting from the time of the last received result.

- The ``--start`` and ``--stop`` arguments set the lower and upper bounds for results downloading and processing. They can be used togheter or separately.

- If the ``--start`` argument is not given, results are downloaded starting from the last processed result's timestamp, or from the last 7 days (configurable in the global config) if the measurement has not been processed yet.

- If the ``--stop`` argument is missing, results up to the last produced one are downloaded.

- The ``--latest`` argument can be used when the other two are not passed and it allows to download the `latest results <https://atlas.ripe.net/docs/measurement-latest-api/>`_ only.

- For running measurements, the ``--dont-wait`` argument allows to run a monitor against up to date results then exiting, without waiting for measurement's interval before running it again.

Multiple monitors: ``daemonize`` command
****************************************

.. note::

    This mode is highly experimental

The ``daemonize`` command allows to run multiple monitors within a single instance of **ripe-atlas-monitor** by forking the main process into many subprocesses, one for each monitor. This mode does not allow to use time frame arguments, results are downloaded starting from the last received one for each measurement. This mode is mostly suitable for streaming monitors or continous measurements.

.. code:: bash

    $ ripe-atlas-monitor daemonize -m Monitor1Name -m Monitor2Name
