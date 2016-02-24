Commands
========

Results analysis
----------------

The ``analyze`` command can be used to have an overview of results received from a measurement and how they are elaborated by **ripe-atlas-monitor**:

.. code:: bash

    $ ripe-atlas-monitor analyze --measurement-id 1234567890

    $ ripe-atlas-monitor analyze -m MonitorName

Some heuristics provide aggregated metrics for most of the measurement's types:

- RTTs distribution (*ping, traceroute*)
- target responded or not (*ping, traceroute*)
- destination IP addresses (*ping, traceroute, ssl*)
- SSL certificate fingerprints (*ssl*)
- destination AS numbers and upstream ASNs (*traceroute*)
- AS paths (*traceroute*)
- DNS responses' flags combinations (*dns*)
- EDNS status (*dns*)

Results of each metric are grouped on the basis of common patterns and sorted by the number of matching probes.

Example analysis of measurement ID 1674977, a traceroute from 50 probes all over the world toward www.ripe.net (see it on `RIPE Atlas Tracepath <https://www.pierky.com/ripeatlastracepath/demo/>`_):

.. code:: bash

    $ ripe-atlas-monitor analyze --measurement-id 1674977

    Downloading and processing results... please wait
    Median RTTs:

          < 30 ms: 25 times, probe ID 10001 (AS3265, NL), probe ID 10012 (AS3265, NL), probe ID 10039 (AS701, US), ...

       30 - 60 ms: 14 times, probe ID 10068 (AS34594, HR), probe ID 10772 (AS12552, SE), probe ID 10816 (AS12322, FR), ...

        >= 180 ms: 5 times, probe ID 10509 (AS1273, HK), probe ID 10510 (AS1273, SG), probe ID 12468 (AS30844, ZW), ...

     150 - 180 ms: 3 times, probe ID 10313 (US), probe ID 13631 (AS21502, FR), probe ID 14856 (AS7922, US)

      (use the --show-all-rtts argument to show the full list)

    Destination responded:

     yes: 38 times, probe ID 10001 (AS3265, NL), probe ID 10012 (AS3265, NL), probe ID 10068 (AS34594, HR), ...

      no: 11 times, probe ID 10039 (AS701, US), probe ID 10460 (AS7155, GB), probe ID 10922 (RU), ...

    Unique destination IP addresses:

     193.0.6.139: 49 times, probe ID 10001 (AS3265, NL), probe ID 10012 (AS3265, NL), probe ID 10039 (AS701, US), ...

    Destination AS:

      3333: 38 times, probe ID 10001 (AS3265, NL), probe ID 10012 (AS3265, NL), probe ID 10068 (AS34594, HR), ...

     12513: 1 time, probe ID 12277 (AS12513, GB)

      7922: 1 time, probe ID 16134 (AS7922, US)

      7155: 1 time, probe ID 10460 (AS7155, GB)

      6830: 1 time, probe ID 12224 (AS6830, NL)

      5089: 1 time, probe ID 13335 (AS5089, GB)

      3320: 1 time, probe ID 11059 (AS3320, DE)

      3269: 1 time, probe ID 4228 (AS3269, IT)

       701: 1 time, probe ID 10039 (AS701, US)

    Upstream AS:

      1200: 24 times, probe ID 10001 (AS3265, NL), probe ID 10012 (AS3265, NL), probe ID 10273 (AS9143, NL), ...

      1299: 3 times, probe ID 10068 (AS34594, HR), probe ID 11586 (AS29056, AT), probe ID 16063 (AS6830, IE)

      3356: 2 times, probe ID 10313 (US), probe ID 14856 (AS7922, US)

     33765: 1 time, probe ID 15282 (AS33765, TZ)

     31213: 1 time, probe ID 11418 (AS39087, RU)

     21502: 1 time, probe ID 13631 (AS21502, FR)

     12513: 1 time, probe ID 10953 (AS12513, GB)

      8218: 1 time, probe ID 14175 (AS24651, LV)

      4755: 1 time, probe ID 14593 (AS4755, IN)

      2856: 1 time, probe ID 11610 (AS2856, GB)

      Only top 10 most common shown.
      (use the --show-all-upstream-asns argument to show the full list)

    Most common ASs sequences:

           1200 3333: 24 times

         S 1200 3333: 14 times

              S 1200: 14 times

              S 3333: 5 times

           1299 3333: 3 times

         S 1299 3333: 2 times

      9002 1200 3333: 2 times

      3356 1200 3333: 2 times

     15589 1200 3333: 2 times

              S 6830: 2 times

      (use the --show-all-aspaths argument to show the full list)

    Most common ASs sequences (with IXPs networks):

           1200 3333: 24 times

         S 1200 3333: 14 times

              S 1200: 14 times

              S 3333: 5 times

           1299 3333: 3 times

         S 1299 3333: 2 times

      9002 1200 3333: 2 times

      3356 1200 3333: 2 times

     15589 1200 3333: 2 times

              S 6830: 2 times

      (use the --show-all-aspaths argument to show the full list)

The ``--probes`` argument can be used to restrict the analysis to results produced by a limited set of probes by specifying their IDs.

.. code:: bash

    $ ripe-atlas-monitor analyze --measurement-id 1234567890 --probes 1,23,456

The ``--key`` argument can be used to provide a RIPE Atlas key needed to fetch the results. Other arguments may be used to display statistics about probes distribution and to show sub-results, grouping them by country or by source AS: the ``--help`` will show all of these options.

Monitors' configuration management
----------------------------------

Some commands can be used to manage monitors' configuration:

- ``init-monitor``: initializes a new monitor configuration by cloning the template file;

- ``edit-monitor``: opens the monitor's configuration file with the default text editor (``$EDITOR`` or ``misc.editor`` global config option);

- ``check-monitor``: verifies that the monitor's configuration syntax is valid and conforming to the measurement's type. The ``-v`` argument can be used to display an explanatory description of the given configuration as interpreted by the program.

.. code:: bash

    $ ripe-atlas-monitor [init-monitor | edit-monitor | check-monitor] -m MonitorName

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

The ``run`` command allows to execute a single monitor. It is mostly useful to process one-off measurements, to schedule execution or to debug monitors' configurations.

.. code:: bash

    $ ripe-atlas-monitor run -m MonitorName -vvv

In this mode, the ``--start``, ``--stop`` and ``--latest`` arguments allow to set the time frame for the measurement's results to download, unless the monitor has the ``stream`` option set to use `RIPE Atlas result streaming <https://atlas.ripe.net/docs/result-streaming/>`_.
The ``--probes`` argument can be used to restrict the processing to results produced by a limited set of probes by specifying their IDs.

Time frame options
~~~~~~~~~~~~~~~~~~

By default, for measurements which are still running, results are fetched continously every *measurement's interval* seconds, starting from the time of the last received result.

- The ``--start`` and ``--stop`` arguments set the lower and upper bounds for results downloading and processing. They can be used togheter or separately.

- If the ``--start`` argument is not given, results are downloaded starting from the last processed result's timestamp, or from the last 7 days (configurable in the global config) if the measurement has not been processed yet.

- If the ``--stop`` argument is missing, results up to the last produced one are downloaded.

- The ``--latest`` argument can be used when the other two are not passed and it allows to download the `latest results <https://atlas.ripe.net/docs/measurement-latest-api/>`_ only.

- For running measurements, the ``--dont-wait`` argument allows to run a monitor against up to date results then exiting, without waiting for measurement's interval before running it again.

Scheduling monitors
~~~~~~~~~~~~~~~~~~~

Execution of **ripe-atlas-monitor** can be scheduled (using ``crontab`` for example) in order to periodically monitor measurements' results.

For continous measurements (those which are not stopped and keep producing results) the ``--dont-wait`` argument is particularly suggested, so that at each execution the program downloads and processes the results collected since the previous one.

.. note::

    Since only one instance of **ripe-atlas-monitor** at a time can be executed, if you plan to run multiple monitors be careful to schedule them in order to avoid overlapping running; alternatively consider using the ``daemonize`` command (see below).

If you are using a virtualenv, you can point your cron's job at the full ``python`` executable that is in the virtualenv's ``bin`` directory...

.. code:: bash

    1 * * * * /home/USERNAME/ripe-atlas-monitor/venv/bin/python /home/USERNAME/ripe-atlas-monitor/venv/bin/ripe-atlas-monitor -m MonitorName --dont-wait

... or you can write a wrapper bash script that sets up the virtualenv and then runs your command...

.. code:: bash

    #! /bin/bash
    cd /home/USERNAME/ripe-atlas-monitor/venv/
    source bin/activate
    "$@"

.. code:: bash

    1 * * * * /home/USERNAME/ripe-atlas-monitor/setup_venv_and_run ripe-atlas-monitor -m MonitorName --dont-wait

Multiple monitors: ``daemonize`` command
****************************************

.. note::

    This mode is highly experimental

The ``daemonize`` command allows to run multiple monitors within a single instance of **ripe-atlas-monitor** by forking the main process into many subprocesses, one for each monitor. This mode does not allow to use time frame arguments, results are downloaded starting from the last received one for each measurement. This mode is mostly suitable for streaming monitors or continous measurements.

.. code:: bash

    $ ripe-atlas-monitor daemonize -m Monitor1Name -m Monitor2Name
