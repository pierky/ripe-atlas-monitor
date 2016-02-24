Changelog
=========

0.1.5
-----

improvements
++++++++++++

- more options for the ``analyze`` command:
  - show probes (up to 3) beside results
  - destination AS and upstream AS results
  - show common sequences/patterns among results
- add ``--probes`` argument to ``run`` and ``analyze`` commands to filter results
- email logging of error messages

fixes
+++++

- fix empty resultset handling in ``analyze`` cmd

0.1.4
-----

new features
++++++++++++

- Python 3.4 support

improvements
++++++++++++

- ``-m`` argument for ``analyze`` command, to gather msm id and auth key from the monitor itself
- ``--dont-wait`` argument for ``run`` command

fixes
+++++

- herror handling for null RTT results in ``analyze`` command

0.1.3
-----

improvements
++++++++++++

- better RTT results formatting in ``analyze`` command
- no stdout logging when used in ``daemonize`` mode

fixes
+++++

- error handling for IXPs networks info unavailability

0.1.2
-----

new features
++++++++++++

- ``analyze`` command to show elaborated results from a measurement

- bash autocomplete

fixes
+++++

- continous monitors didn't run continously

0.1.1
-----

improvements
++++++++++++

- better results and actions logging

0.1.0
-----

First release (beta)
