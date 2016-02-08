Global configuration
====================

The global configuration file contains some options that are used by the program to run: the working directory path, logging options, default values for some actions and so on.

By default, **ripe-atlas-monitor** looks for this file in ``$HOME/.config/ripe-atlas-monitor`` (if ``$HOME`` is not defined, it tries with ``/etc/ripe-atlas-monitor/config.cfg``), but this path can be set with the ``--cfg`` command line argument.

Only one parameter is really needed, it is the ``var`` directory used by the program to store its monitors configuration files and a bunch of other data (IP addresses cache, running status).

You can initialize the global configuration file by executing ``ripe-atlas-monitor init-config``: this command copies the template file to the default path. Add the ``--cfg`` argument to use a custom path.

Comments within the file itself should be enough to explain the various options. If you want to take a look at it, you can find it on `GitHub <https://github.com/pierky/ripe-atlas-monitor/blob/master/pierky/ripeatlasmonitor/templates/global_config.yaml>`_.
