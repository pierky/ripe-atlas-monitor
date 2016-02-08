Monitors: how they work
=======================

Monitors are the core of the program. You can initialize their configuration with ``ripe-atlas-monitor init-monitor -m monitor_name``: a monitor template file will be created and opened for customization using the preferred text editor (which can also be set within the global configuration file or via the ``$EDITOR`` environment variable).

How they work
-------------

You have a RIPE Atlas measurement;

- probes involved in the measurement collect some results (ping, traceroute, ...);
- a **ripe-atlas-monitor**'s monitor is executed;
- results for the aforementioned measurement are downloaded and elaborated;
- for each result, the probe's information (ID, country, ASN) are matched against a set of rules;
- if a matching condition is found, the result collected by that probe is matched against a set of results you expected from that probe;
- actions (email, syslog, external programs) are performed on the basis of this process's output.

All this is written in YAML files, one for each monitor you want to configure:

.. code:: yaml

    descr: Check network reachability
    matching_rules:
    - descr: Probes from France via AS64496
      src_country: FR
      expected_results: ViaAS64496
      actions: EMailToNOC
    - descr: RTT from AS64499 and AS64500 below 50ms
      src_as:
      - 64499
      - 64500
      expected_results: LowRTT
      actions: EMailToNOC
    expected_results:
      ViaAS64496:
        upstream_as: 64496
      LowRTT:
        rtt: 50
    actions:
      EMailToNOC:
        kind: email
        to_addr: noc@agreatcompany.org
        subject: "ripe-atlas-monitor: unexpected results"
    measurement-id: 123456789

For the complete syntax of monitors' configuration file please refer to :doc:`SYNTAX`.

Kinds of monitors
-----------------

Depending on the measurement they are configured to use and which command is used to run them, monitors can be grouped into 3 categories:

- *one-off* monitors are those used to process one-off measurements: they are executed using the ``--latest`` argument of **ripe-atlas-monitor** to download only the latest results, or they can be executed using both the ``--start`` and ``--stop`` command line argument in order to define a specific time frame within which results are downloaded;

- *continous* monitors are used to continously process results for those measurements which have not been stopped yet: results are downloaded and processed once every *x* seconds, where *x* is the ``interval`` value of the measurement itself; when the ``--start`` argument of **ripe-atlas-monitor** is used, results are downloaded starting at that time, otherwise results are downloaded starting from the timestamp of the last processed result;

- *streaming* monitors, which are those that use `RIPE Atlas result streaming <https://atlas.ripe.net/docs/result-streaming/>`_.

The type of monitor is not written anywhere, it's derived from the :doc:`commands <COMMANDS>` used to run **ripe-atlas-monitor**. For example, the same monitor can be run using ``ripe-atlas-monitor run -m MonitorName --measurement-id 123456 --latest`` to process the latest results from the measurement ID 123456, but also using ``ripe-atlas-monitor daemonize -m MonitorName`` to continously process results from the measurement reported in the ``measurement-id`` attribute of its configuration file. It can be also run in streaming mode, by using the ``--stream`` command line argument (provided that the measurement is still running).

Expected results criteria
-------------------------

Expected results can be of various kinds, depending on the measurement's type, and various criteria can be used to verify collected results.

Traceroute measurements can be used to monitor **AS path toward a destination**, ping measurements to test **network reachability** and performance, SSL measurements to be sure that the certificates received by a probe match the **expected fingerprints** and that TLS connections are not hijacked on their way, DNS measurements to verify **host name resolution**.

For the full list of implemented criteria please read :doc:`SYNTAX`.

Advanced use
------------

Configuration syntax "tricks" and *internal labels* allow to describe complex scenarios.

Excluding probes from processing
++++++++++++++++++++++++++++++++

A rule with no ``expected_results`` and the ``process_next`` attribute to its default value False (or missing) allows to stop further processing for those probes which match the rule's criteria:

.. code:: yaml

    matching_rules:
    - descr: Do not process results for probe ID 123 and 456
      probe_id:
      - 123
      - 456

Match all probes except those...
++++++++++++++++++++++++++++++++

The ``reverse`` attribute of a rule, when set to True, allows to match all the probes which do not meet the given criteria:

.. code:: yaml

    matching_rules:
    - descr: All probes except those from AS64496
      src_as: 64496
      reverse: True

Actions execution
+++++++++++++++++

The ``when`` attribute of an action can be used to set when it has to be performed:

- ``on_match``, the action is performed when the collected result matches one of the expected values, or when the rule has no expected results at all;
- ``on_mismatch``, the action is performed when the collected result does not match the expected values;
- ``always``, well, the action is always performed, independently of results.

Internal labels
+++++++++++++++

Actions can be used to attach internal labels to probes on the basis of rules and results processing. These labels can be subsequently used to match probes against specific rules.

.. code:: yaml

    matching_rules:
    - descr: Set 'VIP' (Very Important Probe) label to ID 123 and 456
      probe_id:
      - 123
      - 456
      process_next: True
      actions: SetVIPLabel
    - descr: Set 'VIP' label to Italian probes too
      src_country: IT
      process_next: True
      actions: SetVIPLabel
    - descr: VIPs must have low RTT
      internal_labels: VIP
      expected_results: LowRTT
    actions:
      SetVIPLabel:
        when: always
        kind: label
        op: add
        label_name: VIP

Integration with ripe-atlas-tools (Magellan)
++++++++++++++++++++++++++++++++++++++++++++

`Magellan <https://github.com/RIPE-NCC/ripe-atlas-tools>`_ is the official command-line client for RIPE Atlas. It allows, moreover, to `create new measurements <https://ripe-atlas-tools.readthedocs.org/en/latest/use.html#measurement-creation>`_ from the command line. It can be used, for example, in an action to create one-off measurements from the probes which fail expectations.

.. code:: yaml

    actions:
      RunRIPEAtlasTraceroute:
        descr: Create new traceroute msm from the probe which missed expectations
        kind: run
        path: ripe-atlas
        args:
        - measure
        - traceroute
        - --target
        - www.example.com
        - --no-report
        - --from-probes
        - $ProbeID
