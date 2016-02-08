RIPE Atlas Monitor
==================
|Documentation| |Build Status| |PYPI Version| |Python Versions|

A Python tool to monitor results collected by `RIPE Atlas`_ probes and verify they match against predefined expected values.

**Full documentation**: https://ripe-atlas-monitor.readthedocs.org/

How does it work?
-----------------

On the basis of a `RIPE Atlas`_ measurement previously created, you define a *monitor* by declaring which results you expect that probes should produce: *rules* are used to map probes and their *expected results*. Depending on whether the collected results match the expectations, custom  *actions* are performed: to log the result, to send an email, a syslog message or to run an external program.

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
        to: noc@agreatcompany.org
        subject: ripe-atlas-monitor: unexpected results
    measurement-id: 123456789

.. _RIPE Atlas: https://atlas.ripe.net

.. include:: TOC.rst

Status
------

This tool is currently in **beta**: some field tests have been done but it needs to be tested deeply and on more scenarios.

Moreover, contributions (fixes to code and to grammatical errors, typos, new features) are very much appreciated. More details on the contributing guide.

Bug? Issues?
------------

But also suggestions? New ideas?

Please create an issue on GitHub at https://github.com/pierky/ripe-atlas-monitor/issues

Author
------

Pier Carlo Chiodi - https://pierky.com

Blog: https://blog.pierky.com Twitter: `@pierky <https://twitter.com/pierky>`_

.. |Documentation| image:: https://readthedocs.org/projects/ripe-atlas-monitor/badge/?version=latest
    :target: http://ripe-atlas-monitor.readthedocs.org/en/latest/?badge=latest
.. |Build Status| image:: https://travis-ci.org/pierky/ripe-atlas-monitor.svg?branch=master
    :target: https://travis-ci.org/pierky/ripe-atlas-monitor
.. |PYPI Version| image:: https://img.shields.io/pypi/v/ripe-atlas-monitor.svg
    :target: https://pypi.python.org/pypi/ripe-atlas-monitor/
.. |Python Versions| image:: https://img.shields.io/pypi/pyversions/ripe-atlas-monitor.svg
    :target: https://pypi.python.org/pypi/ripe-atlas-monitor/
