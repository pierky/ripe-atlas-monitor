Monitor configuration syntax
============================

.. contents::

Monitor
-------


A monitor allows to process results from a measurement.

**Configuration fields:**

- ``descr`` (optional): monitor's brief description.

- ``measurement-id`` (optional): measurement ID used to gather results. It can
  be given (and/or overwritten) via command line argument ``--measurement-id``.

- ``matching_rules``: list of rules to match probes against. When a probe
  matches one of these rules, its expected results are processed and its
  actions are performed.

- ``expected_results`` (optional): list of expected results. Probe's expected
  results contain references to this list.

- ``actions`` (optional): list of actions to be executed on the basis of
  probe's expected results.

- ``stream`` (optional): boolean indicating if results streaming must be used.
  It can be given (and/or overwritten) via command line argument ``--stream``.

- ``stream_timeout`` (optional): how long to wait (in seconds) before stopping
  a streaming monitor if no results are received on the stream.

- ``key`` (optional): RIPE Atlas key to access the measurement. It can be
  given (and/or overwritten) via command line argument ``--key``.

- ``key_file`` (optional): a file containing the RIPE Atlas key to access the
  measurement. The file must contain only the RIPE Atlas key, in plain text.
  If ``key`` is given, this field is ignored.

Rule
----


Probes which produced the results fetched from the measurement are matched
against these rules to determine whether those results must be processed
or not.

**Configuration fields:**

- ``descr`` (optional): a brief description of the rule.

- ``process_next`` (optional): determine whether the rule following the current
  one has to be elaborated or nor. More details on the description below.

- ``src_country`` (optional): list of two letters country ISO codes.

- ``src_as`` (optional): list of Autonomous System numbers.

- ``probe_id`` (optional): list of probes' IDs.

- ``internal_labels`` (optional): list of internal labels. More details on the
  description below.

- ``reverse`` (optional): boolean, indicating if the aforementioned criteria
  identify probes which have to be exluded from the matching.

- ``expected_results`` (optional): list of expected results' names which
  have to be processed on match. Must be one or more of the expected results
  defined in Monitor.``expected_results``. If empty or missing, the rule will
  be treated as if a match occurred and its actions are performed.

- ``actions`` (optional): list of actions' names which have to be perormed for
  matching probes. Must be one or more of the actions defined in
  Monitor.``actions``.

The ``src_country`` criterion matches when probe's source country is one of
the country ISO codes given in the list.

The ``src_as`` criterion matches when probe's source AS is one of the ASN
given in the list. Since RIPE Atlas defines two ASs for each probe (ASN_v4
and ASN_v6) the one corresponding to the measurement's address family is
taken into account.

The ``probe_id`` criterion matches when probe's ID is one of the IDs given
in the list.

The ``internal_labels`` criterion matches when a probe has been previously
tagged with a label falling in the given list. See the ``label`` Action for
more details.

A probe matches the rule when all the given criteria are satisfied or when
no criteria are defined at all. If ``reverse`` is True, a probe matches when
none of the criteria is satisfied.

When a probe matches the rule, the expected results given
in ``expected_results`` are processed; actions given in the ``actions`` list
are performed on the basis of expected results processing output. If
no ``expected_results`` are given, actions will be performed too.

When a probe matches the current rule's criteria:

- if ``process_next`` is True, the rule which follows the current one is
  forcedly elaborated;

- if ``process_next`` if False or missing, the rules processing is stopped.

If a probe does not match the current rule's criteria:

- if ``process_next`` is False, the rule processing is forcedly stopped;

- if ``process_next`` is True or missing, the rule which follows the current
  one is regularly processed.

**Examples:**

.. code:: yaml

    matching_rules:
    - descr: Do not process results for probe ID 123 and 456
      probe_id:
      - 123
      - 456
    - descr: Check dst AS for any probe, errors to NOC; process next rule
      expected_results: DstAS
      actions: SendEMailToNOC
      process_next: True
    - descr: Italian probes must reach target via AS64496
      src_country: IT
      expected_results: ViaAS64496
      actions: LogErrors
    - descr: German and French probes must reach target with low RTT
      src_country:
      - DE
      - FR
      expected_results: LowRTT
      actions: LogErrors

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

Expected result
---------------


A group of criteria used to match probes' results.

**Configuration fields:**

- ``descr`` (optional): a brief description of this group of criteria.

Matching rules reference this on their ``expected_results`` list.

When a probe matches a rule, the keys in the ``expected_results`` list
of that rule are used to obtain the group of criteria to be used to
process the result.

**Example:**

.. code:: yaml

    matching_rules:
    - descr: Probes from France via AS64496
      src_country: FR
      expected_results: ViaAS64496
    expected_results:
      ViaAS64496:
        upstream_as: 64496

Common criteria
***************

Criterion: rtt
++++++++++++++


Test the median round trip time toward destination.

**Available for**:

- ping

- traceroute.


**Configuration fields:**

- ``rtt``: maximum RTT (in ms).

- ``rtt_tolerance`` (optional): tolerance (in %) on ``rtt``.

If ``rtt_tolerance`` is not given, match when measured RTT is less
than ``rtt``, otherwise match when measured RTT is within ``rtt``
+/- ``rtt_tolerance`` %.

**Examples:**

.. code:: yaml

    expected_results:
      LowRTT:
        rtt: 50
      Near150:
        rtt: 150
        rtt_tolerance: 30

Criterion: dst_responded
++++++++++++++++++++++++


Verify if destination responded.

**Available for**:

- traceroute

- ping

- sslcert.


**Configuration fields:**

- ``dst_responded``: boolean indicating if the destination is expected to be
  responding or not.

For ping, a destination is responding if a probe received at least one
reply packet.
For sslcert, a destination is responding if at least one certificate is
received by the probe.

If ``dst_responded`` is True, match when a destination is responding.
If ``dst_responded`` is False, match when a destination is not responding.

**Example:**

.. code:: yaml

    expected_results:
      DestinationReachable:
        dst_responded: True

Criterion: dst_ip
+++++++++++++++++


Verify that the destination IP used by the probe for the measurement is
the expected one.

**Available for**:

- traceroute

- ping

- sslcert.


**Configuration fields:**

- ``dst_ip``: list of expected IP addresses (or prefixes).

Match when the probe destination IP is one of the expected ones (or falls
within one of the expected prefixes).

**Examples:**

.. code:: yaml

    dst_ip: 192.168.0.1

    dst_ip:
    - 192.168.0.1
    - 2001:DB8::1

    dst_ip:
    - 192.168.0.1
    - 10.0.0.0/8
    - 2001:DB8::/32

Traceroute criteria
*******************

Criterion: dst_as
+++++++++++++++++


Verify the traceroute destination's AS number.

**Available for**:

- traceroute


**Configuration fields:**

- ``dst_as``: list of Autonomous System numbers.

It builds the path of ASs traversed by the traceroute.
Match when the last AS in the path is one of the expected ones.

**Examples:**

.. code:: yaml

    dst_as:
    - 64496

    dst_as:
    - 64496
    - 65551

Criterion: as_path
++++++++++++++++++


Verify the path of ASs traversed by a traceroute.

**Available for**:

- traceroute


**Configuration fields:**

- ``as_path``: list of Autonomous System path.

An AS path is made of AS numbers separated by white spaces. It can
contain two special tokens:

- "S", that is expanded with the probe's source AS number;

- "IX", that represents an Internet Exchange Point peering network for
  those IXPs which don't announce their peering prefixes via BGP.

The "IX" token is meagniful only if the ``ip_cache.use_ixps_info``
global configuration parameter is True.

It builds the path of ASs traversed by the traceroute.
Match when the AS path or a contiguous part of it is one of
the expected ones.

**Examples:**

.. code:: yaml

    as_path: 64496 64497

    as_path:
    - 64496 64497
    - 64498 64499 64500

    as_path:
    - S 64496 64497

    as_path:
    - S IX 64500

Criterion: upstream_as
++++++++++++++++++++++


Verify the traceroute destination upstream's AS number.

**Available for**:

- traceroute


**Configuration fields:**

- ``upstream_as``: list of Autonomous System numbers.

It builds the path of ASs traversed by the traceroute.
Match when the penultimate AS in the path is one of the expected ones.

**Examples:**

.. code:: yaml

    upstream_as:
    - 64496

    upstream_as:
    - 64496
    - 64497

SSL criteria
************

Criterion: cert_fp
++++++++++++++++++


Verify SSL certificates' fingerprints.

**Available for**:

- sslcert


**Configuration fields:**

- ``cert_fp``: list of certificates' SHA256 fingerprints or SHA256
  fingerprints of the chain.

A fingerprint must be in the format 12:34:AB:CD:EF:... 32 blocks of 2
characters hex values separated by colon (":").

The ``cert_fp`` parameter can contain stand-alone fingerprints or bundle of
fingerprints in the format "fingerprint1,fingerprint2,fingerprintN".

A result matches if any of its certificates' fingerprint is in the list
of stand-alone expected fingerprints or if the full chain fingerprints is
in the list of bundle fingerprints.

**Examples:**

.. code:: yaml

    expected_results:
      MatchLeafCertificate:
        cert_fp: 01:02:[...]:31:32
      MatchLeacCertificates:
        cert_fp:
        - 01:02:[...]:31:32
        - 12:34:[...]:CD:EF
      MatchLeafOrChain:
        cert_fp:
        - 01:02:[...]:31:32
        - 12:34:[...]:CD:EF,56:78:[...]:AB:CD

DNS criteria
************

Criterion: dns_rcode
++++++++++++++++++++


Verify if DNS responses received by a probe have the expected rcode.

**Available for**:

- dns.


**Configuration fields:**

- ``dns_rcode``: list of expected DNS rcodes ("NOERROR", "FORMERR", "SERVFAIL",
  "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET",
  "NOTAUTH", "NOTZONE", "BADVERS").

Match when all the responses received by a probe have one of the expected
rcodes listed in ``dns_rcode``.

**Example:**

.. code:: yaml

    expected_results:
      DNS_NoError_or_NXDomain:
        dns_rcode:
        - "NOERROR"
        - "NXDOMAIN"

Criterion: dns_flags
++++++++++++++++++++


Verify if DNS responses received by a probe have the expected
headers flags on.

**Available for**:

- dns.


**Configuration fields:**

- ``dns_flags``: list of expected DNS flag ("aa", "ad", "cd", "qr", "ra",
  "rd").

Match when all the responses received by a probe have all the expected
flags on.

**Example:**

.. code:: yaml

    expected_results:
      AA_and_AD:
        dns_flags:
        - aa
        - ad

Criterion: edns
+++++++++++++++


Verify EDNS extension of DNS responses received by probes.

**Available for**:

- dns.


**Configuration fields:**

- ``edns``: boolean indicating whether EDNS support is expected or not.

- ``edns_size`` (optional): minimum expected size.

- ``edns_do`` (optional): boolean indicating the expected presence of DO flag.

- ``edns_nsid`` (optional): list of expected NSID values.

The optional parameters are taken into account only when ``edns`` is True.

If ``edns`` is True, match when all the responses contain EDNS extension,
otherwise when all the responses do not contain it.
If ``edns_size`` is given, the size reported must be >= than the expected
one.
If ``edns_do`` is given, all the responses must have (or have not) the DO
flag on.
If ``edns_nsid`` is given, all the responses must contain and EDNS NSID
option which falls within the list of values herein specified.

**Examples:**

.. code:: yaml

    edns: true

    edns: true
    edns_do: true

    edns: true
    edns_nsid:
    - "ods01.l.root-servers.org"
    - "kbp01.l.root-servers.org"

Criterion: dns_answers
++++++++++++++++++++++


Verify if the responses received by a probe contain the expected
records.

**Available for**:

- dns.


**Configuration fields:**

- ``dns_answers``: one or more sections where records are searched on. Must
  be one of "answers", "authorities", "additionals".

Each section must contain a list of records.

Match when all the responses received by a probe contain at least one
record matching the expected ones in each of the given sections.

**Example:**

.. code:: yaml

    dns_answers:
        answers:
            - <record1>
            - <record2>
        authorities:
            - <record3>
            - <record4>

DNS record
``````````


Test properties which are common to all DNS record types.

**Configuration fields:**

- ``type``: record's type. Must be one of the DNS record types implemented
  and described below.

- ``name`` (optional): list of expected names.

- ``ttl_min`` (optional): minimum TTL that is expected for the record.

- ``ttl_max`` (optional): maximum TTL that is expected for the record.

- ``class`` (optional): expected class for the record.

Match when all the defined criteria are met:

- record name must be within the list of given names (``name``);

- record TTL must be >= ``ttl_min`` and <= ``ttl_max``;

- record class must be equal to ``class``.

On the basis of record's ``type``, further parameters may be needed.

**Example:**

.. code:: yaml

    dns_answers:
        answers:
            - type: A
              name: www.ripe.net.
              address: 193.0.6.139
            - type: AAAA
              name:
              - www.ripe.net.
              - ripe.net.
              ttl_min: 604800
              address: 2001:67c:2e8:22::c100:0/64

A record
````````


Verify if record's type is A and if received address match the
expectations.

**Configuration fields:**

- ``address``: list of IPv4 addresses (or IPv4 prefixes).

Match when record's type is A and resolved address is one of the
given addresses (or falls within one of the given prefixes).

AAAA record
```````````


Verify if record's type is AAAA and if received address match the
expectations.

**Configuration fields:**

- ``address``: list of IPv6 addresses (or IPv6 prefixes).

Match when record's type is AAAA and resolved address is one of the
given addresses (or falls within one of the given prefixes).

NS record
`````````


Verify if record's type is NS and if target is one of the expected ones.

**Configuration fields:**

- ``target``: list of expected targets.

Match when record's type is NS and received target is one of those given
in ``target``.

CNAME record
````````````


Verify if record's type is CNAME and if target is one of the expected ones.

**Configuration fields:**

- ``target``: list of expected targets.

Match when record's type is CNAME and received target is one of those given
in ``target``.

Action
------


Action performed on the basis of expected results processing for probes
which match the ``matching_rules`` rules.

**Configuration fields:**

- ``kind``: type of action.

- ``descr`` (optional): brief description of the action.

- ``when`` (optional): when the action must be performed (with regards of
  expected results processing output); one of "on_match", "on_mismatch",
  "always". Default: "on_mismatch".

When a probe matches a rule, it's expected results are processed; on the
basis of the output, actions given in the rule's ``actions`` list are
performed.
For each expected result, if the probe's collected result matches the
expectation actions whose ``when`` = "on_match" or "always" are performed.
If the collected result does not match the expected result, actions
whose ``when`` = "on_mismatch" or "always" are performed.

Action log
**********


Log the match/mismatch along with the collected result.

No parameters required.

Action email
************


Send an email with the expected result processing output.

**Configuration fields:**

- ``from_addr`` (optional): email address used in the From field.

- ``to_addr`` (optional): email address used in the To field.

- ``subject`` (optional): subject of the email message.

- ``smtp_host`` (optional): SMTP server's host.

- ``smtp_port`` (optional): SMTP server's port.

- ``use_ssl`` (optional): boolean indicating whether the connection
  toward SMTP server must use encryption.

- ``username`` (optional): username for SMTP authentication.

- ``password`` (optional): password for SMTP authentication.

- ``timeout`` (optional): timeout, in seconds.

Parameters which are not given are read from the global configuration
file ``default_smtp`` section.

Action run
**********


Run an external program.

**Configuration fields:**

- ``path``: path of the program to run.

- ``env_prefix`` (optional): prefix used to build environment variables.

- ``args`` (optional): list of arguments which have to be passed to the
  program. If the argument starts with "$" it is replaced with the
  value of the variable with the same name.

If ``env_prefix`` is not given, it's value is taken from the global
configuration file ``misc.env_prefix`` parameter.

Variables are:

- ``ResultMatches``: True, False or None
- ``MsmID``: measurement's ID
- ``MsmType``: measurement's type (ping, traceroute, sslcert, dns)
- ``MsmAF``: measurement's address family (4, 6)
- ``MsmStatus``: measurement's status (Running, Stopped)
  [https://atlas.ripe.net/docs/rest/]
- ``MsmStatusID``: measurement's status ID
  [https://atlas.ripe.net/docs/rest/]
- ``Stream``: True or False
- ``ProbeID``: probe's ID
- ``ProbeCC``: probe's ISO Country Code
- ``ProbeASNv4``: probe's ASN (IPv4)
- ``ProbeASNv6``: probe's ASN (IPv6)
- ``ProbeASN``: probe's ASN related to measurement's address family
- ``ResultCreated``: timestamp of result's creation date/time

**Example:**

.. code:: yaml

    actions:
      RunMyProgram:
        kind: run
        path: /path/to/my-program
        args:
        - command
        - -o
        - --msm
        - $MsmID
        - --probe
        - $ProbeID

Action syslog
*************


Log the match/mismatch along with the collected result using syslog.

**Configuration fields:**

- ``socket`` (optional): where the syslog message has to be logged. One of
  "file", "udp", "tcp".

- ``host`` (optional): meaningful only when ``socket`` is "udp" or "tcp". Host
  where send the syslog message to.

- ``port`` (optional): meaningful only when ``socket`` is "udp" or "tcp".
  UDP/TCP port where send the syslog message to.

- ``file`` (optional): meaningful only when ``socket`` is "file". File where the
  syslog message has to be written to.

- ``facility`` (optional): syslog facility that must be used to log the
  message.

- ``priority`` (optional): syslog priority that must be used to log the
  message.

Parameters which are not given are read from the global configuration
file ``default_syslog`` section.

Action label
************


Add or remove custom labels to/from probes.

**Configuration fields:**

- ``op``: operation; one of "add" or "del".

- ``label_name``: label to be added/removed.

- ``scope`` (optional): scope of the label; one of "result" or "probe".
  Default: "result".

Labels can be added to probes and subsequently used to match those probes
in other rules (``internal_labels`` criterion).

If scope is "result", the operation is significative only within the
current result processing (that is, within the current ``matching_rules``
processing for the current result). Labels added to probe are
removed when the current result processing is completed.

If scope is "probe", the operation is persistent across results processing.


