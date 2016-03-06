# Copyright (C) 2016 Pier Carlo Chiodi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import six

from .Action import Action, ACTION_CLASSES
from .ExpectedResult import ExpectedResult
from .ExpResCriteria import CRITERIA_CLASSES, \
                            CRITERIA_CLASSES_COMMON, \
                            CRITERIA_CLASSES_TRACEROUTE, \
                            CRITERIA_CLASSES_SSL, \
                            CRITERIA_CLASSES_DNS
from .ExpResCriteriaDNS import ExpResCriterion_DNSAnswers, \
                               ExpResCriterion_AnswersSection
from .ExpResCriteriaDNSRecords import ExpResCriterion_DNSRecord, \
                                      HANDLED_RECORD_TYPES
from .Monitor import Monitor
from .Rule import Rule


def format_docstring(docstring):
    if not docstring:
        return ''
    # Convert tabs to spaces (following the normal Python rules)
    # and split into a list of lines:
    lines = docstring.expandtabs().splitlines()
    # Determine minimum indentation (first line doesn't count):
    indent = six.MAXSIZE
    for line in lines[1:]:
        stripped = line.lstrip()
        if stripped:
            indent = min(indent, len(line) - len(stripped))
    # Remove indentation (first line is special):
    trimmed = [lines[0].strip()]
    if indent < six.MAXSIZE:
        for line in lines[1:]:
            trimmed.append(line[indent:].rstrip())
    # Strip off trailing and leading blank lines:
    while trimmed and not trimmed[-1]:
        trimmed.pop()
    while trimmed and not trimmed[0]:
        trimmed.pop(0)
    # Return a single string:
    return '\n'.join(trimmed)


def get_params(ds, c):
    params = []     # list of (param_name, is_optional, is_list)

    like_a_param_pattern = re.compile("^`.+")
    param_pattern = re.compile("^`([\w_-]+)`\s?(\(optional\))?:\s(list)?")
    for line in ds.split("\n"):
        match = param_pattern.match(line)
        if like_a_param_pattern.match(line) and not match:
            raise ValueError(
                "{}: it seems a param but it's not: {}".format(
                    c, line
                )
            )
        if match:
            params.append(
                (
                    match.group(1),
                    match.group(2) is not None,
                    match.group(3) is not None
                )
            )

    all_fields = []
    mandatory_fields = []
    optional_fields = []

    if hasattr(c, "CRITERION_NAME"):
        mandatory_fields.append(c.CRITERION_NAME)

    if hasattr(c, "MANDATORY_CFG_FIELDS"):
        mandatory_fields.extend(getattr(c, "MANDATORY_CFG_FIELDS"))

    all_fields += mandatory_fields

    for param in params:
        if param[1] and param[0] in mandatory_fields:
            raise ValueError(
                "{}: param {} optional but it is mandatory".format(
                    c, param[0]
                )
            )

    if hasattr(c, "OPTIONAL_CFG_FIELDS"):
        optional_fields = getattr(c, "OPTIONAL_CFG_FIELDS")

    all_fields += optional_fields

    for param in params:
        if not param[1] and param[0] in optional_fields:
            raise ValueError(
                "{}: param {} mandatory but it is optional".format(c, param[0])
            )

    for field in all_fields:
        if field not in [param[0] for param in params]:
            raise ValueError("{}: undocumented field: {}".format(c, field))

    for param in params:
        if param[0] not in all_fields:
            raise ValueError("{}: unknown param: {}".format(c, param[0]))

    return params


def get_class_descr(ds_or_class):
    if isinstance(ds_or_class, str):
        return ds_or_class.split("\n")[0]
    else:
        ds = format_docstring(ds_or_class.__doc__)
        if ds:
            return get_class_descr(ds)
        else:
            return None


def dump_doc_title(s, lvl):
    HEADINGS = {
        "1": "=" * len(s),
        "2": "-" * len(s),
        "3": "*" * len(s),
        "4": "+" * len(s),
        "5": "`" * len(s)
    }

    return s + "\n" + HEADINGS[str(lvl)] + "\n"


def dump_doc(c, lvl):

    s = format_docstring(c.__doc__)
    title = get_class_descr(s)

    r = ""

    r += dump_doc_title(title, lvl) + "\n"

    lines = s.split("\n")[1:]

    example = False
    configuration_fields = False
    parameters = False

    for line in lines:
        line = line.replace("`", "``")

        if line == "":
            parameters = False
        else:
            if line.startswith("Example"):
                example = True
                r += "**{}**\n".format(line)
                r += "\n"
                r += ".. code:: yaml\n"
                continue

            elif line.startswith("`"):
                parameters = True
                if not configuration_fields:
                    r += "**Configuration fields:**\n\n"
                    configuration_fields = True
                r += "- "

            elif line.startswith("Available for:"):
                r += "**Available for**:\n\n"

                msm_types = line.split(":")[1].split(",")
                for msm_type in msm_types:
                    r += "- " + msm_type.strip().replace(".", "") + "\n\n"
                continue

            else:
                if example:
                    r += "    "
                if parameters:
                    r += "  "
        r += line + "\n"

    r += "\n"

    if c == ExpResCriterion_DNSAnswers:
        r += dump_doc(ExpResCriterion_DNSRecord, lvl+1)
        for subc in HANDLED_RECORD_TYPES:
            r += dump_doc(subc, lvl+1)
    return r


def build_doc():
    r = dump_doc_title("Monitor configuration syntax", 1) + "\n"
    r += ".. contents::\n\n"

    r += dump_doc(Monitor, 2)

    r += dump_doc(Rule, 2)

    r += dump_doc(ExpectedResult, 2)

    criteria = (
        ("Common criteria", CRITERIA_CLASSES_COMMON),
        ("Traceroute criteria", CRITERIA_CLASSES_TRACEROUTE),
        ("SSL criteria", CRITERIA_CLASSES_SSL),
        ("DNS criteria", CRITERIA_CLASSES_DNS)
    )

    cls_cnt = 0
    for group, classes in criteria:
        r += dump_doc_title(group, 3) + "\n"
        for subc in classes:
            cls_cnt += 1
            r += dump_doc(subc, 4)

    if cls_cnt != len(CRITERIA_CLASSES):
        raise ValueError(
            "One or more criteria classes have not been processed. "
            "{} processed vs {} total.".format(cls_cnt, len(CRITERIA_CLASSES))
        )

    r += dump_doc(Action, 2)
    for subc in ACTION_CLASSES:
        r += dump_doc(subc, 3)

    return r


def dump_yaml(c, indent="", show_doc=True, elements_type="",
              comment_optional=True, index=0):
    INDENT = "    "

    r = ""

    s = format_docstring(c.__doc__)

    if not s:
        return ""

    if show_doc:
        # print the whole docstring
        r += indent + "# {}\n".format("="*75)
        for line in s.split("\n"):
            r += indent + "# " + line + "\n"

        r += "\n"

    params = get_params(s, c)

    first_list_element = True

    class_description = get_class_descr(s)

    if elements_type == "dict":
        dict_key = class_description.replace(" ", "_")
        r += indent + "{}_{}:\n".format(dict_key, index+1)
    elif elements_type == "list":
        list_comment = class_description
        r += indent + "# {} n. {}\n".format(list_comment, index+1)

    if not show_doc:
        if c in HANDLED_RECORD_TYPES or c in ACTION_CLASSES:
            r += indent + "# {}\n".format(class_description)

    prefix = ""
    if elements_type == "dict":
        prefix = INDENT

    for param in params:
        if elements_type == "list":
            if first_list_element:
                r += indent + "- \n"
                first_list_element = False
            prefix = "  "

        r += indent + "{prefix}{comment}{param}: \n".format(
            prefix=prefix,
            comment="#" if comment_optional and param[1] else "",
            param=param[0]
        )

        if c == Monitor and param[0] == "expected_results":
            for i in range(2):
                r += dump_yaml(ExpectedResult, indent=indent + INDENT,
                               elements_type="dict",
                               show_doc=show_doc and i == 0,
                               comment_optional=comment_optional, index=i)

        elif c == Monitor and param[0] == "matching_rules":
            for i in range(2):
                r += dump_yaml(Rule, indent=indent,
                               elements_type="list",
                               show_doc=show_doc and i == 0,
                               comment_optional=comment_optional, index=i)

        elif c == Monitor and param[0] == "actions":
            for i in range(2):
                r += dump_yaml(Action, indent=indent + INDENT,
                               elements_type="dict",
                               show_doc=show_doc and i == 0,
                               comment_optional=comment_optional, index=i)

        else:
            if param[2]:
                for i in range(3):
                    param_name = param[0]

                    if c == Rule and param_name == "expected_results":
                        param_name = get_class_descr(ExpectedResult)
                    if c == Rule and param_name == "actions":
                        param_name = get_class_descr(Action)

                    param_name = param_name.replace(" ", "_")

                    r += indent + "{prefix}{comment}- {param}_{i}\n".format(
                        comment="#" if comment_optional and param[1] else "",
                        prefix=prefix,
                        param=param_name,
                        i=i+1
                    )
            r += "\n"

    if c == ExpectedResult:
        r += indent + prefix + "# one or more of the following criteria\n\n"

        for subc in CRITERIA_CLASSES:
            r += dump_yaml(subc, indent=indent + INDENT, show_doc=show_doc,
                           comment_optional=comment_optional, index=index)
    elif c == Action:
        r += indent + prefix + ("# one or more of the following "
                                "action-specific parameters\n\n")

        for subc in ACTION_CLASSES:
            r += dump_yaml(subc, indent=indent + INDENT, show_doc=show_doc,
                           comment_optional=comment_optional, index=index)

    elif c == ExpResCriterion_DNSAnswers:
        for i in range(2):
            r += dump_yaml(ExpResCriterion_AnswersSection,
                           indent=indent + INDENT, elements_type="dict",
                           show_doc=show_doc and i == 0,
                           comment_optional=comment_optional, index=i)

    elif c == ExpResCriterion_AnswersSection:
        for i in range(2):
            r += dump_yaml(ExpResCriterion_DNSRecord,
                           indent=indent + INDENT, elements_type="list",
                           show_doc=show_doc and i == 0,
                           comment_optional=comment_optional, index=i)

    elif c == ExpResCriterion_DNSRecord:
        r += indent + prefix + ("# one of the following "
                                "record-specific parameters\n\n")

        for subc in HANDLED_RECORD_TYPES:
            r += dump_yaml(subc, indent=indent + prefix, show_doc=show_doc,
                           comment_optional=comment_optional, index=index)

    return r


def build_monitor_cfg_tpl(comment_optional=True, show_doc=True):
    r = ""
    r += dump_yaml(Monitor, comment_optional=comment_optional,
                   show_doc=show_doc)

    return r

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Doc builder for RIPE Atlas Monitor"
    )

    subparsers = parser.add_subparsers(
        title="commands",
        dest="command"
    )

    sub_parser = subparsers.add_parser(
        "doc",
        help="Build monitor doc"
    )

    sub_parser = subparsers.add_parser(
        "cfg",
        help="Build monitor config template"
    )
    sub_parser.add_argument(
        "--no-comment",
        action="store_false",
        help="Do not comment optional fields",
        dest="comment_optional"
    )

    args = parser.parse_args()

    if args.command == "doc":
        print(build_doc())
    elif args.command == "cfg":
        print(build_monitor_cfg_tpl(comment_optional=args.comment_optional))
