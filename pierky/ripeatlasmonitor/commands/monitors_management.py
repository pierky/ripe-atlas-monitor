import os

from ..Config import Config
from ..Doc import build_monitor_cfg_tpl
from pierky.ripeatlasmonitor.Monitor import Monitor
from pierky.ripeatlasmonitor.Errors import RIPEAtlasMonitorError, \
                                           ProgramError, ArgumentError, \
                                           MissingFileError
from utils import edit_file


def init_monitor_cfg_file(monitor_name, force):
    file_path = "{}/monitors/{}.yaml".format(
        Config.get("var_dir"), monitor_name
    )

    if os.path.isfile(file_path) and not force:
        raise ArgumentError(
            "A monitor with name '{}' already exists. Use the "
            "--force argument if you really want to erase its "
            "configuration.".format(monitor_name)
        )

    answer = raw_input("Do you want help comments to be removed "
                       "from the new monitor's config template? [yes/NO] ")

    show_doc = answer.lower() != "yes"

    tpl = build_monitor_cfg_tpl(show_doc=show_doc)

    try:
        with open(file_path, "w") as monitor_file:
            monitor_file.write(tpl)
    except Exception as e:
        raise ProgramError(
            "Can't write monitor file {}: {}".format(file_path, e)
        )


def edit_monitor(name, ask=True):
    if ask:
        ask = ("Do you want to open this monitor's config in the "
               "default text editor [yes/NO]: ")
    else:
        ask = None

    file_path = "{}/monitors/{}.yaml".format(
        Config.get("var_dir"), name
    )

    return edit_file(file_path, ask)


def check_monitor_cfg(name, verbose):
    try:
        monitor = Monitor(name)
        if verbose:
            monitor.display()
        else:
            print("OK")
        return True
    except MissingFileError:
        raise
    except RIPEAtlasMonitorError as e:
        print("ERROR: {}".format(str(e)))
        return False


def check_monitor_cfg_loop(name, verbose):
    while not check_monitor_cfg(name, verbose):
        if not edit_monitor(name):
            return False
    return True


def execute(args):
    if args.command == "init-monitor":
        init_monitor_cfg_file(args.monitor_name, args.force)
        print("Monitor configuration initialized.")

        if edit_monitor(args.monitor_name):
            check_monitor_cfg_loop(args.monitor_name, False)

    elif args.command == "check-monitor":
        if args.silent:
            if check_monitor_cfg(args.monitor_name, args.verbose):
                return 0
            else:
                return 1
        else:
            check_monitor_cfg_loop(args.monitor_name, args.verbose)

    elif args.command == "edit-monitor":
        edit_monitor(args.monitor_name, ask=False)
        check_monitor_cfg_loop(args.monitor_name, args.verbose)

    else:
        raise NotImplementedError()
