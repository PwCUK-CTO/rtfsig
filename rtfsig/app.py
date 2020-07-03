"""
This module is an example implementation of a console program which uses the core library.

It can be used standalone (the shell command 'rtfsig' is aliased to this script during
setup) or to demonstrate how to integrate rtfsig into another tool.
"""
import argparse
import logging
import sys
from typing import NoReturn
from . import VERSION_STRING
from .core import RtfAnalyser, OBSERVATIONS
from .yara import generate_yara_rule


def main() -> NoReturn:
    """
    Main method that obtains user arguments, sets up logging and calls the parser.
    """
    _configure_logging()
    args = _get_arguments()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        parser = RtfAnalyser(filename=args.rtf_file)

    except FileNotFoundError:
        logging.error("Couldn't open file %s", args.rtf_file)
        sys.exit(-1)

    logging.info("Starting to parse file %s", args.rtf_file)

    for reference in parser.results["observations"]:
        logging.info(OBSERVATIONS[reference])

    rules = []
    if parser.results["loose_strings"]:
        logging.info(
            "Interesting strings (higher chance of FP): %s",
            ", ".join(parser.results["loose_strings"]),
        )
        rules.append(
            generate_yara_rule(
                "loose_rule",
                "RTF file matching known unique identifiers (higher chance of FP, adjust 'any of them' if required)",
                parser.results["loose_strings"],
            )
        )

    if parser.results["strict_strings"]:
        logging.debug(
            "Interesting strings (lower chance of FP): %s",
            ", ".join(parser.results["strict_strings"]),
        )
        rules.append(
            generate_yara_rule(
                "strict_rule",
                "RTF file matching known unique identifiers (lower chance of FP)",
                parser.results["strict_strings"],
            )
        )

    if rules:
        logging.info(
            "Found some unique strings!  Consider using vtgrep or deploying Yara rules"
        )
        if args.yara:
            _save_yara_rules(args.yara, rules)

    else:
        logging.info(
            "Did not find anything unique to signature, check the document for unique parts which have been missed"
        )


def _save_yara_rules(filename: str, rules: str) -> NoReturn:
    """
    Utility function to

    Args:
        filename: the file to save rule data to
        rules: raw Yara rule data
    """
    with open(filename, "w") as fh:
        fh.write("".join(rules))


def _configure_logging() -> NoReturn:
    """
    Set up logging with a basic level of INFO.
    """
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)


def _get_arguments() -> argparse.Namespace:
    """
    Parses command line options and returns the output of argparse.

    Returns:
        The argparse Namespace containing user options.
    """

    description = (
        "Examine RTF documents for artefacts that can be used to hunt similar files.\n\n"
        "This is rtfsig version {}, by David Cannings (@edeca).".format(VERSION_STRING)
    )

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-f", "--rtf-file", help="RTF file to analyse", required=True)
    parser.add_argument(
        "-x",
        "--exclude-risky",
        help="Exclude riskier items, e.g. the information group (default: all items included)",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "-y",
        "--yara",
        help="Write Yara rules to file (default: not written)",
        default=None,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="print more debugging messages to screen",
        action="store_true",
    )

    return parser.parse_args()


if __name__ == "__main__":
    main()
