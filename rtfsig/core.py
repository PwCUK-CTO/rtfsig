"""
The core of rtfsig, containing the RtfAnalyser class which is used to parse files and generate
a set of potentially unique strings.

Future versions should also investigate:

 * protusertbl (may contain username & domain info)
 * userprops (user defined document properties)
 * passwordhash (read-only password protection, match hashes across docs)
 * password (weak / deprecated version of passwordhash)
 * revtbl (older version of rsidtbl)
"""
import logging
import re
import string
from typing import NoReturn


OBSERVATIONS = {
    "OBS001": "File contains bytes outside ASCII printable range",
    "OBS002": "Non-standard RTF file marker found (expected \\rtf1)",
    "OBS003": "Change identifier found which is not in the RSID table (document likely modified)",
    "OBS004": "Document contains images with a fixed width/height",
    "OBS005": "Document contains information group tags",
    "OBS006": "Document contains image identifiers (bliptags)",
    "OBS007": "Document contains change tracking (RSID tags)",
}


class ParsingException(Exception):
    """
    Default exception raised when parsing an RTF fails, for example due to file validation.
    """


class RtfAnalyser:
    """
    The core class responsible for parsing RTF documents. A new object should be created for each
    file to be analysed.
    """

    def __init__(
        self, filename: str = None, data: bytearray = None, risky_items: bool = True
    ):
        self.results = {
            "loose_strings": set(),
            "strict_strings": set(),
            "observations": [],
        }
        self._risky_items = risky_items

        if filename is None and data is None:
            raise ValueError("Need one of filename or data")

        if filename:
            self._parse_file(filename)
        elif data:
            if not isinstance(data, bytes):
                raise TypeError("Expected data to be bytes")

            self._parse_data(data)

    def _parse_file(self, filename: str) -> NoReturn:
        """
        Internal function. Parse a single RTF document, validating it first and then extracting
        useful features.

        Args:
            filename: the RTF document to parse
        """

        # Open in binary mode and ignore errors, we are only interested in the
        # ASCII content of this file.  Characters outside ASCII codepoints are
        # invalid in RTF and not currently needed (we should add an observation).
        with open(filename, "rb") as fh:
            data = fh.read()

        self._parse_data(data)

    def _parse_data(self, data: bytearray) -> NoReturn:
        """
        Internal function. Parse a single RTF document from a bytearray.

        Args:
            data: the raw RTF document contents
        """
        if any([chr(x) not in string.printable for x in data]):
            self._add_observation("OBS001")

        self._data = data.decode("ascii", "ignore")

        if self._data[0:4] != "{\\rt":
            raise ParsingException(
                "This file does not look like an RTF, magic bytes don't validate"
            )

        if self._data[4:6] != "f1":
            # Check for any deviation from \rtf1, often used by malicious documents to evade really old
            # (or really terrible) security products.
            self._add_observation("OBS002")

        self._find_rsid_tags()
        self._find_blip_tags()
        self._find_image_sizes()
        if self._risky_items:
            self._find_information_group()

    def _add_observation(self, reference: str) -> NoReturn:
        """
        Add an observation about the current RTF document to the findings.

        Args:
            reference: the unique reference of the observation, e.g. OBS001
        """
        if reference not in OBSERVATIONS:  # pragma: no cover
            raise IndexError("Invalid observation identifier")

        self.results["observations"].append(reference)

    def _find_image_sizes(self):
        """
        Extract picw* and picw* tags, which are used to define the size of an image (including
        the scaled size).  The regex aims for the longest possible match, which should be more
        unique than individual strings (e.g. if we assume most images will be in the range
        1<N<4096 units).
        """

        found = 0
        for match in re.finditer(
            r"(?P<longest_match>(?:\\(?:picw|pich|picwgoal|pichgoal)\d+\s*)+)",
            self._data,
        ):
            logging.debug("Image size: %s", match.group("longest_match"))
            self.results["loose_strings"].add(match.group("longest_match").strip())
            found += 1

        if found:
            logging.debug("Found %d embedded image(s) with set height/width", found)
            self._add_observation("OBS004")

    def _find_information_group(self):
        """
        Search for the document information group, which is optional but may be added by some
        RTF generation applications.

        Note these matches may not be very unique, for example "{\\author user}".  Care is
        required if using these as the only match inside a document.
        """

        info_tags = [
            "title",
            "subject",
            "author",
            "manager",
            "category",
            "keywords",
            "operator",
            "company",
            "creatim",
            "revtim",
            "doccomm",
        ]
        tags = "|".join(info_tags)

        found = 0
        for match in re.finditer(
            r"(?P<whole_tag>{\s*\\(?:" + tags + r")\s+([^}]+)\s*})", self._data
        ):
            logging.debug("Document information tag: %s", match.group("whole_tag"))
            self.results["loose_strings"].add(match.group("whole_tag"))
            found += 1

        if found == 0:
            logging.debug("Did not find any document information group tags")
        else:
            self._add_observation("OBS005")
            logging.debug("Found %d document information group tags", found)

    def _find_blip_tags(self):
        """
        Find blip* tags, which store 32 bit signed integers to identify images.  These should
        be relatively unique.
        """

        if "bliptag" in self._data:
            found = 0
            for match in re.finditer(r"\\(?P<whole_tag>bliptag-?\d+)", self._data):
                logging.debug("Raw bliptag value is %s", match.group("whole_tag"))

                # TODO: Refactor into self._add_strings(..)
                self.results["loose_strings"].add(match.group("whole_tag"))
                found += 1

            if found == 0:
                logging.error(
                    "Found bliptag but could not parse the unique value, report a bug!"
                )
            else:
                logging.debug("Found %d bliptag tag(s) in this document", found)
                self._add_observation("OBS006")

        if "blipuid" in self._data:
            found = 0
            for match in re.finditer(
                r"\\(?P<whole_tag>blipuid\s+(?P<unique_id>[a-f0-9]+))", self._data
            ):
                logging.debug("Raw blipuid value is %s", match.group("unique_id"))

                self.results["loose_strings"].add(match.group("unique_id"))
                self.results["strict_strings"].add(match.group("whole_tag"))
                found += 1

            if found == 0:
                logging.error(
                    "Found blipuid but could not parse the unique value, report a bug!"
                )
            else:
                logging.debug("Found %d blipuid tag(s) in this document", found)

    def _find_rsid_tags(self):
        """
        Finds "revision save ID" tags (RSID) which are used to track changes to a document.
        """

        match = re.search(r"\\\*\\rsidtbl\s([^}]+)}", self._data)
        if match:
            logging.debug("Found an RSID table in this document")
            self._add_observation("OBS007")
            raw_data = match.group(1).strip()
            logging.debug("Raw RSID data is %s", raw_data)
            self.results["strict_strings"].add(raw_data)

            # TODO: Hash the raw RSID table and store (scalable document matching)

        else:
            logging.debug("Did not find an RSID table")
            # TODO: Some brute force checks here, e.g. search for the *rsid tags below
            return

        # Extract the unique markers from the RSID table
        revisions = []
        for match in re.finditer(
            r"(?P<whole_tag>\\rsid(?P<revision_id>\d+))", raw_data
        ):
            logging.debug("Found revision %s", match.group(1))
            revisions.append(match.group("revision_id"))
            self.results["loose_strings"].add(match.group("whole_tag"))

        # TODO: Check revisions are sequential, and evaluate whether this is always the case.

        # Extract each individual change marker
        change_markers = [
            "insrsid",
            "rsidroot",
            "delrsid",
            "charrsid",
            "sectrsid",
            "pararsid",
            "tblrsid",
        ]
        for marker in change_markers:
            for match in re.finditer(r"\\({})(\d+)".format(marker), self._data):
                control_word = match.group(1)
                unique_id = match.group(2)

                logging.debug("Found marker %s, change ID %s", control_word, unique_id)
                # If the change identifier is not in the RSID table then we've got some dodgy
                # parsing *or* the document has been modified manually after creation.
                if unique_id not in revisions:
                    self._add_observation("OBS003")
                    logging.debug(
                        "Found change ID %s (control word %s) that is not in the RSID table.  Potential bug or modified document",
                        unique_id,
                        control_word,
                    )

                self.results["loose_strings"].add(control_word + unique_id)
