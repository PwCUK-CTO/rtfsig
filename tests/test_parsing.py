"""
Test cases to ensure core functionality is working correctly.
"""
import pytest
from rtfsig.core import RtfAnalyser, ParsingException

""" Sample data, these are meant to test the parsing and not represent valid RTF documents """
DOC_MINIMAL = b"{\\rtf1}"
DOC_AS_STRING = "{\\rtf1}"
DOC_INVALID_HEADER = b"{\\rxf1}"
DOC_MODIFIED_HEADER = b"{\\rtXY"
DOC_BINARY = b"{\\rtf1}\x13\x37"
DOC_INFO_GROUP = (
    b"{\\rtf1}{\\info{\\title My first document}{\\author edeca}{\\operator Neo}}"
)
DOC_PICTURE = b"{\\rtf1}{\\pict{\\*\\picprop}\\wmetafile8\\picw10\\pich10\\picwgoal10\\pichgoal10 0011}"
DOC_BLIPTAG = b"{\\rtf1}\\bliptag-1234567890\\blipupi-111{\\*\\blipuid 0011223344556677889900aabbccddeeff}"
DOC_INVALID_BLIPTAG = b"{\\rtf1}\\bliptag-nope"
DOC_INVALID_BLIPUID = b"{\\rtf1}\\blipuid zzzz"
DOC_REVISION_TABLE = b"{\\rtf1}{\\*\\rsidtbl \\rsid1234\\rsid5678}"
DOC_REVISION_TAGS = b"{\\rtf1}{\\*\\rsidtbl \\rsid1234\\rsid5678}\\pard \\pararsid1234"
DOC_INVALID_REVISION_TAG = (
    b"{\\rtf1}{\\*\\rsidtbl \\rsid1234\\rsid5678}\\pard \\pararsid9012"
)


def test_invalid_arguments():
    with pytest.raises(ValueError):
        _ = RtfAnalyser()


def test_minimal_document():
    _ = RtfAnalyser(data=DOC_MINIMAL)


def test_string_argument():
    with pytest.raises(TypeError):
        _ = RtfAnalyser(data=DOC_AS_STRING)


def test_file_argument(tmp_path):
    """
    Ensure the module can correctly parse a document from a filename.
    """
    filename = tmp_path / "test.rtf"
    filename.write_text(DOC_MINIMAL.decode("ascii"))
    _ = RtfAnalyser(filename=filename)


def test_invalid_document():
    with pytest.raises(ParsingException):
        _ = RtfAnalyser(data=DOC_INVALID_HEADER)


def test_modified_header():
    """
    Check the parser correctly handles documents with non-printable bytes, and raises an
    appropriate warning in the results.
    """
    parser = RtfAnalyser(data=DOC_MODIFIED_HEADER)
    assert "OBS002" in parser.results["observations"]


def test_binary_document():
    """
    Check the parser correctly handles documents with non-printable bytes, and raises an
    appropriate warning in the results.
    """
    parser = RtfAnalyser(data=DOC_BINARY)
    assert "OBS001" in parser.results["observations"]


def test_info_group():
    """
    Check that document information metadata is correctly parsed.
    """
    parser = RtfAnalyser(data=DOC_INFO_GROUP)
    assert "OBS005" in parser.results["observations"]
    assert "{\\author edeca}" in parser.results["loose_strings"]


def test_picture():
    """
    Check that pictures with a fixed size are correctly parsed.
    """
    parser = RtfAnalyser(data=DOC_PICTURE)
    assert "OBS004" in parser.results["observations"]
    assert "\\picw10\\pich10\\picwgoal10\\pichgoal10" in parser.results["loose_strings"]


def test_bliptag():
    """
    Check that pictures with a unique identifier are correctly parsed.
    """
    parser = RtfAnalyser(data=DOC_BLIPTAG)
    assert "OBS006" in parser.results["observations"]
    assert "0011223344556677889900aabbccddeeff" in parser.results["loose_strings"]
    assert "bliptag-1234567890" in parser.results["loose_strings"]


def test_invalid_bliptag():
    """
    Check that invalid bliptags are silently ignored (a message is printed). This behaviour may
    change in a future version to raise an exception.
    """
    _ = RtfAnalyser(data=DOC_INVALID_BLIPTAG)


def test_invalid_blipuid():
    """
    Check that invalid blipuids are silently ignored (a message is printed). This behaviour may
    change in a future version to raise an exception.
    """
    _ = RtfAnalyser(data=DOC_INVALID_BLIPUID)


def test_revision_table():
    """
    Check that invalid blipuids are silently ignored (a message is printed). This behaviour may
    change in a future version to raise an exception.
    """
    parser = RtfAnalyser(data=DOC_REVISION_TABLE)
    assert "OBS007" in parser.results["observations"]
    assert "\\rsid1234" in parser.results["loose_strings"]
    assert "\\rsid5678" in parser.results["loose_strings"]


def test_revision_tags():
    """
    Check that invalid blipuids are silently ignored (a message is printed). This behaviour may
    change in a future version to raise an exception.
    """
    parser = RtfAnalyser(data=DOC_REVISION_TAGS)
    assert "pararsid1234" in parser.results["loose_strings"]


def test_invalid_revision_tags():
    """
    Check that invalid blipuids are silently ignored (a message is printed). This behaviour may
    change in a future version to raise an exception.
    """
    parser = RtfAnalyser(data=DOC_INVALID_REVISION_TAG)
    assert "OBS003" in parser.results["observations"]
