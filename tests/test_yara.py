"""
Test the Yara utility functions.
"""
import plyara
from rtfsig.yara import generate_yara_rule


def test_yara():
    """
    This test should pass with no exceptions if we are generating valid Yara rules. This is
    useful to ensure that future Yara versions work correctly with the tool.
    """
    strings = ["foo", "bar"]
    data = generate_yara_rule("test_rule", "This is a test rule", strings)

    parser = plyara.Plyara()
    rule = parser.parse_string(data)
    assert rule
