"""
Utility module that uses Jinja2 to generate Yara rules from a basic template.
"""
from jinja2 import Template
from . import VERSION_STRING


RULE_TEMPLATE = """
rule {{ rule_name }} {
  meta:
    description = "{{ description }}"
    generated_by = "rtfsig version {{ version }}"

  strings:
    {% for string in strings -%}
    $ = "{{ string }}" ascii
    {% endfor %}
  condition:
    uint32be(0) == 0x7b5c7274 and any of them
}

"""


def generate_yara_rule(name: str, description: str, strings: list) -> str:
    """
    Generate the text for a Yara rule using the Jinja2 templating engine.

    Args:
        name: the rule name to generate
        description: metadata to add to the rule
        strings: a list of strings to add to this rule.

    Returns:
        A string containing a Yara rule
    """
    template = Template(RULE_TEMPLATE)

    safe_strings = []
    for string in strings:
        # Replace backslash and double quotes to ensure valid rules
        string = string.replace("\\", "\\\\")
        string = string.replace('"', '\\"')
        safe_strings.append(string)

    args = {
        "rule_name": name,
        "description": description,
        "strings": safe_strings,
        "version": VERSION_STRING,
    }
    return template.render(args)
