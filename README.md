![pipeline status][img_pipeline_status]
![test coverage][img_test_coverage]

# Introduction

This tool is designed to make it easy to signature potentially unique parts of RTF files.

It was written by David Cannings (@edeca) and released by PwC UK under the Apache 2.0 license.  

To install, you'll need Python 3 and some basic libraries. These are handled automatically if you install using `pip`:

    $ pip install rtfsig

Then run like:

    $ rtfsig -f badfile.rtf -y output.yar

This will scan the file for potentially unique RTF tags, print details to screen and save a Yara rule to `output.yar`.

Please raise bugs as Github issues, and note this tool is in beta.

# Output

## Console

Basic output is shown on the console, which can be used to search VirusTotal (try a search like `content:rsid7043998`).

    -> % rtfsig -f 0b06052d3b5954594cf0e28bd9c50d9110eb8fb78cb78c9a99686eb4ba3391df.hostile
    INFO:root:Starting to parse file 0b06052d3b5954594cf0e28bd9c50d9110eb8fb78cb78c9a99686eb4ba3391df.hostile
    INFO:root:Non-standard RTF magic marker, should be {\rtf1, often a sign of malicious docs
    INFO:root:Found an RSID table in this document
    INFO:root:Found 1 embedded image(s) with set height/width
    INFO:root:Found 2 document information group tags
    INFO:root:Interesting strings (higher chance of FP): \rsid7043998, \rsid7476075, insrsid7043998, \rsid10243744, \rsid7604251, insrsid10243744, {\author blue}, rsidroot10243744, \rsid9200135, tblrsid10243744, charrsid10243744, \picw1\pich1\picwgoal1\pichgoal1 , pararsid10243744, \rsid7238080, insrsid7476075, \rsid11666446, insrsid12343406, \rsid12343406, {\operator blue}
    INFO:root:Found some unique strings!  Consider using vtgrep or deploying Yara rules

Debug output can be generated using `-v` which is helpful if you are reporting a bug.

## Yara rules

The tool will automatically generate Yara rules if the `-y` option is passed.  Two Yara rules are created, one which should generate low false positives (`strict_rule`) and one which may have a higher false positive rate (`loose_rule`).

It is recommended to review strings carefully and to change `any of them` to a sensible number, for example `3 of them`.

An example rule generated from `0b06052d3b5954594cf0e28bd9c50d9110eb8fb78cb78c9a99686eb4ba3391df` looks like:

    rule loose_rule {
      meta:
        description = "RTF file matching known unique identifiers (higher chance of FP, adjust 'any of them' if required)"
        generated_by = "rtfsig version 0.0.2"

      strings:
        $ = "{\\author blue}" ascii
        $ = "\\rsid7238080" ascii
        $ = "pararsid10243744" ascii
        $ = "insrsid7043998" ascii
        $ = "\\rsid7043998" ascii
        $ = "rsidroot10243744" ascii
        $ = "\\rsid9200135" ascii
        $ = "\\rsid7604251" ascii
        $ = "insrsid7476075" ascii
        $ = "\\rsid10243744" ascii
        $ = "insrsid12343406" ascii
        $ = "{\\operator blue}" ascii
        $ = "insrsid10243744" ascii
        $ = "charrsid10243744" ascii
        $ = "\\rsid11666446" ascii
        $ = "\\rsid12343406" ascii
        $ = "\\picw1\\pich1\\picwgoal1\\pichgoal1 " ascii
        $ = "tblrsid10243744" ascii
        $ = "\\rsid7476075" ascii

      condition:
        uint32be(0) == 0x7b5c7274 and any of them
    }

    rule strict_rule {
      meta:
        description = "RTF file matching known unique identifiers (lower chance of FP)"
        generated_by = "rtfsig version 0.0.2"

      strings:
        $ = "\\rsid7043998\\rsid7238080\\rsid7476075\\rsid7604251\\rsid9200135\\rsid10243744\\rsid11666446\\rsid12343406" ascii

      condition:
        uint32be(0) == 0x7b5c7274 and any of them
    }
    
# Known limitations

* At present, documents containing lots of obfuscation (e.g. comments between control words and their values) may 
not be parsed correctly. Please raise an issue with sample files for further inspection.

# Contributing

To setup a development environment, clone the git repository and run the following inside a virtualenv:

    $ pip install -e ".[dev]"

Before submitting a pull request, please check all tests pass and there is 100% coverage of the core module.

This is as simple as running tox and checking the output:

    $ tox
    .. tool output ..
    
    py37: commands succeeded
    congratulations :)

# Version history

* v0.0.1 (18th October 2019) - Initial version, supports RSID control words and generating Yara rules
* v0.0.2 (23rd October 2019) - Second beta, added support for unique image identifiers and document information
* v0.0.3 (23rd October 2019) - Third beta, added support for picture sizes
* v0.1.0 (19th September 2020) - First public release, packaged as a Python module for PyPI

[img_pipeline_status]: https://gitlab.com/cto-uk/python-modules/rtfsig/badges/master/pipeline.svg
[img_test_coverage]: https://gitlab.com/cto-uk/python-modules/rtfsig/badges/master/coverage.svg
