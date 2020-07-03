
rule loose_rule {
  meta:
    description = "RTF file matching known unique identifiers (higher chance of FP, adjust 'any of them' if required)"
    generated_by = "rtfsig version 0.0.3"

  strings:
    $ = "\\rsid11344222" ascii
    $ = "insrsid2828354" ascii
    $ = "\\rsid2828354" ascii
    $ = "rsidroot2828354" ascii
    $ = "sectrsid5596333" ascii
    $ = "\\rsid5207222" ascii
    $ = "insrsid5596333" ascii
    $ = "\\rsid5596333" ascii
    $ = "insrsid5207222" ascii
    $ = "{\\title Korean}" ascii
    
  condition:
    uint32be(0) == 0x7b5c7274 and any of them
}

rule strict_rule {
  meta:
    description = "RTF file matching known unique identifiers (lower chance of FP)"
    generated_by = "rtfsig version 0.0.3"

  strings:
    $ = "\\rsid2828354\\rsid5207222\\rsid5596333\\rsid11344222" ascii
    
  condition:
    uint32be(0) == 0x7b5c7274 and any of them
}
