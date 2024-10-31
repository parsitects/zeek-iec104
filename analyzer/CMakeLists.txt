spicy_add_analyzer(
    NAME iec104
    PACKAGE_NAME spicy-iec104
    SOURCES iec104.spicy iec104.evt
    SCRIPTS __load__.zeek iec104.zeek dpd.sig
)
