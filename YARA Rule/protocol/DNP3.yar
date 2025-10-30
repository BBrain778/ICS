import "pe"

rule DNP3_Read_Write_last365
{
    meta:
        description = "Detects DNP3 read/write/select/operate behavior using structural multi-byte patterns instead of single-byte codes."
        author = "Emlyn Research"
        date = "2025-10-30"
        protocol = "DNP3 (IEEE-1815)"
        severity = "medium"

    strings:
        /* DNP3 Libraries / APIs */
        $lib_opendnp3   = "opendnp3" nocase
        $lib_pydnp3     = "pydnp3" nocase
        $lib_dnp3       = "libdnp3" nocase
        $vendor_auto    = "automatak" nocase

        /* Function-related strings */
        $str_select     = "SelectBeforeOperate" nocase
        $str_operate    = "operate" nocase
        $str_outstation = "outstation" nocase
        $str_master     = "master" nocase

        /* DNP3 Application Layer frame patterns (multi-byte context) */
        $fc_read   = { 05 64 ?? ?? ?? ?? 01 }   // Start+Header+FunctionCode=Read
        $fc_write  = { 05 64 ?? ?? ?? ?? 02 }   // Write
        $fc_operate= { 05 64 ?? ?? ?? ?? 04 }   // Operate

    condition:
        (
            /* File type restriction: compiled executables only */
            pe.is_pe or
            uint16(0) == 0x5A4D or
            uint32(0) == 0x7F454C46 or
            uint32(0) == 0xFEEDFACE or
            uint32(0) == 0xFEEDFACF
        )
        and
        (
            ( any of ($lib_*) or any of ($vendor_auto) )
            and
            ( any of ($str_*) or any of ($fc_*) )
        )
}
