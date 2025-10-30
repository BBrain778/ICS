import "pe"

rule Modbus_Read_Write_last180
{
    meta:
        description = "Detects Modbus read/write behavior limited to PE/ELF binaries and common script types (exe/dll/sys/elf/so/ps1/bat/cmd/vbs/sh/py/pl)"
        date = "2025-10-30"
        reference = "MITRE ATT&CK T0806, T0836, T0801, T0869"
        protocol = "Modbus TCP/RTU"
        severity = "medium"

    strings:
        /* Libraries and SDKs */
        $lib_modbus   = "libmodbus" nocase
        $lib_pymodbus = "pymodbus" nocase
        $lib_goburrow = "github.com/goburrow/modbus" nocase

        /* CLI tools / utilities */
        $cmd_modpoll  = "modpoll" nocase
        $cmd_mdpoll   = "mdpoll" nocase
        $cmd_modscan  = "modscan" nocase

        /* Common Modbus function calls */
        $func_read_coils               = "read_coils" nocase
        $func_read_holding_registers   = "read_holding_registers" nocase
        $func_write_single_coil        = "write_single_coil" nocase
        $func_write_single_register    = "write_single_register" nocase
        $func_write_multiple_registers = "write_multiple_registers" nocase
        $func_read_input_registers     = "read_input_registers" nocase
        $func_modbus_write             = "modbus_write" nocase
        $func_modbus_read              = "modbus_read" nocase

        /* Modbus function codes (FC) */
        $fc03 = { 03 }   // Read Holding Registers
        $fc06 = { 06 }   // Write Single Register
        $fc10 = { 10 }   // Write Multiple Registers

        /* shebang for scripts */
        $shebang = "#!" ascii

    condition:
        (
            /* ---- File type restriction ---- */
            pe.is_pe or                           /* Windows PE (exe/dll/sys) */
            uint16(0) == 0x5A4D or                /* 'MZ' header (PE fallback) */
            uint32(0) == 0x7F454C46 or            /* ELF magic (\x7F 'ELF') */
            uint32(0) == 0xFEEDFACE or            /* Mach-O 32-bit */
            uint32(0) == 0xFEEDFACF or            /* Mach-O 64-bit */
            uint32(0) == 0xCEFAEDFE or            /* Mach-O swapped */
            uint32(0) == 0xCAFEBABE or            /* Java class or fat Mach-O */
            $shebang at 0                         /* script with #! */
        )
        and
        (
            /* ---- Modbus read/write behavior ---- */
            (
                any of ($lib_modbus, $lib_pymodbus, $lib_goburrow, 
                        $cmd_modpoll, $cmd_mdpoll, $cmd_modscan)
            )
            and
            (
                any of ($func_read_coils, $func_read_holding_registers, 
                        $func_read_input_registers,
                        $func_write_single_coil, $func_write_single_register,
                        $func_write_multiple_registers,
                        $func_modbus_write, $func_modbus_read)
                or any of ($fc03, $fc06, $fc10)
            )
        )
}
