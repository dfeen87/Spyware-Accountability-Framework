rule synthetic_spyware_example : mercenary_infrastructure {
    meta:
        description = "SYNTHETIC EXAMPLE: Detects characteristics of a mock mercenary spyware loader."
        author = "Spyware Accountability Framework"
        date = "2024-03-01"
        reference = "https://github.com/your-org/spyware-accountability-framework"
        warning = "THIS IS A SYNTHETIC RULE. DO NOT DEPLOY EXPECTING REAL DETECTIONS."
        version = "1.0"

    strings:
        // These are fake strings designed to mimic the structure of an obfuscated payload or C2 beacon.
        $domain1 = "c2.example-spyware.xyz" ascii wide
        $domain2 = "update.example-spyware.xyz" ascii wide

        // A mock hardcoded key or unique identifier string
        $mock_mutex = "Global\\FakeSpywareMutex_0xDEADBEEF" ascii wide

        // Example of detecting a specific, anomalous function call pattern (synthetic bytes)
        $suspicious_bytes = { E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 ?? 68 ?? ?? ?? ?? FF 15 }

    condition:
        // Look for the mock mutex OR both fake domains OR the suspicious byte pattern
        uint16(0) == 0x5A4D and // MZ header
        (
            $mock_mutex or
            ($domain1 and $domain2) or
            $suspicious_bytes
        )
}
