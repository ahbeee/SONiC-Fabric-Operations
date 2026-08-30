from collector.platform import parse_platform_inventory


def test_parse_system_eeprom_with_namespaced_fields():
    records = {
        "/openconfig-platform:components/component/component[name=System Eeprom]/state": {
            "description": "x86_64-example-r0",
            "serial-no": "SN123",
            "openconfig-platform-ext:base-mac-address": "00:11:22:33:44:55",
            "software-version": "4.6.0",
        }
    }
    assert parse_platform_inventory(records) == {
        "description": "x86_64-example-r0", "serial_number": "SN123",
        "base_mac": "00:11:22:33:44:55", "software_version": "4.6.0",
    }
