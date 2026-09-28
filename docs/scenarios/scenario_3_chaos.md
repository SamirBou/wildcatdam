# Scenario 3: Chaos

## Overview

| Field | Value |
|---|---|
| **Tactic** | Collection, Impair Process Control |
| **Techniques** | [T0861 - Point & Tag Identification](https://attack.mitre.org/techniques/T0861/), [T0806 - Brute Force I/O](https://attack.mitre.org/techniques/T0806/) |
| **Target** | Wildcat Dam Modbus TCP server, :5020 |
| **Impact** | Door coils and control registers overwritten with random values - operator can no longer trust the HMI or the process |

## Objective

Fuzz the dam's coils and holding registers with random values across their
defined ranges. Unlike the manual override scenario, this isn't a targeted
change - it corrupts door positions, override flags, reduction rates, and
thresholds indiscriminately. The result is a denial-of-view style effect: an
operator watching the HMI can no longer tell what the process is actually
doing, and the control logic reacts to garbage input on the next simulation
tick.

## Fact Variables

| Fact | Description | Type | Default |
|------|-------------|------|---------|
| `modbus.server.ip` | IP address of the dam controller | string | `127.0.0.1` |
| `modbus.server.port` | Modbus TCP port | int | `5020` |
| `modbus.read_coil.start` / `.count` | Baseline/verify coil read range | int | `0` / `6` |
| `modbus.read_holding.start` / `.count` | Baseline/verify holding register read range | int | `0` / `7` |
| `modbus.fuzz_coil.start` | First coil address to fuzz | int | `0` |
| `modbus.fuzz_coil.end` | Last coil address to fuzz | int | `5` |
| `modbus.fuzz_coil.count` | Number of random writes to issue | int | `10` |
| `modbus.fuzz_coil.wait` | Delay between writes (seconds) | float | `0.1` |
| `modbus.fuzz_register.start` | First holding register address to fuzz | int | `0` |
| `modbus.fuzz_register.end` | Last holding register address to fuzz | int | `6` |
| `modbus.fuzz_register.count` | Number of random writes to issue | int | `10` |
| `modbus.fuzz_register.min` | Minimum random register value | int | `0` |
| `modbus.fuzz_register.max` | Maximum random register value | int | `999` |
| `modbus.fuzz_register.wait` | Delay between writes (seconds) | float | `0.1` |

## Caldera Operation

Load `docs/sources/wildcat_dam_facts.yml` as the fact source, then build an
operation using the following abilities in order:

| Step | Ability | Ability ID | Facts Used |
|------|---------|------------|------------|
| 1 | Modbus - Read Coils | `d80b9cd5-b1d8-482a-a745-71d74f9d0885` | baseline: `read_coil.start=0`, `read_coil.count=6` |
| 2 | Modbus - Read Holding Registers | `bc8961a2-7534-4b2a-bbc3-2456f58243be` | baseline: `read_holding.start=0`, `read_holding.count=7` |
| 3 | Modbus - Fuzz Coils | `40f78a8f-2aaa-4b1b-872f-7c6b0f1ddf3e` | `fuzz_coil.start=0`, `fuzz_coil.end=5`, `fuzz_coil.count=10`, `fuzz_coil.wait=0.1` |
| 4 | Modbus - Fuzz Registers | `2a6e8c8e-f350-11ed-9156-23436b8f0e58` | `fuzz_register.start=0`, `fuzz_register.end=6`, `fuzz_register.count=10`, `fuzz_register.min=0`, `fuzz_register.max=999`, `fuzz_register.wait=0.1` |

There are no verify-read steps: Caldera treats a link as a duplicate and
never schedules it if its generated command exactly matches an earlier link
in the same operation, so a second `Read Coils`/`Read Holding Registers`
with the same `start`/`count` as the baseline reads never fires. Verify the
post-fuzz state with the HMI `/update` endpoint or a raw Modbus read instead.

## Expected Observations

Verified against a live run (docker stack, real Modbus plugin, real agent).
Baseline (steps 1-2): coils `ON,OFF,OFF,ON,OFF,OFF`, holding registers
`40,1,3,6,60,5,85`. After steps 3-4:

- Coils read back `OFF,ON,OFF,ON,ON,ON` (T0806) - door_1's position coil flipped off, and both remaining override-enable coils flipped on, none of it tied to actual water level.
- Holding registers read back `946,49,262,950,60,3,922` (T0806) - `close_level` (946) and `threshold_3` (922) are blown far outside their intended 0-100 range, and the reduction rates (49, 262, 950) are far outside their intended 0-10 range. `threshold_1` (60) happened not to get hit by this run's 10 random writes.
- Confirmed independently via the HMI `/update` endpoint: `water_level` reads `0`, `close_level` reads `946`, `threshold_3` reads `922`, `door_1` reads `false`.
- The dam's control loop runs `control_doors()` against these corrupted values on every tick - `water_level` itself was fuzzed to 0, so the whole process view on the HMI is no longer trustworthy.

## See Also

- [Caldera for OT](https://github.com/mitre/caldera-ot)
- [Modbus plugin](https://github.com/mitre/modbus)
- [ATT&CK for ICS - T0861](https://attack.mitre.org/techniques/T0861/)
- [ATT&CK for ICS - T0806](https://attack.mitre.org/techniques/T0806/)
