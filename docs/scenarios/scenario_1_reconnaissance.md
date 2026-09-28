# Scenario 1: Reconnaissance

## Overview

| Field | Value |
|---|---|
| **Tactic** | Collection |
| **Techniques** | [T0802 - Automated Collection](https://attack.mitre.org/techniques/T0802/), [T0861 - Point & Tag Identification](https://attack.mitre.org/techniques/T0861/) |
| **Target** | Wildcat Dam Modbus TCP server, :5020 |
| **Impact** | None - read-only operations only |

## Objective

Scan the dam controller and enumerate every coil, discrete input, and register
it exposes, without issuing a single write. Modbus has no authentication, so
an attacker on the network can build a complete point map of the door
controls, reduction rates, and thresholds using only standard read function
codes.

## Fact Variables

| Fact | Description | Type | Default |
|------|-------------|------|---------|
| `modbus.server.ip` | IP address of the dam controller | string | `127.0.0.1` |
| `modbus.server.port` | Modbus TCP port | int | `5020` |
| `modbus.read_coil.start` | First coil address to read | int | `0` |
| `modbus.read_coil.count` | Number of coils to read | int | `6` |
| `modbus.read_discrete.start` | First discrete input address to read | int | `0` |
| `modbus.read_discrete.count` | Number of discrete inputs to read | int | `1` |
| `modbus.read_holding.start` | First holding register address to read | int | `0` |
| `modbus.read_holding.count` | Number of holding registers to read | int | `7` |
| `modbus.read_input.start` | First input register address to read | int | `0` |
| `modbus.read_input.count` | Number of input registers to read | int | `2` |

## Caldera Operation

Load `docs/sources/wildcat_dam_facts.yml` as the fact source, then build an
operation using the following abilities in order:

| Step | Ability | Ability ID | Facts Used |
|------|---------|------------|------------|
| 1 | Modbus - Read Coils | `d80b9cd5-b1d8-482a-a745-71d74f9d0885` | `modbus.server.ip`, `modbus.server.port`, `modbus.read_coil.start`, `modbus.read_coil.count` |
| 2 | Modbus - Read Discrete Inputs | `001e21ea-61b5-4b78-b79e-9d5687d819bd` | `modbus.server.ip`, `modbus.server.port`, `modbus.read_discrete.start`, `modbus.read_discrete.count` |
| 3 | Modbus - Read Holding Registers | `bc8961a2-7534-4b2a-bbc3-2456f58243be` | `modbus.server.ip`, `modbus.server.port`, `modbus.read_holding.start`, `modbus.read_holding.count` |
| 4 | Modbus - Read Input Registers | `3946b6da-c570-47cd-b63f-c13875297cb4` | `modbus.server.ip`, `modbus.server.port`, `modbus.read_input.start`, `modbus.read_input.count` |
| 5 | Modbus - Scan Device | `7f43fa44-c2aa-4bb6-ba4b-2c1e58df3b51` | `modbus.server.ip`, `modbus.server.port` |

Scan Device is repeatable and ordered last: under the atomic planner a
repeatable ability is never marked complete, so placing it before the
single-shot reads starves them and the operation never reaches step 2.

## Expected Observations

Verified against a live run (docker stack, real Modbus plugin, real agent):

- Step 1: coils 0-5 read back `ON,OFF,OFF,OFF,OFF,OFF` - door_1 open, doors 2-3 closed, all three overrides off (T0861).
- Step 2: the single discrete input reads `ON` - water is being released (door_1 open).
- Step 3: holding registers 0-6 read `40,1,3,6,60,75,85` - `close_level`, the three `reduction_rates`, and the three `thresholds`, matching `config.yaml`'s defaults exactly (T0861).
- Step 4: input registers 0-1 read the live `water_level`/`surge` (`75,3` in this run - water level drifts tick to tick since the sim is running).
- Step 5: device scan connects with no authentication and enumerates all four register types in one pass (T0802). Being repeatable, it keeps re-running - stop the operation once you've seen one successful scan.
- No writes occur; the HMI's `/update` values are unaffected by the operation (only the sim's own control loop changes them).

## See Also

- [Caldera for OT](https://github.com/mitre/caldera-ot)
- [Modbus plugin](https://github.com/mitre/modbus)
- [ATT&CK for ICS - T0802](https://attack.mitre.org/techniques/T0802/)
- [ATT&CK for ICS - T0861](https://attack.mitre.org/techniques/T0861/)
