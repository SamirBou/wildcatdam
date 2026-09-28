# Scenario 2: Manual Override

## Overview

| Field | Value |
|---|---|
| **Tactic** | Impair Process Control, Collection |
| **Techniques** | [T0836 - Modify Parameter](https://attack.mitre.org/techniques/T0836/), [T0861 - Point & Tag Identification](https://attack.mitre.org/techniques/T0861/) |
| **Target** | Wildcat Dam Modbus TCP server, :5020 |
| **Impact** | Door 1 forced open regardless of water level; door 2's auto-open threshold tampered so it stays open across a much wider, abnormal band of water levels |

## Objective

Seize manual control of door 1 by flipping its override-enable coil, then
force the door open independent of `control_doors()`'s hysteresis logic.
Separately, rewrite door 2's auto-open threshold to an abnormally low value
via a holding register write - door 2 is never touched by an override, but
with its threshold slammed to 5 it now opens (and stays open) far below the
water level an operator would expect. Both writes are accepted with no
authentication.

## Control Data

Coil and register addresses on the wire are zero-based; `config.yaml`'s
1-based `addr` values are one higher (`config.yaml addr = wire address + 1`).

| Control | config.yaml | Wire Address | Value |
|---|---|---|---|
| door_1.override_enable | coil addr 4 | 3 | ON (1) |
| door_1.position | coil addr 1 | 0 | ON (1) |
| threshold_2 | holding register addr 6 | 5 | 5 |

## Fact Variables

| Fact | Description | Type | Default |
|------|-------------|------|---------|
| `modbus.server.ip` | IP address of the dam controller | string | `127.0.0.1` |
| `modbus.server.port` | Modbus TCP port | int | `5020` |
| `modbus.read_coil.start` / `.count` | Baseline/verify coil read range | int | `0` / `6` |
| `modbus.read_holding.start` / `.count` | Baseline/verify holding register read range | int | `0` / `7` |
| `modbus.write_coil.start` | Coil address to write | int | `3`, `0` |
| `modbus.write_coil.value` | Value for a single coil write | string | `ON` |
| `modbus.write_register.start` | Holding register address to write | int | `5` |
| `modbus.write_register.value` | Value for a single register write | int | `5` |

## Caldera Operation

Load `docs/sources/wildcat_dam_facts.yml` as the fact source, then build an
operation using the following abilities in order:

| Step | Ability | Ability ID | Facts Used |
|------|---------|------------|------------|
| 1 | Modbus - Read Coils | `d80b9cd5-b1d8-482a-a745-71d74f9d0885` | baseline: `read_coil.start=0`, `read_coil.count=6` |
| 2 | Modbus - Write Single Coil | `056e6289-4cbf-417f-928a-d75125e4db4f` | `write_coil.start=3`, `write_coil.value=ON` (door_1 override enable) |
| 3 | Modbus - Write Single Coil | `056e6289-4cbf-417f-928a-d75125e4db4f` | `write_coil.start=0`, `write_coil.value=ON` (door_1 forced open) |
| 4 | Modbus - Write Single Register | `d6991b6b-d3b2-4398-ad3f-d736ae09acf9` | `write_register.start=5`, `write_register.value=5` (threshold_2 slammed low) |
| 5 | Modbus - Read Holding Registers | `bc8961a2-7534-4b2a-bbc3-2456f58243be` | verify: `read_holding.start=0`, `read_holding.count=7` |

There's no coil re-read step: Caldera treats a link as a duplicate and never
schedules it if its generated command exactly matches an earlier link in the
same operation, so a second `Read Coils` with the same `start`/`count` as the
baseline never fires. Verify the coil-side effect with the HMI `/update`
endpoint or a raw Modbus read instead.

## Expected Observations

Verified against a live run (docker stack, real Modbus plugin, real agent):

- Step 1: baseline coil read - `ON,OFF,OFF,OFF,OFF,OFF` (door_1 already open from a prior auto cycle, override off).
- Step 2-3: both coil writes return "Write successful" with no authentication (T0836).
- Step 4: register write returns "Write successful".
- Step 5: holding registers read back `40,1,3,6,60,5,85` - register 5 (threshold_2) is now `5`, down from its default `75` (T0836).
- Independently confirmed with a raw Modbus read (bypassing Caldera): coil 0 (door_1 position) = ON, coil 3 (door_1 override_enable) = ON.
- Confirmed via the HMI `/update` endpoint: `threshold_2` reads `5` and `door_1` reads `1`.

## See Also

- [Caldera for OT](https://github.com/mitre/caldera-ot)
- [Modbus plugin](https://github.com/mitre/modbus)
- [ATT&CK for ICS - T0836](https://attack.mitre.org/techniques/T0836/)
- [ATT&CK for ICS - T0861](https://attack.mitre.org/techniques/T0861/)
