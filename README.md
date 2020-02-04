# Brokkenpiloot

Brokkenpiloot is a tool that can replace bytes in the
virtual memory (including the code segment) of a
running Windows process with the intention of modifying
its behaviour.

Brokkenpiloot modifies the target process in-memory.
This means it does not harm the target binary on the
disk. This is also what allows Brokkenpiloot to turn
the patch on and off without relaunching the target
binary.

## History

Brokkenpiloot was written in 2019 as a proof-of-concept
tool that disabled presence checking in Fly UK's
Skytrack logging software for Prepar3d and X-Plane.

The virtual airline Fly UK requires flightsimmers to log
all their FlyUK flights with Skytrack, a software tool
which automatically records flight details such as
departure and arrival times, position data and fuel
consumption. On longer flights (2+ hours), Skytrack checks
to make sure virtual pilots are at their desks during the
whole flight by asking them to tune the aircraft
communication radios to a random frequency every 1-3 hours.

Brokkenpiloot disabled these checks by modifying a single
byte in the skytrack.exe process at the machine code level,
such that Skytrack would accept rather than reject incorrect
frequencies programmed in the radios. Because Brokkenpiloot
reversed Skytrack's checking logic, this also meant the
correct frequency would be rejected by Skytrack if both
radios accidentally happen to be tuned to it. The
statistical chance of this happening was small: around 1.2%
for an 18-hour flight and 0.6% for a 9-hour flight. The
risk could be eliminated entirely by making sure the
communication radios were not tuned to the same frequency.

Brokkenpiloot was written as an exercise in learning how to
reverse engineer Windows applications with IDA Free. As the
name "Brokkenpiloot" implies, using it in the real (virtual)
world would be questionable. The `TARGET_BYTES` and
`REPLACEMENT_BYTES` in the code have been changed to prevent
such use.
