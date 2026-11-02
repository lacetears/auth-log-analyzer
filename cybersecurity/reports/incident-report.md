# Incident 001: Login failures followed by a successful login
**Classification:** synthetic exercise, not a real compromise or live SIEM result.

## Evidence and timeline (UTC)
- 2026-01-15 09:00–09:04: five failures for `demo` on `lab-linux`, source `192.0.2.10`.
- 09:04: the Python detector crosses the five-failure threshold.
- 09:05: successful authentication within the rolling five-minute window raises a high-priority investigation alert.
- The second host has one failed login followed by success and does not meet the threshold.

## Assessment
The pattern warrants investigation but does not prove credential compromise. A legitimate user mistyping a password can trigger it. The IP addresses are documentation addresses. The normalized dataset contains no process, geolocation, MFA, or endpoint evidence.

## Investigation and proposed response
Confirm the account owner and expected source, review authentication and session logs, correlate endpoint process activity, and check MFA evidence. If unauthorized access is confirmed, revoke sessions and reset credentials under the organization's response policy. Preserve original logs before changes. No actual containment was performed in this exercise.

## Tuning and limitations
The detector groups by host, source IP, and username. Distributed attacks, password spraying across users, and invalid-user SSH attempts need separate rules. A success resets that group's window. Duplicate input events can inflate counts. The Wazuh sample rule uses Wazuh's own correlation behavior and is not claimed to be equivalent to the Python rule.
