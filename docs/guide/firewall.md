# Firewall

Packet Eye can block an IP address, a range or an application with the
**Windows Firewall**. It only manages its own rules: they all belong to
the firewall group **“Packet Eye”**, so nothing else on the system is
touched, and you can always review them in *Windows Defender Firewall
with Advanced Security*.

!!! warning "Administrator rights"
    Creating, toggling or deleting rules requires the agent to run as
    Administrator (which it already needs for the capture). Listing works
    without.

## Blocking from anywhere

| Where | What |
|---|---|
| Connection details panel | *Block IP* (remote address), *Block app* (owner process). |
| Apps tab | *Block* on an application row. |
| History tab | Block button on each top connection. |
| Firewall tab | Manual form, and one-click blocking of flagged endpoints. |

Each time a dialog asks for the **direction** (outbound by default,
inbound, or both — which creates two rules) and an optional **note**,
stored in the rule description.

Safety checks: loopback and `0.0.0.0` can't be blocked (that would cut
the UI off from the agent), prefixes shorter than `/8` are refused, and
programs must be an existing absolute `.exe` path.

## The Firewall tab

- Counters of active / disabled rules and of IP vs application rules.
- The rule list with an **on/off switch** per rule (disabling keeps the
  rule for later), the target, the direction and the note, plus delete.
- **New block rule** — IP addresses / CIDRs (comma-separated) or an
  executable path.
- **Flagged this session** — remote IPs that raised medium/high/critical
  alerts since the page was opened, worst first, each with a *Block*
  button or a *blocked* badge.

Rules persist in Windows: they keep blocking after the agent stops or
the PC reboots. Blocked outbound traffic never reaches the network card,
so it disappears from the capture once the rule is active.

## How it works

The agent drives the built-in `NetSecurity` PowerShell module
(`New-NetFirewallRule`, `Get-NetFirewallRule`…), whose output isn't
localised, unlike `netsh`. Values you type are validated, then passed to
PowerShell through environment variables — never pasted into the script
— so there's no command-injection surface.
