# Applications

The **Apps** tab answers "which program on this PC talks to the
network, how much, and with whom?".

## Live or over a period

- **Live** aggregates the current connections table (the last ~60 s of
  activity): per application you get the session traffic, the current
  throughput, the number of distinct remote endpoints, the countries and
  the top domains.
- **1 h / 6 h / 24 h / 7 d / 30 d** query the [history](history.md)
  database instead, so you also see programs that are not running
  anymore.

Rows are sorted by traffic; the bar shows each app's share. The filter
box matches an app name, a domain or a country code (`US`, `FR`…).

## Drill down

Click a row to expand its connections:

- in **Live**, the list comes from the live table — click one to jump to
  the globe with that connection selected;
- in a period, the list comes from the history (top remote endpoints by
  bytes).

## Blocking an application

*Block* creates a Windows Firewall rule for the program's executable
(resolved from the running process). See [Firewall](firewall.md). Rows
whose program is already blocked show a red **blocked** badge.

Connections whose owner couldn't be resolved are grouped under
*(unknown process)* — typically inbound traffic to closed ports, or
system components.
