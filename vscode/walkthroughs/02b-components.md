# Choose components

Observer is built from components: one capture adapter per AI tool,
the API proxy and its compression, terminals, code intelligence, the
team connection, telemetry export and more. **Settings > Components** in the
dashboard lists every one with what it adds to this machine: the ports
it listens on, the hosts it talks to, the files it writes and the other
tools' config files it edits.

- **Active**: it runs.
- **Installed, inactive**: the code is in this build but nothing runs:
  no listener, no network, no changes to your tools.
- **Not in this build**: this binary was built without it; the row
  names the builds that include it.

Every change shows a preview first (what becomes active, what becomes
inactive, and what Observer undoes in your tools' config) and only
applies after you confirm. Removing a component keeps its data unless
you also choose to delete it.

With no selection recorded, every component in this build stays
active, exactly as before. The same choices are available from a
terminal with `observer components status`, `observer components
select`, `add` and `remove`.
