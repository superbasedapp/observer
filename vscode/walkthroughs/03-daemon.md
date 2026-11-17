# Pick a daemon mode

The extension can either **use** a daemon you already started
in a terminal, or **manage** the daemon's lifecycle on your behalf.
Pick one via the `observer.daemon.mode` setting:

| Mode | What happens |
|---|---|
| **`detect`** | Use a running daemon only. Never spawn. If no daemon is running, the status bar shows "SuperBased idle" and you start one yourself with `observer start`. |
| **`managed`** | The extension spawns `observer start` on activation and kills it on shutdown. Refuses to spawn a second daemon when one is already running (safety rail). |
| **`auto`** (default) | If a daemon is running, use it. Otherwise spawn one, with the same supervision as `managed`. |

### Recommendation

Most people **leave the default `auto`**: the editor starts the daemon
when none is running and uses yours when you started one yourself.

If you always run `observer start` in a tmux pane or a separate
terminal and never want the editor to start one, pick **`detect`**.

### Crash recovery

In `managed` and `auto` modes, the extension restarts the daemon
with backoff `[1 s, 2 s, 5 s]` if it exits unexpectedly. After
three failed restarts a notification offers **Open Output Channel**
/ **Retry**.
