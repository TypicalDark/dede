<!-- SPDX-License-Identifier: Apache-2.0 -->
# Capture & MITM — a Wireshark / Charles analog for an emulated target

## How the real tools work

- **Wireshark** taps a network interface (libpcap / a kernel BPF filter), records
  frames into a capture buffer, and runs a stack of **dissectors** that decode each
  frame layer by layer (Ethernet → IP → TCP → HTTP). You get a filterable,
  exportable (pcap/JSON) timeline of traffic. It is passive — capture only.
- **Charles / mitmproxy / Fiddler** are *man-in-the-middle* HTTP(S) proxies. The
  client is pointed at the proxy; the proxy terminates TLS with **its own CA** that
  the client is made to trust, so it can read and **rewrite** requests and
  responses, throttle, breakpoint, and replay them. It is active — intercept and
  edit.

Both share one shape: **tap a stream → record → dissect → filter → (optionally)
modify / replay.**

## The honest mapping onto dede

dede runs flat x86-64 with no OS or network stack, so there is no wire to sniff.
The equivalent observable boundary is the guest's **external-interaction surface**:
on Linux that is overwhelmingly **syscalls** — and the network *is* syscalls
(`socket`/`connect`/`sendto`/`recvfrom`/`read`/`write`) — plus CPU probes
(`cpuid`/`rdtsc`) and port I/O. dede already emits an `Event` for each of these
through its Observer bus, and already has a replay-safe way to change guest state
(the injected-event log). So the tap and the MITM fall out of existing machinery:

| Real tool concept | dede realisation |
|---|---|
| Interface tap / BPF | `CaptureTap` — an Observer on the event bus |
| Frame record | `CaptureEntry` per syscall/probe, with the arg registers captured |
| Dissector | `syscall_name()` + arg rendering (network calls recognised) |
| Filter | by kind / number (and the `capture` shell command) |
| Export (pcap/JSON) | `CaptureTap::to_text()` / `to_json()` |
| MITM breakpoint | a `Syscall` run point (optionally filtered by number) |
| Rewrite request/response | a mutating macro on that run point edits args / `rax` |
| Deterministic replay of an edited session | the edit is logged as an injected event |

### What ships today

- `CaptureTap` records syscalls (with SysV argument registers), `cpuid`, and
  `rdtsc`, dissecting syscall numbers to names including the network family.
- Shell: `capture on|off|clear|list`; JSON/text export in the API.
- MITM: `RunPointType::Syscall` + a mutating macro rewrites arguments or the
  return value; because it goes through the injected-event log, the modified run
  **replays deterministically** — something a live proxy cannot offer.
- Covered by `tests/test_capture.cpp` and effectiveness test 42.

### Roadmap (to a full Wireshark/Charles experience)

1. **Syscall semantic layer.** Model `socket`/`connect`/`sendto`/`recvfrom` against
   a virtual network so payload buffers (pointer + length in the arg registers) are
   captured and shown, not just the call. This is the "frame bytes" of the capture.
2. **Protocol dissectors.** Decode captured buffers as HTTP/DNS/TLS-record the way
   Wireshark layers dissectors; render a HAR-like view for HTTP.
3. **A GUI capture panel** (the "packet list / detail / bytes" three-pane layout)
   over `capture_log()`, with filtering and a flow/timeline view tied to the
   time-travel scrubber — scrub the timeline, watch the capture replay.
4. **TLS-MITM analog.** If a guest links a TLS library, intercept the plaintext at
   the `read`/`write` boundary (the same place Charles sits, one layer in) rather
   than breaking crypto — and, since execution is deterministic and reversible, do
   it with time-travel instead of a live proxy.
5. **Real pcap export** of the modelled network traffic, so captures open in actual
   Wireshark.

The tap and the MITM boundary are in place now; the roadmap is about richer
dissection and a dedicated GUI panel on top of them.
