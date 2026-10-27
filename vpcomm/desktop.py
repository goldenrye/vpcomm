"""Native desktop interface, with a terminal fallback."""

import argparse
import asyncio
import getpass
import os
import queue
import sys
import threading

from .audio import AudioDevice
from .client import connection_options, interruptible_call
from .crypto import Invitation


def error_summary(exc: BaseException) -> str:
    if isinstance(exc, BaseExceptionGroup):
        return "; ".join(error_summary(child) for child in exc.exceptions)
    # Do not echo server-controlled close reasons or credentials into the interface.
    from websockets.exceptions import ConnectionClosed, InvalidStatus

    if isinstance(exc, ConnectionClosed):
        return "Call ended or relay disconnected."
    if isinstance(exc, InvalidStatus):
        return "Relay rejected connection. Check address, access token, and capacity."
    if isinstance(exc, TimeoutError):
        return "Call timed out."
    return f"{type(exc).__name__}: check connection, invitation, or audio device."


def run_terminal(args):
    token = os.environ.get("VPCOMM_ACCESS_TOKEN") or getpass.getpass("Relay access token: ")
    if args.new:
        invitation = Invitation.create()
        print("Share this one-time invitation privately with the other participant:")
        print(invitation.export())
        print("Anyone holding it can impersonate a participant. Do not reuse it.")
    else:
        invitation = Invitation.parse(getpass.getpass("Invitation: "))
    audio = AudioDevice(args.input_device, args.output_device)
    print("Use headphones. Ctrl+C ends the call. No recordings are saved.")
    try:
        asyncio.run(
            interruptible_call(
                args.server,
                token,
                invitation,
                audio,
                print,
                stop=threading.Event(),
                ca_file=args.ca,
            )
        )
    except KeyboardInterrupt:
        print("\nCall ended.")
    except Exception as exc:
        print(error_summary(exc), file=sys.stderr)
        return 1
    return 0


def run_window(args):
    try:
        import tkinter as tk
        from tkinter import messagebox, ttk
    except ImportError:
        print("Tk is unavailable. Install Tk for your Python, or use --cli.", file=sys.stderr)
        return 1

    root = tk.Tk()
    root.title("VPComm | Private audio")
    root.geometry("740x550")
    root.minsize(650, 520)
    panel = ttk.Frame(root, padding=24)
    panel.pack(fill="both", expand=True)
    ttk.Label(panel, text="VPComm", font=("", 24, "bold")).pack(anchor="w")
    ttk.Label(panel, text="Two people. Your relay. End-to-end encrypted audio.").pack(
        anchor="w", pady=(4, 18)
    )

    def field(label, initial="", masked=False):
        ttk.Label(panel, text=label).pack(anchor="w")
        variable = tk.StringVar(value=initial)
        entry = ttk.Entry(panel, textvariable=variable, show="*" if masked else "")
        entry.pack(fill="x", pady=(4, 12))
        return variable, entry

    server, server_entry = field("Relay address", args.server)
    token, token_entry = field(
        "Relay access token (not the invitation)", os.environ.get("VPCOMM_ACCESS_TOKEN", ""), True
    )
    invitation, invitation_entry = field("One-time invitation (paste to join)", masked=True)
    controls = ttk.Frame(panel)
    controls.pack(fill="x", pady=(0, 16))
    status_text = tk.StringVar(
        value="Ready. Generate an invitation or paste one received privately."
    )
    ttk.Label(panel, textvariable=status_text, wraplength=665).pack(anchor="w", pady=8)
    ttk.Label(
        panel,
        text="Use headphones; this prototype has no echo cancellation.\n"
        "Share invitations through a trusted channel. Compare verification codes.\n"
        "The relay can see IP addresses and call timing, but not decrypt audio.\n"
        "Experimental protocol: not independently security audited.",
        wraplength=665,
    ).pack(anchor="w", pady=12)
    events: queue.Queue[tuple[str, str]] = queue.Queue()
    stop = threading.Event()
    worker = None
    audio = None
    closing = False

    def new_invitation():
        invitation.set(Invitation.create().export())
        status_text.set(
            "Invitation generated. Copy it and share privately; use it for one call only."
        )

    def copy_invitation():
        if invitation.get():
            root.clipboard_clear()
            root.clipboard_append(invitation.get())
            status_text.set("Copied. Your clipboard may retain the secret; clear it after sharing.")

    def set_busy(busy):
        for widget in (server_entry, token_entry, invitation_entry, new_button, copy_button, join):
            widget.configure(state="disabled" if busy else "normal")
        hangup.configure(state="normal" if busy else "disabled")
        mute.configure(state="normal" if busy else "disabled")

    def connect_call():
        nonlocal worker, audio
        try:
            connection_options(server.get().strip(), args.ca)
            parsed = Invitation.parse(invitation.get())
            access = token.get().strip()
            if len(access) < 32 or not access.isascii():
                raise ValueError("Enter a relay access token of at least 32 ASCII characters")
        except ValueError as exc:
            messagebox.showerror("Check call details", str(exc))
            return
        stop.clear()
        audio = AudioDevice(args.input_device, args.output_device)
        url = server.get().strip()
        set_busy(True)
        mute.configure(text="Mute")

        def work():
            try:
                asyncio.run(
                    interruptible_call(
                        url,
                        access,
                        parsed,
                        audio,
                        lambda text: events.put(("status", text)),
                        stop=stop,
                        ca_file=args.ca,
                    )
                )
            except Exception as exc:
                events.put(("status", error_summary(exc)))
            finally:
                events.put(("done", ""))

        worker = threading.Thread(target=work, name="vpcomm-call", daemon=True)
        worker.start()

    def toggle_mute():
        if audio is not None:
            if audio.muted.is_set():
                audio.muted.clear()
                mute.configure(text="Mute")
            else:
                audio.muted.set()
                mute.configure(text="Unmute")

    new_button = ttk.Button(controls, text="New invitation", command=new_invitation)
    copy_button = ttk.Button(controls, text="Copy invitation", command=copy_invitation)
    join = ttk.Button(controls, text="Start / Join", command=connect_call)
    mute = ttk.Button(controls, text="Mute", command=toggle_mute, state="disabled")
    hangup = ttk.Button(controls, text="Hang up", command=stop.set, state="disabled")
    for button in (new_button, copy_button, join, mute, hangup):
        button.pack(side="left", padx=(0, 8))

    def close():
        nonlocal closing
        closing = True
        stop.set()
        if worker is None or not worker.is_alive():
            root.destroy()
        else:
            status_text.set("Closing audio devices...")

    def poll():
        while True:
            try:
                kind, text = events.get_nowait()
            except queue.Empty:
                break
            if kind == "done":
                set_busy(False)
                invitation.set("")
                status_text.set(
                    status_text.get() + "\nDisconnected. Use a new invitation next time."
                )
            else:
                status_text.set(text)
        if closing and (worker is None or not worker.is_alive()):
            root.destroy()
            return
        root.after(100, poll)

    root.protocol("WM_DELETE_WINDOW", close)
    root.after(100, poll)
    root.mainloop()
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default="ws://127.0.0.1:8765/relay")
    parser.add_argument("--cli", action="store_true", help="Use terminal instead of desktop window")
    parser.add_argument(
        "--new", action="store_true", help="Generate an invitation in terminal mode"
    )
    parser.add_argument("--ca", help="PEM CA file for a privately issued server certificate")
    parser.add_argument("--input-device", type=int, help="PortAudio input device index")
    parser.add_argument("--output-device", type=int, help="PortAudio output device index")
    parser.add_argument("--list-devices", action="store_true")
    args = parser.parse_args()
    if args.list_devices:
        import sounddevice as sd

        print(sd.query_devices())
        return
    if sys.byteorder != "little":
        parser.exit(1, "Stage-one audio supports little-endian desktops only.\n")
    try:
        raise SystemExit(run_terminal(args) if args.cli else run_window(args))
    except ValueError as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
