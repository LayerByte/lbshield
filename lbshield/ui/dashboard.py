"""Live dashboard rendering."""

from __future__ import annotations

from rich.layout import Layout
from rich.panel import Panel

from lbshield.models import Event, ServerMetadata
from lbshield.ui.banner import banner
from lbshield.ui.components import status_panel
from lbshield.ui.tables import events_table, key_value_table
from lbshield.utils.formatting import (
    format_bps,
    format_bytes_per_second,
    format_percent,
    format_pps,
)


def dashboard(
    server: ServerMetadata,
    cpu_percent: float,
    ram_percent: float,
    swap_percent: float,
    disk_percent: float,
    load_average: float,
    rx_bps: float,
    tx_bps: float,
    rx_pps: float,
    tx_pps: float,
    connections: int,
    syn_recv: int,
    events: list[Event],
) -> Layout:
    layout = Layout()
    layout.split_column(Layout(name="header", size=8), Layout(name="body", ratio=1), Layout(name="events", size=12))
    layout["body"].split_row(Layout(name="left"), Layout(name="middle"), Layout(name="right"))
    layout["header"].update(banner(server))
    layout["left"].update(
        key_value_table(
            "SERVER",
            [
                ("Name", server.name),
                ("IP", server.public_ip or "unknown"),
                ("Hostname", server.hostname),
                ("Interface", server.interface or "unknown"),
            ],
            "cyan",
        )
    )
    layout["middle"].update(
        Panel(
            key_value_table(
                "SYSTEM",
                [
                    ("CPU", format_percent(cpu_percent)),
                    ("RAM", format_percent(ram_percent)),
                    ("SWAP", format_percent(swap_percent)),
                    ("DISK", format_percent(disk_percent)),
                    ("LOAD", f"{load_average:.2f}"),
                ],
                "green",
            ),
            border_style="green",
        )
    )
    warnings = sum(1 for event in events if event.severity.value != "INFO")
    layout["right"].split_column(
        Panel(
            key_value_table(
                "NETWORK",
                [
                    ("RX", format_bps(rx_bps)),
                    ("TX", format_bps(tx_bps)),
                    ("RX PPS", format_pps(rx_pps)),
                    ("TX PPS", format_pps(tx_pps)),
                    ("CONNS", str(connections)),
                    ("SYN_RECV", str(syn_recv)),
                    ("RX BYTES", format_bytes_per_second(rx_bps / 8)),
                ],
                "cyan",
            ),
            border_style="cyan",
        ),
        status_panel("PROTECTED", "NORMAL" if warnings == 0 else "ELEVATED", len(events), warnings),
    )
    layout["events"].update(events_table(events))
    return layout

