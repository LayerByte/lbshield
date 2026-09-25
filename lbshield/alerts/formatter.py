"""Alert text formatting."""

from __future__ import annotations

from lbshield.models import Event, Incident, Severity
from lbshield.utils.formatting import format_bps, format_duration, format_pps


def standard_alert(event: Event) -> str:
    label = "Resolved" if event.resolved else ("Warning" if event.severity != Severity.INFO else "Info")
    return f"{label} ! [ {event.message} ]"


def discord_incident_text(incident: Incident) -> str:
    lines = [
        "🚨 **LBShield — Possible DDoS Attack Detected**",
        "",
        "🖥️ **Target Server**",
        "",
        f"Server: {incident.server.name}",
        f"Server ID: {incident.server.server_id}",
    ]
    if incident.server.public_ip:
        lines.append(f"IP: {incident.server.public_ip}")
    lines.extend([f"Hostname: {incident.server.hostname}", f"Interface: {incident.server.interface or 'unknown'}", "", "📊 **Summary**", ""])
    lines.append(f"Number of signatures: {len(incident.signatures)}")
    if incident.peak_pps is not None:
        lines.append(f"Highest PPS Peak: {format_pps(incident.peak_pps)}")
    if incident.peak_bps is not None:
        lines.append(f"Highest BPS Peak: {format_bps(incident.peak_bps)}")
    if incident.observed_pps is not None:
        lines.append(f"Total PPS: {format_pps(incident.observed_pps)}")
    if incident.observed_bps is not None:
        lines.append(f"Total Bandwidth: {format_bps(incident.observed_bps)}")
    if incident.unique_sources is not None:
        lines.append(f"Unique Sources: {incident.unique_sources}")
    lines.extend(["", "📝 **Detailed signatures**", ""])
    for signature in incident.signatures:
        lines.append(f"**{signature.name}**")
        lines.append(f"Layer: {signature.layer}")
        if signature.protocol:
            lines.append(f"Protocol: {signature.protocol}")
        if signature.peak_pps is not None:
            lines.append(f"PPS Peak: {format_pps(signature.peak_pps)}")
        if signature.peak_bps is not None:
            lines.append(f"BPS Peak: {format_bps(signature.peak_bps)}")
        if signature.request_peak is not None:
            lines.append(f"Request Peak: {signature.request_peak:.2f} rps")
        if signature.target:
            lines.append(f"Target: {signature.target}")
        lines.append("")
    if incident.top_sources:
        lines.extend(["🌐 **Top Sources**", ""])
        for source, value in incident.top_sources[:5]:
            lines.append(f"{source}      {format_pps(value)}")
        lines.append("")
    lines.append(f"Incident: {incident.incident_id}")
    lines.append(f"Status: {incident.status.value.title()}")
    return "\n".join(lines)


def discord_resolution_text(incident: Incident) -> str:
    lines = [
        "✅ **LBShield — Network Incident Resolved**",
        "",
        "🖥️ **Target Server**",
        "",
        f"Server: {incident.server.name}",
    ]
    if incident.server.public_ip:
        lines.append(f"IP: {incident.server.public_ip}")
    lines.extend(["", "📊 **Summary**", "", f"Duration: {format_duration(incident.duration_seconds)}"])
    if incident.peak_pps is not None:
        lines.append(f"Peak PPS: {format_pps(incident.peak_pps)}")
    if incident.peak_bps is not None:
        lines.append(f"Peak Bandwidth: {format_bps(incident.peak_bps)}")
    lines.append(f"Signatures: {len(incident.signatures)}")
    lines.extend(["", f"Incident: {incident.incident_id}", "Status: Resolved"])
    return "\n".join(lines)


def telegram_incident_text(incident: Incident) -> str:
    lines = [
        "🚨 LBShield — Possible DDoS Attack Detected",
        "",
        "🖥️ Target Server",
        "",
        incident.server.name,
    ]
    if incident.server.public_ip:
        lines.append(incident.server.public_ip)
    lines.extend(["", "📊 Summary", "", f"Signatures: {len(incident.signatures)}"])
    if incident.peak_pps is not None:
        lines.append(f"PPS Peak: {format_pps(incident.peak_pps)}")
    if incident.peak_bps is not None:
        lines.append(f"BPS Peak: {format_bps(incident.peak_bps)}")
    lines.extend(["", "📝 Signatures", ""])
    lines.extend(f"• {signature.name}" for signature in incident.signatures)
    lines.extend(["", f"Incident: {incident.incident_id}"])
    return "\n".join(lines)

