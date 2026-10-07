"""Field and checkbox specs for every generic service config page.

Each SERVICE_PAGES entry is (config_section, fields, checks), rendered by
gui.dialogs._ServicePage in this order:
  fields: (label, config_key, default, tooltip[, dropdown_choices])
  checks: (label, config_key, default_bool, tooltip)

To expose a new config option in the GUI, add a row here.
"""

from gui.widgets import _MAIL_HOST_DEFAULT

_PORT_ROOT = "Requires root (or iptables redirect from standard port)."
_ENABLED = "Enable or disable this service entirely."
_LOG_REQ = "Log every incoming request (method, path, headers) to the log panel."

# Services whose page is just a port and an Enabled box.
_SIMPLE_TCP_SERVICES = [
    ("smb",   "445",  "Fake SMB server"),
    ("rdp",   "3389", "Fake RDP server"),
    ("vnc",   "5900", "Fake VNC server"),
    ("mysql", "3306", "Fake MySQL server"),
    ("mssql", "1433", "Fake MSSQL server"),
    ("redis", "6379", "Fake Redis server"),
    ("ldap",  "389",  "Fake LDAP server"),
]

SERVICE_PAGES = (
    (
        "http",
        [
            ("Port",            "port",           "80",
             f"TCP port for the HTTP server. Default: 80. {_PORT_ROOT}"),
            ("Response Code",   "response_code",  "200",
             "HTTP status code returned for every request.",
             ["200", "301", "302", "400", "403", "404", "500", "503"]),
            ("Response Body",   "response_body",  "<html><body>OK</body></html>",
             "HTML/text body returned in every HTTP response.\n"
             "Malware may check this content for specific strings."),
            ("Response Body File", "response_body_file", "",
             "Path to an HTML file to serve instead of the Response Body field above.\n"
             "Relative to the NotTheNet project root (e.g. assets/notthenet-page.html).\n"
             "Leave blank to use the Response Body string."),
            ("Server Header",   "server_header",  "Apache/2.4.51",
             "Value of the 'Server:' response header.\n"
             "Spoofing a real server (Apache, nginx) may satisfy malware fingerprinting checks."),
            ("Response Delay (ms)", "response_delay_ms", "50",
             "Artificial delay in milliseconds added before each HTTP response.\n"
             "Realistic latency (50-200 ms) defeats timing-based sandbox detection\n"
             "that flags environments with suspiciously instant responses.\n"
             "Set to 0 to disable."),
        ],
        [("Enabled", "enabled", True, _ENABLED),
         ("Log Requests", "log_requests", True, _LOG_REQ),
         ("Dynamic Responses", "dynamic_responses", True,
          "Serve context-aware responses based on requested file extension.\n"
          "If malware requests /payload.dll, it gets a valid PE stub.\n"
          "If it requests an image, it gets a valid PNG/JPEG header.\n"
          "Defeats sandbox detection that checks Content-Type vs extension."),
         ("DoH Intercept", "doh_intercept", True,
          "Intercept DNS-over-HTTPS (DoH) queries embedded in HTTPS traffic.\n"
          "Resolves DoH requests to the configured redirect_ip,\n"
          "preventing malware from bypassing the fake DNS server."),
         ("WebSocket Intercept", "websocket_intercept", True,
          "Accept WebSocket upgrade requests, complete the handshake,\n"
          "and then send a close frame. Satisfies malware that uses\n"
          "WebSocket-based C2 channels.")],
    ),
    (
        "https",
        [
            ("Port",            "port",           "443",
             f"TCP port for the HTTPS server. Default: 443. {_PORT_ROOT}"),
            ("Cert File",       "cert_file",      "certs/server.crt",
             "Path to the TLS certificate. Generated automatically by notthenet-install.sh\n"
             "(RSA-4096, self-signed). Malware rarely validates the cert."),
            ("Key File",        "key_file",       "certs/server.key",
             "Path to the TLS private key. Should be readable only by root (mode 0600)."),
            ("Response Code",   "response_code",  "200",
             "HTTP status code returned inside the TLS tunnel.",
             ["200", "301", "302", "400", "403", "404", "500", "503"]),
            ("Response Body",   "response_body",  "<html><body>OK</body></html>",
             "HTML/text body returned inside every HTTPS response."),
            ("Response Body File", "response_body_file", "",
             "Path to an HTML file to serve instead of the Response Body field above.\n"
             "Relative to the NotTheNet project root (e.g. assets/notthenet-page.html).\n"
             "Leave blank to use the Response Body string."),
            ("Server Header",   "server_header",  "Apache/2.4.51",
             "Value of the 'Server:' response header inside the TLS tunnel."),
            ("Response Delay (ms)", "response_delay_ms", "50",
             "Artificial delay in milliseconds added before each HTTPS response.\n"
             "Realistic latency (50-200 ms) defeats timing-based sandbox detection.\n"
             "Set to 0 to disable."),
        ],
        [("Enabled", "enabled", True, _ENABLED),
         ("Log Requests", "log_requests", True, _LOG_REQ),
         ("Dynamic Responses", "dynamic_responses", True,
          "Serve context-aware responses based on requested file extension.\n"
          "Same as the HTTP option \u2014 applied inside the TLS tunnel."),
         ("Dynamic Certificates", "dynamic_certs", True,
          "Forge a unique TLS certificate for each domain on-the-fly.\n"
          "When malware connects to https://evil-c2.com, a cert with\n"
          "CN=evil-c2.com and matching SANs is generated instantly,\n"
          "signed by NotTheNet\u2019s Root CA. Install the CA cert in the\n"
          "analysis VM\u2019s trust store for seamless interception."),
         ("DoH Intercept", "doh_intercept", True,
          "Intercept DNS-over-HTTPS queries inside the TLS tunnel.\n"
          "Responds with the configured redirect_ip."),
         ("WebSocket Intercept", "websocket_intercept", True,
          "Accept and intercept WebSocket upgrade requests\n"
          "inside the TLS tunnel.")],
    ),
    ("smtp", [
        ("Port",     "port",     "25",
         f"TCP port for the SMTP server. Default: 25. {_PORT_ROOT}"),
        ("Hostname", "hostname", _MAIL_HOST_DEFAULT,
         "SMTP server hostname announced in the 220 banner and EHLO response."),
        ("Banner",   "banner",   f"220 {_MAIL_HOST_DEFAULT} ESMTP",
         "Full 220 greeting sent on connection.\n"
         "Malware may parse this to fingerprint the mail server."),
    ], [
        ("Enabled",     "enabled",     True,  _ENABLED),
        ("Save Emails", "save_emails", True,
         "Save each received email as a .eml file in logs/emails/\n"
         "with a UUID filename for later analysis."),
    ]),
    ("smtps", [
        ("Port",     "port",     "465",
         f"TCP port for SMTPS (implicit TLS). Default: 465. {_PORT_ROOT}"),
        ("Hostname", "hostname", _MAIL_HOST_DEFAULT,
         "Hostname announced in the SMTPS banner and EHLO response."),
        ("Banner",   "banner",   f"220 {_MAIL_HOST_DEFAULT} ESMTP",
         "220 greeting sent after TLS handshake completes."),
    ], [
        ("Enabled",     "enabled",     True,  _ENABLED),
        ("Save Emails", "save_emails", True,
         "Save received emails to logs/emails/ (same directory as SMTP)."),
    ]),
    ("pop3", [
        ("Port",     "port",     "110",
         f"TCP port for the POP3 server. Default: 110. {_PORT_ROOT}"),
        ("Hostname", "hostname", _MAIL_HOST_DEFAULT,
         "Hostname announced in the POP3 +OK greeting banner."),
    ], [
        ("Enabled", "enabled", True, _ENABLED),
    ]),
    ("pop3s", [
        ("Port",     "port",     "995",
         f"TCP port for POP3S (implicit TLS). Default: 995. {_PORT_ROOT}"),
        ("Hostname", "hostname", _MAIL_HOST_DEFAULT,
         "Hostname announced in the POP3S +OK greeting banner."),
    ], [
        ("Enabled", "enabled", True, _ENABLED),
    ]),
    ("imap", [
        ("Port",     "port",     "143",
         f"TCP port for the IMAP server. Default: 143. {_PORT_ROOT}"),
        ("Hostname", "hostname", _MAIL_HOST_DEFAULT,
         "Hostname used in the IMAP greeting and capability responses."),
    ], [
        ("Enabled", "enabled", True, _ENABLED),
    ]),
    ("imaps", [
        ("Port",     "port",     "993",
         f"TCP port for IMAPS (implicit TLS). Default: 993. {_PORT_ROOT}"),
        ("Hostname", "hostname", _MAIL_HOST_DEFAULT,
         "Hostname used in the IMAPS greeting and capability responses."),
    ], [
        ("Enabled", "enabled", True, _ENABLED),
    ]),
    ("ftp", [
        ("Port",       "port",       "21",
         f"TCP port for the FTP server. Default: 21. {_PORT_ROOT}"),
        ("Banner",     "banner",     "220 Microsoft FTP Service",
         "220 greeting sent on connection.\n"
         "Malware may check this to confirm an FTP server is listening."),
        ("Upload Dir", "upload_dir", "logs/ftp_uploads",
         "Directory where uploaded files are saved.\n"
         "Each file is renamed to a UUID to prevent collisions."),
    ], [
        ("Enabled",       "enabled",       True, _ENABLED),
        ("Allow Uploads", "allow_uploads", True,
         "Accept STOR commands (file uploads).\n"
         "Disable to silently reject all upload attempts."),
    ]),
    (
        "ntp",
        [("Port", "port", "123",
          f"UDP port for the NTP server. Default: 123. {_PORT_ROOT}")],
        [("Enabled", "enabled", True, _ENABLED)],
    ),
    (
        "irc",
        [
            ("Port",     "port",     "6667",
             f"TCP port for the fake IRC server. Default: 6667. {_PORT_ROOT}"),
            ("Hostname", "hostname", "irc.example.com",
             "IRC server hostname advertised in the 001\u2013004 welcome burst.\n"
             "Malware often uses this to verify it connected to the right server."),
            ("Network",  "network",  "IRCnet",
             "IRC network name sent in RPL_ISUPPORT (005).\n"
             "Some bots check this to confirm the correct network."),
            ("Channel",  "channel",  "botnet",
             "Default channel name returned in /LIST. Bots typically JOIN\n"
             "a hard-coded channel name rather than relying on /LIST."),
            ("MOTD",     "motd",     "Welcome to IRC.",
             "Message of the Day text sent after successful registration."),
        ],
        [("Enabled", "enabled", True, _ENABLED)],
    ),
    (
        "tftp",
        [
            ("Port",       "port",       "69",
             f"UDP port for the TFTP server. Default: 69. {_PORT_ROOT}"),
            ("Upload Dir", "upload_dir", "logs/tftp_uploads",
             "Directory where WRQ (write) uploads are saved.\n"
             "Created automatically. Each file is prefixed with a UUID\n"
             "to prevent collisions."),
        ],
        [
            ("Enabled",       "enabled",       True, _ENABLED),
            ("Allow Uploads", "allow_uploads", True,
             "Accept WRQ (write) transfers from clients.\n"
             "Disable to silently reject all upload attempts with\n"
             "TFTP error code 2 (Access violation)."),
        ],
    ),
    (
        "telnet",
        [
            ("Port",   "port",   "23",
             f"TCP port for the Telnet server. Default: 23. {_PORT_ROOT}"),
            ("Banner", "banner", "router login",
             "Text displayed before the login prompt.\n"
             "Common Mirai targets: 'router login', 'BusyBox on OpenWrt',\n"
             "'(none)' \u2014 match whatever the target bot expects."),
            ("Prompt", "prompt", "# ",
             "Shell prompt shown to the bot after login.\n"
             "'# ' implies a root shell; '$ ' implies a normal user.\n"
             "Mirai simply issues commands without checking the prompt."),
        ],
        [("Enabled", "enabled", True, _ENABLED)],
    ),
    (
        "socks5",
        [
            ("Port", "port", "1080",
             f"TCP port for the SOCKS5 proxy. Default: 1080. {_PORT_ROOT}\n"
             "Every CONNECT request logs the real destination host and port\n"
             "the malware was trying to reach \u2014 the highest-value intel\n"
             "this service captures."),
        ],
        [("Enabled", "enabled", True, _ENABLED)],
    ),
    (
        "ircs",
        [
            ("Port",     "port",     "6697",
             f"TCP port for the TLS-wrapped IRC server. Default: 6697. {_PORT_ROOT}"),
            ("Hostname", "hostname", "irc.example.com",
             "IRC server hostname in the 001\u2013004 welcome burst."),
            ("Network",  "network",  "IRCnet",
             "IRC network name sent in RPL_ISUPPORT (005)."),
            ("Channel",  "channel",  "botnet",
             "Default channel name. Bots typically JOIN a hard-coded name."),
            ("MOTD",     "motd",     "Welcome to IRC.",
             "Message of the Day text sent after successful registration."),
        ],
        [("Enabled", "enabled", True, _ENABLED)],
    ),
    (
        "catch_all",
        [
            ("TCP Catch-All Port", "tcp_port", "9999",
             "Fallback TCP port. iptables redirects all unmatched TCP traffic here\n"
             "when 'Redirect TCP' is enabled."),
            ("UDP Catch-All Port", "udp_port", "9998",
             "Fallback UDP port. iptables redirects all unmatched UDP traffic here\n"
             "when 'Redirect UDP' is enabled."),
        ],
        [
            ("Redirect TCP (catch-all)", "redirect_tcp", True,
             "Add an iptables REDIRECT rule to send all unmatched TCP traffic\n"
             "to the TCP catch-all port above."),
            ("Redirect UDP (catch-all)", "redirect_udp", False,
             "Add an iptables REDIRECT rule to send all unmatched UDP traffic\n"
             "to the UDP catch-all port. Use with caution \u2014 may disrupt UDP services."),
        ],
    ),
    *(
        (
            key,
            [("Port", "port", port,
              f"TCP port for the {tip.lower()}. Default: {port}. {_PORT_ROOT}")],
            [("Enabled", "enabled", True, _ENABLED)],
        )
        for key, port, tip in _SIMPLE_TCP_SERVICES
    ),
    (
        "icmp",
        [],
        [
            ("Enabled", "enabled", True,
             "Enable the ICMP echo responder.\n"
             "When active, an iptables DNAT rule redirects all forwarded\n"
             "ICMP echo-requests (pings) to this host. The kernel then\n"
             "replies automatically, so malware connectivity checks succeed.\n"
             "Requires root / CAP_NET_RAW."),
        ],
    ),
)
