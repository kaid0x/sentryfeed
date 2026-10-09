"""My stack: the products a company runs, matched against stories.

The visitor picks products on /stack. Their choice is kept only in their own
browser; the server just tags every story with the products it mentions, and the
page filters on that. Nothing about what anyone runs is ever sent here.

Patterns are case-sensitive, since product names are capitalised: "Exchange" the
Microsoft server, not "exchange" the verb. Run `python stack.py` to see which
stories in your database match which products.
"""
import re

CATEGORIES = [
    ("network", "Firewalls, VPNs and network gear"),
    ("email", "Email and collaboration"),
    ("server", "Servers and operating systems"),
    ("web", "Web servers, CMS and business apps"),
    ("transfer", "File transfer and backup"),
    ("identity", "Identity, cloud and security tools"),
    ("endpoint", "Browsers and devices"),
    ("dev", "Developer tools"),
]

# (id, name shown, category, pattern). A pattern can name the product, its parts
# or its well-known nicknames ("CitrixBleed" is NetScaler).
PRODUCTS = [
    ("fortinet", "Fortinet (FortiGate, FortiOS…)", "network", r"Fortinet|Forti[A-Z][A-Za-z]+"),
    ("paloalto", "Palo Alto Networks (PAN-OS, GlobalProtect)", "network", r"Palo Alto Networks|PAN-OS|GlobalProtect|Expedition tool"),
    ("cisco", "Cisco (IOS XE, ASA, Firepower, ISE…)", "network", r"Cisco(?! Talos)"),
    ("ivanti", "Ivanti (Connect Secure, EPMM…)", "network", r"Ivanti|Pulse Secure|Pulse Connect"),
    ("netscaler", "Citrix NetScaler", "network", r"NetScaler|Citrix ADC|Citrix Gateway|CitrixBleed"),
    ("citrix", "Citrix (other products)", "network", r"Citrix(?! ?(?:ADC|Gateway|Bleed))"),
    ("sonicwall", "SonicWall", "network", r"SonicWall|SonicOS"),
    ("checkpoint", "Check Point", "network", r"Check Point(?! Research)"),
    ("juniper", "Juniper (Junos)", "network", r"Juniper|Junos"),
    ("f5", "F5 BIG-IP", "network", r"\bF5\b|BIG-IP"),
    ("zyxel", "Zyxel", "network", r"Zyxel"),
    ("mikrotik", "MikroTik", "network", r"MikroTik|RouterOS"),
    ("tplink", "TP-Link", "network", r"TP-Link"),
    ("dlink", "D-Link", "network", r"D-Link"),
    ("exchange", "Microsoft Exchange", "email", r"Exchange Server|Microsoft Exchange|Exchange Online|ProxyLogon|ProxyShell|ProxyNotShell"),
    ("sharepoint", "Microsoft SharePoint", "email", r"SharePoint"),
    ("m365", "Microsoft 365 (Outlook, Teams)", "email", r"Microsoft 365|Office 365|Microsoft Outlook|Outlook (?:and|for|on|app|client|flaw|bug|vulnerabilit\w*|zero-day)|OneDrive|Microsoft Teams|Teams app"),
    ("zimbra", "Zimbra", "email", r"Zimbra"),
    ("roundcube", "Roundcube", "email", r"Roundcube"),
    ("confluence", "Atlassian Confluence", "email", r"Confluence|Atlassian"),   # "Atlassian flaw" can mean either
    ("jira", "Atlassian Jira", "email", r"Jira|Atlassian"),
    ("slack", "Slack", "email", r"\bSlack\b"),
    ("zoom", "Zoom", "email", r"\bZoom\b(?! in| out)"),
    ("windows", "Microsoft Windows", "server", r"Windows(?! Defender)|Patch Tuesday|\bRDP\b"),
    ("windowsserver", "Windows Server and Active Directory", "server", r"Windows Server|Active Directory|Domain Controller|\bWSUS\b|Kerberos"),
    ("linux", "Linux", "server", r"Linux|Ubuntu|Debian|Red Hat|RHEL"),
    ("vmware", "VMware (ESXi, vCenter)", "server", r"VMware|ESXi|vCenter|vSphere"),
    ("openssh", "OpenSSH", "server", r"OpenSSH"),
    ("openssl", "OpenSSL", "server", r"OpenSSL"),
    ("apache", "Apache (HTTP Server, Tomcat, Struts)", "web", r"Apache(?! Software Foundation)|Tomcat|Struts"),
    ("nginx", "nginx", "web", r"[Nn][Gg][Ii][Nn][Xx]"),
    ("wordpress", "WordPress and plugins", "web", r"WordPress|Elementor|WooCommerce"),
    ("drupal", "Drupal", "web", r"Drupal"),
    ("oracle", "Oracle (WebLogic, E-Business Suite, PeopleSoft)", "web", r"Oracle|WebLogic|PeopleSoft"),
    ("sap", "SAP (NetWeaver…)", "web", r"\bSAP\b|NetWeaver"),
    ("salesforce", "Salesforce", "web", r"Salesforce"),
    ("moveit", "MOVEit (Progress)", "transfer", r"MOVEit"),
    ("kiteworks", "Kiteworks", "transfer", r"Kiteworks"),
    ("goanywhere", "GoAnywhere", "transfer", r"GoAnywhere"),
    ("veeam", "Veeam", "transfer", r"Veeam"),
    ("wsftp", "WS_FTP / CrushFTP / Cleo", "transfer", r"WS_FTP|CrushFTP|\bCleo\b"),
    ("okta", "Okta", "identity", r"\bOkta\b"),
    ("azure", "Microsoft Azure / Entra ID", "identity", r"Azure|Entra ID|Entra"),
    ("aws", "Amazon Web Services", "identity", r"\bAWS\b|Amazon Web Services|Amazon S3|\bS3 bucket"),
    ("gcp", "Google Cloud / Workspace", "identity", r"Google Cloud|Google Workspace|Gmail"),
    ("snowflake", "Snowflake", "identity", r"Snowflake"),
    ("crowdstrike", "CrowdStrike", "identity", r"CrowdStrike"),
    ("cloudflare", "Cloudflare", "identity", r"Cloudflare(?![- ](?:check|themed|lookalike))"),
    ("chrome", "Google Chrome / Chromium", "endpoint", r"Chrome|Chromium"),
    ("firefox", "Mozilla Firefox", "endpoint", r"Firefox|Mozilla"),
    ("edge", "Microsoft Edge", "endpoint", r"Microsoft Edge|\bEdge browser"),
    ("apple", "Apple (iOS, macOS, Safari)", "endpoint", r"\biOS\b|iPadOS|macOS|Safari|iPhone|Apple"),
    ("android", "Android and Samsung", "endpoint", r"Android|Samsung|Pixel"),
    ("qnap", "QNAP / Synology NAS", "endpoint", r"QNAP|Synology"),
    ("github", "GitHub", "dev", r"GitHub"),
    ("gitlab", "GitLab", "dev", r"GitLab"),
    ("jenkins", "Jenkins", "dev", r"Jenkins"),
    ("docker", "Docker / Kubernetes", "dev", r"Docker|Kubernetes|\bK8s\b|containerd"),
    ("npm", "npm / PyPI packages", "dev", r"\bnpm\b|PyPI|\bpip\b"),
    ("vscode", "VS Code and extensions", "dev", r"VS ?Code|Visual Studio Code|Open VSX"),
]

# A story only counts when it's about the product, not just mentioning that an attack
# arrived by email or that a researcher works at a vendor. Faked brands don't count.
_NOT_ABOUT = re.compile(r"(?i:\b(?:fake|spoofed|bogus|counterfeit|impersonat\w*)\b)")

_COMPILED = [(pid, re.compile(rf"(?<!\w)(?:{pattern})(?!\w)")) for pid, _, _, pattern in PRODUCTS]
NAMES = {pid: name for pid, name, _, _ in PRODUCTS}


SECURITY_SEVERITIES = ("red", "orange", "yellow")   # tech news and events aren't about your stack's security


def match(item):
    """Product ids a story mentions, from its title and the start of its summary."""
    title = item.get("title") or ""
    text = f"{title} {(item.get('summary') or '')[:400]}"
    found = []
    for pid, regex in _COMPILED:
        m = regex.search(text)
        if not m:
            continue
        # "Fake Cloudflare checks", "impersonating Microsoft Teams": the brand is the bait.
        before = text[max(0, m.start() - 30):m.start()]
        if _NOT_ABOUT.search(before) and not regex.search(text, m.end()):
            continue
        found.append(pid)
    # NetScaler stories often also say "Citrix"; don't double-tag them as other Citrix products.
    if "netscaler" in found and "citrix" in found:
        found.remove("citrix")
    return found


def catalog():
    """Products grouped by category, for the picker."""
    return [(key, label, [(pid, name) for pid, name, cat, _ in PRODUCTS if cat == key]) for key, label in CATEGORIES]


def main():
    from app import load_items_ungrouped

    items = [i for i in load_items_ungrouped(14) if i["severity"] in SECURITY_SEVERITIES]
    tagged = 0
    for item in items:
        products = match(item)
        if products:
            tagged += 1
            print(f"[{item['severity']}] {item['title']}")
            print(f"    {', '.join(NAMES[p] for p in products)}")
    print(f"\n{tagged} of {len(items)} stories mention a product in the catalog.")


if __name__ == "__main__":
    main()
