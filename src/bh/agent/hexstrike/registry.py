"""The HexStrike tool table: one entry per `@mcp.tool()` function of HexStrike's MCP client, classed and, for the
ones the sandbox can run, ported to an argv template.

Origin: HexStrike AI (MIT, Copyright (c) 2026 Muhammad Osama (0x4m4)), hexstrike_mcp.py lines 267-5414: the tool
names, their categories and their signatures (parameter names, types, defaults, copied verbatim below), and the
command each one sent to hexstrike_server.py (lines 10377-15480, the `/api/tools/*` routes) for the ported ones.
Modified: the help texts are rewritten; HexStrike's commands were strings run through a shell, here each one is an
argv template (one token per element, never a shell); every tool is classed; defaults that pointed at missing
wordlists or forbidden sources are replaced for the run (`Tool.overrides`), proxy and rate come from the
environment (run.py), and the free `additional_args` string becomes a checked list of tokens.

Classes:
  passive   archive or subdomain sources, no request to the target
  mapper    maps the surface (crawl, probe); contract.MAPPERS
  scanner   automated scanner, refused when the program forbids scanners; contract.SCANNERS; the default for a
            network tool we cannot class
  local     reads a local file or HexStrike's own state, no network
  no-route  needs raw sockets or a protocol other than HTTP(S): the gate cuts it, the tool can do nothing here
  refused   password attacks, default credentials, exploitation, payload or shell generators, post-exploitation,
            cloud tools that need credentials, network poisoning, arbitrary code

Template tokens: `{param}` is replaced by the value inside the token (never split); `{_proxy}`, `{_rate}`,
`{_delay_s}`, `{_delay_ms}`, `{_proxy_hostport}`, `{_run}`, `{_conf}` are set by run.py. A token `p?tok` is kept
only when `p` is truthy, `!p?tok` only when it is falsy, `p=v?tok` only when `p == v`. `{additional_args}` alone marks
where the caller's tokens go (default: at the end).

Stdlib only (the sandbox runs `python3 -I` with bh/agent mounted alone).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

CLASSES = ("passive", "mapper", "scanner", "local", "no-route", "refused")
KINDS = ("text", "url", "host", "hosts", "path", "csv", "choice", "int", "bool", "args", "locked", "offset")
GUARD = re.compile(r"^(!?)(\w+)(?:=([\w.,-]*))?\?(.*)$", re.S)
VAR = re.compile(r"\{(\w+)\}")
INTERNAL = ("_proxy", "_proxy_hostport", "_rate", "_delay_s", "_delay_ms", "_run", "_conf")

# Read roots: wordlists and templates shipped in the image. The work dir is added by run.py.
READ_ROOTS = (
    "/usr/share/seclists",
    "/usr/share/wordlists",
    "/usr/share/dirb",
    "/usr/share/dirbuster",
    "/usr/share/wfuzz",
    "/usr/share/nuclei-templates",
    "/opt/bh",
)
WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"
NUCLEI_TEMPLATES = "/opt/bh/nuclei-templates"
# tools.NUCLEI_EXCLUDE_TAGS plus rce (exploitation): never run, whatever the caller's tags.
NUCLEI_EXCLUDE = "dos,fuzz,intrusive,bruteforce,brute-force,default-login,osint,oast,headless,rce"
# gau: the passive providers the gate lets through (tools.ARCHIVE_PROVIDERS); commoncrawl needs port 80.
GAU_PROVIDERS = ("wayback", "otx", "urlscan")


@dataclass(frozen=True)
class Param:
    name: str
    type: str  # from the signature: str int bool float dict list any
    default: object
    required: bool


@dataclass(frozen=True)
class Check:
    """How tool_run validates one parameter of a ported tool."""

    kind: str = "text"
    choices: tuple = ()
    lo: int = 0
    hi: int = 0
    maxlen: int = 512
    base: str = ""  # relative paths resolve here (default: the work dir)
    note: str = ""  # why a locked parameter is locked


@dataclass(frozen=True, eq=False)
class Tool:
    name: str
    category: str
    params: tuple[Param, ...]
    binary: str
    argv: tuple[str, ...]
    klass: str
    ported: bool
    origin: int  # line of the function in hexstrike_mcp.py
    help: str  # two lines at most, rewritten
    why: str = ""  # why it is refused, without a route, or not ported
    checks: dict = field(default_factory=dict)
    deny: tuple[str, ...] = ()  # flags refused in additional_args, on top of run.DENY
    stdin: str = ""
    overrides: dict = field(default_factory=dict)  # run value when the caller omits the parameter
    need_one: tuple[str, ...] = ()
    free_args: bool = True  # additional_args accepted
    conf: str = ""  # config file written to the run dir, given as {_conf}
    example: dict = field(default_factory=dict)
    duplicates: tuple[int, ...] = ()  # other lines defining the same name in hexstrike_mcp.py
    posix: bool = False  # short options take attached values or bundle (-dVALUE, -ab): checked letter by letter

    def param(self, name: str) -> Param | None:
        return next((p for p in self.params if p.name == name), None)


def _type(ann: ast.expr | None) -> str:
    if ann is None:
        return "any"
    base = ast.unparse(ann).split("[")[0].strip().lower()
    return base if base in ("str", "int", "bool", "float", "dict", "list") else "any"


def parse_signature(sig: str) -> tuple[Param, ...]:
    """Parameters of a HexStrike signature, copied verbatim (parsed, never run)."""
    fn = ast.parse(f"def f({sig}):\n    pass").body[0]
    assert isinstance(fn, ast.FunctionDef)
    a = fn.args
    defaults: list = [None] * (len(a.args) - len(a.defaults)) + list(a.defaults)
    out = []
    for arg, d in zip(a.args, defaults, strict=True):
        out.append(Param(arg.arg, _type(arg.annotation), None if d is None else ast.literal_eval(d), d is None))
    return tuple(out)


# ------------------------------------------------------------------ the 151 HexStrike tools
# (line in hexstrike_mcp.py, name, category, class, binary, signature verbatim, help, why)
# binary "" = HexStrike server logic, nothing to run. why "" = generic text built below.
_NET = "needs raw TCP/UDP sockets ({}); the gate carries HTTP(S) only"
_CREDS = "cloud account audit: needs cloud credentials, which never enter the sandbox"
_SPECS: list[tuple[int, str, str, str, str, str, str, str]] = [
    (284, "nmap_scan", "network", "no-route", "nmap",
     "target:str, scan_type:str='-sV', ports:str='', additional_args:str=''",
     "Port and service scan with nmap.", _NET.format("port scan")),
    (327, "gobuster_scan", "web", "scanner", "gobuster",
     "url:str, mode:str='dir', wordlist:str='/usr/share/wordlists/dirb/common.txt', additional_args:str=''",
     "Content discovery with gobuster (modes dir, vhost, fuzz).", ""),
    (371, "nuclei_scan", "web", "scanner", "nuclei",
     "target:str, severity:str='', tags:str='', template:str='', additional_args:str=''",
     "Template scan with nuclei; dos, brute-force, default-login, rce and OOB tags are always excluded.", ""),
    (422, "prowler_scan", "cloud", "refused", "prowler",
     "provider:str='aws', profile:str='default', region:str='', checks:str='', output_dir:str='/tmp/prowler_output', "
     "output_format:str='json', additional_args:str=''",
     "Cloud account audit with prowler.", _CREDS),
    (456, "trivy_scan", "cloud", "local", "trivy",
     "scan_type:str='image', target:str='', output_format:str='json', severity:str='', output_file:str='', "
     "additional_args:str=''",
     "Vulnerability listing of an image or a file system with trivy.",
     "not ported: trivy is not in the image and downloads its database at start (no route)"),
    (492, "scout_suite_assessment", "cloud", "refused", "scout",
     "provider:str='aws', profile:str='default', report_dir:str='/tmp/scout-suite', services:str='', "
     "exceptions:str='', additional_args:str=''",
     "Cloud account audit with ScoutSuite.", _CREDS),
    (526, "cloudmapper_analysis", "cloud", "refused", "cloudmapper",
     "action:str='collect', account:str='', config:str='config.json', additional_args:str=''",
     "Cloud account inventory with cloudmapper.", _CREDS),
    (555, "pacu_exploitation", "cloud", "refused", "pacu",
     "session_name:str='hexstrike_session', modules:str='', data_services:str='', regions:str='', "
     "additional_args:str=''",
     "Cloud exploitation framework pacu.", "exploitation framework, needs cloud credentials"),
    (587, "kube_hunter_scan", "cloud", "no-route", "kube-hunter",
     "target:str='', remote:str='', cidr:str='', interface:str='', active:bool=False, report:str='json', "
     "additional_args:str=''",
     "Kubernetes cluster probe with kube-hunter.", _NET.format("cluster ports, network ranges")),
    (623, "kube_bench_cis", "cloud", "local", "kube-bench",
     "targets:str='', version:str='', config_dir:str='', output_format:str='json', additional_args:str=''",
     "CIS benchmark of the local Kubernetes node with kube-bench.", ""),
    (654, "docker_bench_security_scan", "cloud", "local", "docker-bench-security",
     "checks:str='', exclude:str='', output_file:str='/tmp/docker-bench-results.json', additional_args:str=''",
     "CIS benchmark of the local Docker host.", ""),
    (684, "clair_vulnerability_scan", "cloud", "no-route", "clairctl",
     "image:str, config:str='/etc/clair/config.yaml', output_format:str='json', additional_args:str=''",
     "Image vulnerability listing through a Clair server.",
     "needs a Clair server and a registry, neither reachable through the gate"),
    (713, "falco_runtime_monitoring", "cloud", "local", "falco",
     "config_file:str='/etc/falco/falco.yaml', rules_file:str='', output_format:str='json', duration:int=60, "
     "additional_args:str=''",
     "Runtime syscall monitoring of the local host with falco.", ""),
    (745, "checkov_iac_scan", "cloud", "local", "checkov",
     "directory:str='.', framework:str='', check:str='', skip_check:str='', output_format:str='json', "
     "additional_args:str=''",
     "Static checks of infrastructure-as-code files with checkov.", ""),
    (779, "terrascan_iac_scan", "cloud", "local", "terrascan",
     "scan_type:str='all', iac_dir:str='.', policy_type:str='', output_format:str='json', severity:str='', "
     "additional_args:str=''",
     "Static checks of infrastructure-as-code files with terrascan.", ""),
    (817, "create_file", "files", "refused", "",
     "filename:str, content:str, binary:bool=False",
     "Write a file through HexStrike's server.", "arbitrary file writes outside the hooks: use the sandbox shell"),
    (843, "modify_file", "files", "refused", "",
     "filename:str, content:str, append:bool=False",
     "Change a file through HexStrike's server.", "arbitrary file writes outside the hooks: use the sandbox shell"),
    (869, "delete_file", "files", "refused", "",
     "filename:str",
     "Delete a file through HexStrike's server.", "arbitrary file deletion outside the hooks"),
    (891, "list_files", "files", "local", "ls",
     "directory:str='.'",
     "List a directory of the work dir.", ""),
    (911, "generate_payload", "exploit", "refused", "",
     "payload_type:str='buffer', size:int=1024, pattern:str='A', filename:str=''",
     "Payload generator.", "payload generator"),
    (945, "install_python_package", "files", "refused", "",
     "package:str, env_name:str='default'",
     "Install a Python package.", "installs and runs third-party code"),
    (969, "execute_python_script", "files", "refused", "",
     "script:str, env_name:str='default', filename:str=''",
     "Run a Python script.", "runs arbitrary code outside the hooks"),
    (1001, "dirb_scan", "web", "scanner", "dirb",
     "url:str, wordlist:str='/usr/share/wordlists/dirb/common.txt', additional_args:str=''",
     "Content discovery with dirb (not recursive here).", ""),
    (1027, "nikto_scan", "web", "scanner", "nikto",
     "target:str, additional_args:str=''",
     "Web server checks with nikto.", ""),
    (1051, "sqlmap_scan", "web", "scanner", "sqlmap",
     "url:str, data:str='', additional_args:str=''",
     "SQL injection detection with sqlmap: risk 1, techniques B/E/U, no data extraction.", ""),
    (1077, "metasploit_run", "exploit", "refused", "msfconsole",
     "module:str, options:Dict[str, Any]={}",
     "Metasploit module runner.", "exploitation framework"),
    (1101, "hydra_attack", "password", "refused", "hydra",
     "target:str, service:str, username:str='', username_file:str='', password:str='', password_file:str='', "
     "additional_args:str=''",
     "Online password guessing with hydra.", "password attack (brute force)"),
    (1143, "john_crack", "password", "refused", "john",
     "hash_file:str, wordlist:str='/usr/share/wordlists/rockyou.txt', format_type:str='', additional_args:str=''",
     "Offline password cracking with John the Ripper.", "password attack"),
    (1176, "wpscan_analyze", "web", "scanner", "wpscan",
     "url:str, additional_args:str=''",
     "WordPress checks with wpscan; no password attack, no API token.", ""),
    (1200, "enum4linux_scan", "network", "no-route", "enum4linux",
     "target:str, additional_args:str='-a'",
     "SMB/NetBIOS enumeration with enum4linux.", _NET.format("SMB, NetBIOS")),
    (1224, "ffuf_scan", "web", "scanner", "ffuf",
     "url:str, wordlist:str='/usr/share/wordlists/dirb/common.txt', mode:str='directory', "
     "match_codes:str='200,204,301,302,307,401,403', additional_args:str=''",
     "Fuzzing with ffuf: directory (url/FUZZ), vhost (Host header), parameter (?FUZZ=value) or url (FUZZ in it).",
     ""),
    (1254, "netexec_scan", "network", "refused", "netexec",
     "target:str, protocol:str='smb', username:str='', password:str='', hash_value:str='', module:str='', "
     "additional_args:str=''",
     "Credential testing and remote execution over SMB, WinRM, SSH.", "password attack and post-exploitation"),
    (1288, "amass_scan", "recon", "passive", "amass",
     "domain:str, mode:str='enum', additional_args:str=''",
     "Subdomains from passive sources with amass (enum -passive, no DNS brute force).", ""),
    (1314, "hashcat_crack", "password", "refused", "hashcat",
     "hash_file:str, hash_type:str, attack_mode:str='0', wordlist:str='/usr/share/wordlists/rockyou.txt', "
     "mask:str='', additional_args:str=''",
     "Offline password cracking with hashcat.", "password attack"),
    (1346, "subfinder_scan", "recon", "mapper", "subfinder",
     "domain:str, silent:bool=True, all_sources:bool=False, additional_args:str=''",
     "Subdomains of a domain from subfinder's sources.", ""),
    (1374, "smbmap_scan", "network", "no-route", "smbmap",
     "target:str, username:str='', password:str='', domain:str='', additional_args:str=''",
     "SMB share listing with smbmap.", _NET.format("SMB")),
    (1408, "rustscan_fast_scan", "network", "no-route", "rustscan",
     "target:str, ports:str='', ulimit:int=5000, batch_size:int=4500, timeout:int=1500, scripts:bool=False, "
     "additional_args:str=''",
     "Fast port scan with rustscan.", _NET.format("port scan")),
    (1444, "masscan_high_speed", "network", "no-route", "masscan",
     "target:str, ports:str='1-65535', rate:int=1000, interface:str='', router_mac:str='', source_ip:str='', "
     "banners:bool=False, additional_args:str=''",
     "Port scan with masscan.", _NET.format("SYN scan")),
    (1482, "nmap_advanced_scan", "network", "no-route", "nmap",
     "target:str, scan_type:str='-sS', ports:str='', timing:str='T4', nse_scripts:str='', os_detection:bool=False, "
     "version_detection:bool=False, aggressive:bool=False, stealth:bool=False, additional_args:str=''",
     "Port scan with nmap and NSE scripts.", _NET.format("SYN scan, OS detection")),
    (1525, "autorecon_comprehensive", "network", "no-route", "autorecon",
     "target:str, output_dir:str='/tmp/autorecon', port_scans:str='top-100-ports', service_scans:str='default', "
     "heartbeat:int=60, timeout:int=300, additional_args:str=''",
     "Multi-tool host reconnaissance with AutoRecon.", _NET.format("port scans first")),
    (1562, "enum4linux_ng_advanced", "network", "no-route", "enum4linux-ng",
     "target:str, username:str='', password:str='', domain:str='', shares:bool=True, users:bool=True, "
     "groups:bool=True, policy:bool=True, additional_args:str=''",
     "SMB/LDAP enumeration with enum4linux-ng.", _NET.format("SMB, LDAP, RPC")),
    (1603, "rpcclient_enumeration", "network", "no-route", "rpcclient",
     "target:str, username:str='', password:str='', domain:str='', "
     "commands:str='enumdomusers;enumdomgroups;querydominfo', additional_args:str=''",
     "MS-RPC enumeration with rpcclient.", _NET.format("MS-RPC")),
    (1637, "nbtscan_netbios", "network", "no-route", "nbtscan",
     "target:str, verbose:bool=False, timeout:int=2, additional_args:str=''",
     "NetBIOS name scan with nbtscan.", _NET.format("NetBIOS over UDP")),
    (1666, "arp_scan_discovery", "network", "no-route", "arp-scan",
     "target:str='', interface:str='', local_network:bool=False, timeout:int=500, retry:int=3, "
     "additional_args:str=''",
     "Local network host discovery with arp-scan.", _NET.format("ARP")),
    (1699, "responder_credential_harvest", "network", "refused", "responder",
     "interface:str='eth0', analyze:bool=False, wpad:bool=True, force_wpad_auth:bool=False, fingerprint:bool=False, "
     "duration:int=300, additional_args:str=''",
     "LLMNR/NBT-NS/WPAD responder.", "network poisoning and credential capture"),
    (1736, "volatility_analyze", "forensics", "local", "volatility",
     "memory_file:str, plugin:str, profile:str='', additional_args:str=''",
     "Memory image analysis with Volatility 2.", ""),
    (1764, "msfvenom_generate", "exploit", "refused", "msfvenom",
     "payload:str, format_type:str='', output_file:str='', encoder:str='', iterations:str='', additional_args:str=''",
     "Payload builder msfvenom.", "payload and shell generator"),
    (1800, "gdb_analyze", "binary", "local", "gdb",
     "binary:str, commands:str='', script_file:str='', additional_args:str=''",
     "Debugger session on a local binary.", "not ported: gdb runs the binary and has its own shell command"),
    (1828, "radare2_analyze", "binary", "local", "r2",
     "binary:str, commands:str='', additional_args:str=''",
     "Reverse engineering of a local binary with radare2.", "not ported: radare2 commands include a shell escape"),
    (1854, "binwalk_analyze", "forensics", "local", "binwalk",
     "file_path:str, extract:bool=False, additional_args:str=''",
     "Embedded file signatures in a local file (binwalk, no extraction).", ""),
    (1880, "ropgadget_search", "exploit", "refused", "ROPgadget",
     "binary:str, gadget_type:str='', additional_args:str=''",
     "ROP gadget search.", "exploit development"),
    (1906, "checksec_analyze", "binary", "local", "checksec",
     "binary:str",
     "Hardening flags of a local binary.", ""),
    (1928, "xxd_hexdump", "binary", "local", "xxd",
     "file_path:str, offset:str='0', length:str='', additional_args:str=''",
     "Hex dump of a local file.", ""),
    (1956, "strings_extract", "binary", "local", "strings",
     "file_path:str, min_len:int=4, additional_args:str=''",
     "Printable strings of a local file.", ""),
    (1982, "objdump_analyze", "binary", "local", "objdump",
     "binary:str, disassemble:bool=True, additional_args:str=''",
     "Disassembly (or headers) of a local binary with objdump.", ""),
    (2012, "ghidra_analysis", "binary", "local", "analyzeHeadless",
     "binary:str, project_name:str='hexstrike_analysis', script_file:str='', analysis_timeout:int=300, "
     "output_format:str='xml', additional_args:str=''",
     "Headless Ghidra analysis of a local binary.", "not ported: Ghidra is not in the image, and runs scripts"),
    (2046, "pwntools_exploit", "exploit", "refused", "python3",
     "script_content:str='', target_binary:str='', target_host:str='', target_port:int=0, exploit_type:str='local', "
     "additional_args:str=''",
     "pwntools script runner.", "exploit development, runs arbitrary code"),
    (2080, "one_gadget_search", "exploit", "refused", "one_gadget",
     "libc_path:str, level:int=1, additional_args:str=''",
     "libc one-gadget finder.", "exploit development"),
    (2106, "libc_database_lookup", "exploit", "refused", "libc-database",
     "action:str='find', symbols:str='', libc_id:str='', additional_args:str=''",
     "libc identification for exploit writing.", "exploit development"),
    (2135, "gdb_peda_debug", "binary", "local", "gdb",
     "binary:str='', commands:str='', attach_pid:int=0, core_file:str='', additional_args:str=''",
     "Debugger session with PEDA.", "not ported: gdb runs the binary, attaches to processes, has a shell command"),
    (2166, "angr_symbolic_execution", "binary", "refused", "python3",
     "binary:str, script_content:str='', find_address:str='', avoid_addresses:str='', analysis_type:str='symbolic', "
     "additional_args:str=''",
     "Symbolic execution with angr.", "runs caller-supplied Python code"),
    (2200, "ropper_gadget_search", "exploit", "refused", "ropper",
     "binary:str, gadget_type:str='rop', quality:int=1, arch:str='', search_string:str='', additional_args:str=''",
     "ROP gadget search with ropper.", "exploit development"),
    (2234, "pwninit_setup", "exploit", "refused", "pwninit",
     "binary:str, libc:str='', ld:str='', template_type:str='python', additional_args:str=''",
     "Exploit workspace setup.", "exploit development"),
    (2265, "feroxbuster_scan", "web", "scanner", "feroxbuster",
     "url:str, wordlist:str='/usr/share/wordlists/dirb/common.txt', threads:int=10, additional_args:str=''",
     "Recursive content discovery with feroxbuster.", ""),
    (2293, "dotdotpwn_scan", "web", "scanner", "dotdotpwn",
     "target:str, module:str='http', additional_args:str=''",
     "Path traversal fuzzer.", ""),
    (2319, "xsser_scan", "web", "scanner", "xsser",
     "url:str, params:str='', additional_args:str=''",
     "XSS checks with xsser.", ""),
    (2345, "wfuzz_scan", "web", "scanner", "wfuzz",
     "url:str, wordlist:str='/usr/share/wordlists/dirb/common.txt', additional_args:str=''",
     "Fuzzing with wfuzz (FUZZ marks the spot in the URL).", ""),
    (2375, "dirsearch_scan", "web", "scanner", "dirsearch",
     "url:str, extensions:str='php,html,js,txt,xml,json', wordlist:str='/usr/share/wordlists/dirsearch/common.txt', "
     "threads:int=30, recursive:bool=False, additional_args:str=''",
     "Content discovery with dirsearch.", ""),
    (2409, "katana_crawl", "web", "mapper", "katana",
     "url:str, depth:int=3, js_crawl:bool=True, form_extraction:bool=True, output_format:str='json', "
     "additional_args:str=''",
     "Crawl with katana, depth 3 at most (deeper counts as a scan).", ""),
    (2443, "gau_discovery", "recon", "passive", "gau",
     "domain:str, providers:str='wayback,commoncrawl,otx,urlscan', include_subs:bool=True, "
     "blacklist:str='png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico', additional_args:str=''",
     "Archived URLs of a domain from wayback, otx and urlscan with gau.", ""),
    (2475, "waybackurls_discovery", "recon", "passive", "waybackurls",
     "domain:str, get_versions:bool=False, no_subs:bool=False, additional_args:str=''",
     "Archived URLs of a domain from the Wayback Machine.", ""),
    (2504, "arjun_parameter_discovery", "web", "scanner", "arjun",
     "url:str, method:str='GET', wordlist:str='', delay:int=0, threads:int=25, stable:bool=False, "
     "additional_args:str=''",
     "Hidden parameter discovery with arjun.", ""),
    (2540, "paramspider_mining", "recon", "scanner", "paramspider",
     "domain:str, level:int=2, exclude:str='png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico', output:str='', "
     "additional_args:str=''",
     "URLs with parameters from archives with paramspider.", ""),
    (2572, "x8_parameter_discovery", "web", "scanner", "x8",
     "url:str, wordlist:str='/usr/share/wordlists/x8/params.txt', method:str='GET', body:str='', headers:str='', "
     "additional_args:str=''",
     "Hidden parameter discovery with x8.", ""),
    (2606, "jaeles_vulnerability_scan", "web", "scanner", "jaeles",
     "url:str, signatures:str='', config:str='', threads:int=20, timeout:int=20, additional_args:str=''",
     "Signature-based web scan with jaeles.", ""),
    (2640, "dalfox_xss_scan", "web", "scanner", "dalfox",
     "url:str, pipe_mode:bool=False, blind:bool=False, mining_dom:bool=True, mining_dict:bool=True, "
     "custom_payload:str='', additional_args:str=''",
     "Reflected and DOM XSS checks with dalfox 3 (`dalfox scan`).", ""),
    (2676, "httpx_probe", "web", "mapper", "httpx-toolkit",
     "target:str, probe:bool=True, tech_detect:bool=False, status_code:bool=False, content_length:bool=False, "
     "title:bool=False, web_server:bool=False, threads:int=50, additional_args:str=''",
     "(first definition, replaced by the one at line 3392)", ""),
    (2717, "anew_data_processing", "util", "local", "anew",
     "input_data:str, output_file:str='', additional_args:str=''",
     "Append new lines to a file (anew).", ""),
    (2744, "qsreplace_parameter_replacement", "util", "local", "qsreplace",
     "urls:str, replacement:str='FUZZ', additional_args:str=''",
     "Replace query-string values in a list of URLs (qsreplace).", ""),
    (2771, "uro_url_filtering", "util", "local", "uro",
     "urls:str, whitelist:str='', blacklist:str='', additional_args:str=''",
     "Deduplicate a list of URLs (uro).", ""),
    (2804, "ai_generate_payload", "exploit", "refused", "",
     "attack_type:str, complexity:str='basic', technology:str='', url:str=''",
     "Attack payload generator.", "payload generator"),
    (2845, "ai_test_payload", "exploit", "refused", "",
     "payload:str, target_url:str, method:str='GET'",
     "Send a generated payload to a URL.", "payload delivery"),
    (2880, "ai_generate_attack_suite", "exploit", "refused", "",
     "target_url:str, attack_types:str='xss,sqli,lfi'",
     "Batch of attack payloads for a URL.", "payload generator"),
    (2941, "api_fuzzer", "api", "scanner", "",
     "base_url:str, endpoints:str='', methods:str='GET,POST,PUT,DELETE', "
     "wordlist:str='/usr/share/wordlists/api/api-endpoints.txt'",
     "API endpoint and method fuzzer.", ""),
    (2977, "graphql_scanner", "api", "scanner", "",
     "endpoint:str, introspection:bool=True, query_depth:int=10, test_mutations:bool=True",
     "GraphQL introspection, depth and mutation checks.", ""),
    (3019, "jwt_analyzer", "api", "scanner", "",
     "jwt_token:str, target_url:str=''",
     "JWT decoding; with a URL it sends altered tokens to it.", ""),
    (3058, "api_schema_analyzer", "api", "scanner", "",
     "schema_url:str, schema_type:str='openapi'",
     "Fetch and review an OpenAPI or GraphQL schema.", ""),
    (3103, "comprehensive_api_audit", "api", "scanner", "",
     "base_url:str, schema_url:str='', jwt_token:str='', graphql_endpoint:str=''",
     "Chains the API tools above against one base URL.", ""),
    (3201, "volatility3_analyze", "forensics", "local", "vol",
     "memory_file:str, plugin:str, output_file:str='', additional_args:str=''",
     "Memory image analysis with Volatility 3.", ""),
    (3229, "foremost_carving", "forensics", "local", "foremost",
     "input_file:str, output_dir:str='/tmp/foremost_output', file_types:str='', additional_args:str=''",
     "File carving from a local image with foremost.", ""),
    (3257, "steghide_analysis", "forensics", "local", "steghide",
     "action:str, cover_file:str, embed_file:str='', passphrase:str='', output_file:str='', additional_args:str=''",
     "Hidden data in a local image or audio file (steghide).", ""),
    (3289, "exiftool_extract", "forensics", "local", "exiftool",
     "file_path:str, output_format:str='', tags:str='', additional_args:str=''",
     "Metadata of a local file with exiftool (read only).", ""),
    (3317, "hashpump_attack", "exploit", "refused", "hashpump",
     "signature:str, data:str, key_length:str, append_data:str, additional_args:str=''",
     "Hash length extension forging.", "exploitation (forged signatures)"),
    (3351, "hakrawler_crawl", "web", "mapper", "hakrawler",
     "url:str, depth:int=2, forms:bool=True, robots:bool=True, sitemap:bool=True, wayback:bool=False, "
     "additional_args:str=''",
     "Crawl with hakrawler, depth 3 at most.", ""),
    (3392, "httpx_probe", "web", "mapper", "httpx-toolkit",
     "targets:str='', target_file:str='', ports:str='', methods:str='GET', status_code:str='', "
     "content_length:bool=False, output_file:str='', additional_args:str=''",
     "Probe hosts or URLs with httpx (status, title, server).", ""),
    (3428, "paramspider_discovery", "recon", "scanner", "paramspider",
     "domain:str, exclude:str='', output_file:str='', level:int=2, additional_args:str=''",
     "URLs with parameters from archives with paramspider.", ""),
    (3462, "burpsuite_scan", "web", "scanner", "burpsuite",
     "project_file:str='', config_file:str='', target:str='', headless:bool=False, scan_type:str='', "
     "scan_config:str='', output_file:str='', additional_args:str=''",
     "Burp Suite scan.", "not ported: Burp is not in the image; bh-zap covers this"),
    (3498, "zap_scan", "web", "scanner", "zaproxy",
     "target:str='', scan_type:str='baseline', api_key:str='', daemon:bool=False, port:str='8090', "
     "host:str='0.0.0.0', format_type:str='xml', output_file:str='', additional_args:str=''",
     "OWASP ZAP scan.", "not ported: use bh-zap (it starts ZAP on loopback behind the gate)"),
    (3536, "arjun_scan", "web", "scanner", "arjun",
     "url:str, method:str='GET', data:str='', headers:str='', timeout:str='', output_file:str='', "
     "additional_args:str=''",
     "Hidden parameter discovery with arjun, with extra data and headers.", ""),
    (3570, "wafw00f_scan", "web", "scanner", "wafw00f",
     "target:str, additional_args:str=''",
     "Identify the WAF in front of a site (wafw00f).", ""),
    (3594, "fierce_scan", "recon", "no-route", "fierce",
     "domain:str, dns_server:str='', additional_args:str=''",
     "DNS reconnaissance with fierce.", _NET.format("DNS queries, zone transfers")),
    (3620, "dnsenum_scan", "recon", "no-route", "dnsenum",
     "domain:str, dns_server:str='', wordlist:str='', additional_args:str=''",
     "DNS enumeration with dnsenum.", _NET.format("DNS queries, zone transfers")),
    (3648, "autorecon_scan", "network", "no-route", "autorecon",
     "target:str='', target_file:str='', ports:str='', output_dir:str='', max_scans:str='', max_port_scans:str='', "
     "heartbeat:str='', timeout:str='', target_timeout:str='', config_file:str='', global_file:str='', "
     "plugins_dir:str='', add_plugins_dir:str='', tags:str='', exclude_tags:str='', port_scans:str='', "
     "service_scans:str='', reports:str='', single_target:bool=False, only_scans_dir:bool=False, "
     "no_port_dirs:bool=False, nmap:str='', nmap_append:str='', proxychains:bool=False, "
     "disable_sanity_checks:bool=False, disable_keyboard_control:bool=False, force_services:str='', "
     "accessible:bool=False, verbose:int=0, curl_path:str='', dirbuster_tool:str='', dirbuster_wordlist:str='', "
     "dirbuster_threads:str='', dirbuster_ext:str='', onesixtyone_community_strings:str='', "
     "global_username_wordlist:str='', global_password_wordlist:str='', global_domain:str='', "
     "additional_args:str=''",
     "Multi-tool host reconnaissance with AutoRecon (all options).", _NET.format("port scans first")),
    (3790, "server_health", "server", "local", "", "",
     "Health of HexStrike's server.", ""),
    (3806, "get_cache_stats", "server", "local", "", "",
     "Cache statistics of HexStrike's server.", ""),
    (3820, "clear_cache", "server", "local", "", "",
     "Clear HexStrike's server cache.", ""),
    (3836, "get_telemetry", "server", "local", "", "",
     "Telemetry of HexStrike's server.", ""),
    (3854, "list_active_processes", "server", "local", "", "",
     "Processes started by HexStrike's server.", ""),
    (3870, "get_process_status", "server", "local", "", "pid:int",
     "Status of one process of HexStrike's server.", ""),
    (3889, "terminate_process", "server", "local", "", "pid:int",
     "Stop one process of HexStrike's server.", ""),
    (3908, "pause_process", "server", "local", "", "pid:int",
     "Pause one process of HexStrike's server.", ""),
    (3927, "resume_process", "server", "local", "", "pid:int",
     "Resume one process of HexStrike's server.", ""),
    (3946, "get_process_dashboard", "server", "local", "", "",
     "Process dashboard of HexStrike's server.", ""),
    (3969, "execute_command", "server", "refused", "",
     "command:str, use_cache:bool=True",
     "Run a shell command line.", "arbitrary shell command"),
    (4013, "monitor_cve_feeds", "intel", "passive", "",
     "hours:int=24, severity_filter:str='HIGH,CRITICAL', keywords:str=''",
     "Recent CVEs from public feeds.", ""),
    (4044, "generate_exploit_from_cve", "exploit", "refused", "",
     "cve_id:str, target_os:str='', target_arch:str='x64', exploit_type:str='poc', evasion_level:str='none'",
     "Exploit writer from a CVE.", "exploit generator"),
    (4083, "discover_attack_chains", "intel", "refused", "",
     "target_software:str, attack_depth:int=3, include_zero_days:bool=False",
     "Computed attack chains for a product.", "computed chains and invented scores, not observed values"),
    (4117, "research_zero_day_opportunities", "intel", "refused", "",
     "target_software:str, analysis_depth:str='standard', source_code_url:str=''",
     "Speculative vulnerability research for a product.", "invented findings, not observed values"),
    (4154, "correlate_threat_intelligence", "intel", "passive", "",
     "indicators:str, timeframe:str='30d', sources:str='all'",
     "Look up indicators in public threat feeds.", ""),
    (4200, "advanced_payload_generation", "exploit", "refused", "",
     "attack_type:str, target_context:str='', evasion_level:str='standard', custom_constraints:str=''",
     "Attack payload generator.", "payload generator, filter circumvention"),
    (4248, "vulnerability_intelligence_dashboard", "intel", "passive", "", "",
     "Summary of recent CVE feeds.", ""),
    (4302, "threat_hunting_assistant", "intel", "local", "",
     "target_environment:str, threat_indicators:str='', hunt_focus:str='general'",
     "Canned threat-hunting checklist.", ""),
    (4412, "get_live_dashboard", "server", "local", "", "",
     "Live process dashboard of HexStrike's server.", ""),
    (4428, "create_vulnerability_report", "report", "local", "",
     "vulnerabilities:str, target:str='', scan_type:str='comprehensive'",
     "Format a vulnerability report.", ""),
    (4482, "format_tool_output_visual", "report", "local", "",
     "tool_name:str, output:str, success:bool=True",
     "Colour a tool output for display.", ""),
    (4511, "create_scan_summary", "report", "local", "",
     "target:str, tools_used:str, vulnerabilities_found:int=0, execution_time:float=0.0, findings:str=''",
     "Format a scan summary.", ""),
    (4547, "display_system_metrics", "server", "local", "", "",
     "System metrics of HexStrike's server.", ""),
    (4596, "analyze_target_intelligence", "intel", "scanner", "",
     "target:str",
     "Target profiling by HexStrike's decision engine.", ""),
    (4620, "select_optimal_tools_ai", "intel", "scanner", "",
     "target:str, objective:str='comprehensive'",
     "Tool selection for a target by HexStrike's decision engine.", ""),
    (4648, "optimize_tool_parameters_ai", "intel", "scanner", "",
     "target:str, tool:str, context:str='{}'",
     "Tool options for a target by HexStrike's decision engine.", ""),
    (4685, "create_attack_chain_ai", "intel", "refused", "",
     "target:str, objective:str='comprehensive'",
     "Computed attack chain for a target.", "computed chains and invented probabilities, not observed values"),
    (4717, "intelligent_smart_scan", "workflow", "scanner", "",
     "target:str, objective:str='comprehensive', max_tools:int=5",
     "Runs several scanners chosen by HexStrike's decision engine.", ""),
    (4770, "detect_technologies_ai", "intel", "scanner", "",
     "target:str",
     "Technology detection on a target.", ""),
    (4802, "ai_reconnaissance_workflow", "workflow", "scanner", "",
     "target:str, depth:str='standard'",
     "Reconnaissance workflow of HexStrike's decision engine.", ""),
    (4851, "ai_vulnerability_assessment", "workflow", "scanner", "",
     "target:str, focus_areas:str='all'",
     "Vulnerability workflow of HexStrike's decision engine.", ""),
    (4911, "bugbounty_reconnaissance_workflow", "workflow", "scanner", "",
     "domain:str, scope:str='', out_of_scope:str='', program_type:str='web'",
     "Bug bounty reconnaissance plan and run.", ""),
    (4944, "bugbounty_vulnerability_hunting", "workflow", "scanner", "",
     "domain:str, priority_vulns:str='rce,sqli,xss,idor,ssrf', bounty_range:str='unknown'",
     "Bug bounty vulnerability workflow.", ""),
    (4975, "bugbounty_business_logic_testing", "workflow", "scanner", "",
     "domain:str, program_type:str='web'",
     "Business logic checklist workflow.", ""),
    (5004, "bugbounty_osint_gathering", "workflow", "passive", "",
     "domain:str",
     "Open-source intelligence workflow for a domain.", ""),
    (5029, "bugbounty_file_upload_testing", "workflow", "refused", "",
     "target_url:str",
     "File upload test workflow.", "uploads executable content (web shells)"),
    (5054, "bugbounty_comprehensive_assessment", "workflow", "scanner", "",
     "domain:str, scope:str='', priority_vulns:str='rce,sqli,xss,idor,ssrf', include_osint:bool=True, "
     "include_business_logic:bool=True",
     "All bug bounty workflows in a row.", ""),
    (5092, "bugbounty_authentication_bypass_testing", "workflow", "refused", "",
     "target_url:str, auth_type:str='form'",
     "Authentication test workflow.", "default credentials and authentication attacks"),
    (5157, "http_framework_test", "web", "scanner", "",
     "url:str, method:str='GET', data:dict={}, headers:dict={}, cookies:dict={}, action:str='request'",
     "HexStrike's HTTP client (request, spider, checks).", ""),
    (5198, "browser_agent_inspect", "web", "scanner", "",
     "url:str, headless:bool=True, wait_time:int=5, action:str='navigate', proxy_port:int=None, "
     "active_tests:bool=False",
     "Headless browser inspection of a page.", "not ported: use bh-browse"),
    (5246, "http_set_rules", "web", "local", "",
     "rules:list",
     "Match-and-replace rules of HexStrike's HTTP client.", ""),
    (5253, "http_set_scope", "web", "local", "",
     "host:str, include_subdomains:bool=True",
     "Scope of HexStrike's HTTP client.", ""),
    (5259, "http_repeater", "web", "scanner", "",
     "request_spec:dict",
     "Replay a request with HexStrike's HTTP client.", "not ported: use curl through the gate, or bh-web"),
    (5265, "http_intruder", "web", "scanner", "",
     "url:str, method:str='GET', location:str='query', params:list=None, payloads:list=None, base_data:dict=None, "
     "max_requests:int=100",
     "Payload fuzzing of parameters with HexStrike's HTTP client.", ""),
    (5282, "burpsuite_alternative_scan", "web", "scanner", "",
     "target:str, scan_type:str='comprehensive', headless:bool=True, max_depth:int=3, max_pages:int=50",
     "Crawl and scan with HexStrike's HTTP client and browser.", ""),
    (5343, "error_handling_statistics", "server", "local", "", "",
     "Error statistics of HexStrike's server.", ""),
    (5374, "test_error_recovery", "server", "local", "",
     "tool_name:str, error_type:str='timeout', target:str='example.com'",
     "Simulated error recovery of HexStrike's server.", ""),
]  # fmt: skip


# ------------------------------------------------------------------ ports
_U, _H = Check("url"), Check("host")
_WL = Check("path")
_ARGS = Check("args")
_CSV = Check("csv")


def _locked(note: str) -> Check:
    return Check("locked", note=note)


_OUT = _locked("the output goes to raw/, chosen by tool_run")
# Flags refused per tool (names without dashes, case kept; abbreviations are refused too, see run.DENY)
_SQLMAP_DENY = (
    "os-shell", "os-cmd", "os-pwn", "os-smbrelay", "os-bof", "priv-esc", "msf-path", "tmp-path", "udf-inject",
    "shared-lib", "file-read", "file-write", "file-dest", "reg-read", "reg-add", "reg-del", "reg-key", "reg-value",
    "reg-data", "reg-type", "sql-query", "sql-shell", "sql-file", "dump", "dump-all", "dbs", "tables", "columns",
    "schema", "count", "users", "passwords", "privileges", "roles", "search", "statements", "common-tables",
    "common-columns", "common-files", "eval", "alert", "tamper", "hpp", "chunked", "d", "g", "wizard",
    "sqlmap-shell", "delay", "threads", "purge", "exclude-sysdbs", "banner", "b", "current-user", "current-db",
    "hostname", "is-dba", "all", "a",
)  # fmt: skip

_PORTS: dict[str, dict] = {
    "gobuster_scan": {
        "argv": ("gobuster", "{mode}", "-u", "{url}", "-w", "{wordlist}", "-t", "1", "--delay", "{_delay_ms}ms",
                 "--proxy", "{_proxy}", "--no-progress", "--no-color"),
        "checks": {"url": _U, "mode": Check("choice", ("dir", "vhost", "fuzz")), "wordlist": _WL,
                   "additional_args": _ARGS},
        "deny": ("p", "t", "threads", "delay", "x"),
        "overrides": {"wordlist": WORDLIST},
    },
    "nuclei_scan": {
        "argv": ("nuclei", "-u", "{target}", "severity?-severity", "severity?{severity}", "tags?-tags", "tags?{tags}",
                 "template?-t", "template?{template}", "-etags", NUCLEI_EXCLUDE, "-proxy", "{_proxy}", "-rl", "{_rate}",
                 "-c", "5", "-ni", "-duc", "-nc", "-silent", "-omit-raw", "-jsonl"),
        "checks": {"target": _U, "severity": Check("csv", ("info", "low", "medium", "high", "critical")),
                   "tags": Check("csv", maxlen=200), "template": Check("path", base=NUCLEI_TEMPLATES),
                   "additional_args": _ARGS},
        "deny": ("itags", "include-tags", "it", "include-templates", "etags", "exclude-tags", "code", "tu",
                 "template-url", "wu", "workflow-url", "ut", "update-templates", "up", "update", "iserver",
                 "interactsh-server", "itoken", "interactsh-token", "p", "pi", "ev", "env-vars", "lfa",
                 "allow-local-file-access", "rl", "rate-limit", "rlm", "rate-limit-minute", "c", "bs", "headless",
                 "sign", "dut", "esc"),
    },
    "dirb_scan": {
        "argv": ("dirb", "{url}", "{wordlist}", "-p", "{_proxy}", "-z", "{_delay_ms}", "-r", "-S"),
        "checks": {"url": _U, "wordlist": _WL, "additional_args": _ARGS},
        "deny": ("p", "P", "z"),
        "overrides": {"wordlist": WORDLIST},
    },
    "nikto_scan": {
        "argv": ("nikto", "-h", "{target}", "-useproxy", "{_proxy}", "-nointeractive", "-ask", "no"),
        "checks": {"target": _U, "additional_args": _ARGS},
        "deny": ("useproxy", "evasion", "e", "mutate", "mutate-options", "update", "Pause", "dbcheck"),
    },
    "sqlmap_scan": {
        "argv": ("sqlmap", "-u", "{url}", "--batch", "data?--data={data}", "--risk", "1", "--technique", "BEU",
                 "--threads", "1", "--proxy", "{_proxy}", "--delay", "{_delay_s}", "--timeout", "10", "--retries", "1",
                 "--output-dir", "{_run}/sqlmap", "--disable-coloring"),
        "checks": {"url": _U, "data": Check("text", maxlen=4096), "additional_args": _ARGS},
        "deny": _SQLMAP_DENY,
    },
    "wpscan_analyze": {
        "argv": ("wpscan", "--url", "{url}", "--proxy", "{_proxy}", "--throttle", "{_delay_ms}", "--no-banner",
                 "--no-update", "--format", "cli-no-colour"),
        "checks": {"url": _U, "additional_args": _ARGS},
        "deny": ("passwords", "P", "usernames", "U", "password-attack", "multicall-max-passwords", "api-token",
                 "stealthy", "random-user-agent", "rua", "throttle", "update", "login-uri"),
    },
    "ffuf_scan": {
        "argv": ("ffuf", "mode=directory?-u", "mode=directory?{url}/FUZZ", "mode=vhost?-u", "mode=vhost?{url}",
                 "mode=vhost?-H", "mode=vhost?Host: FUZZ", "mode=parameter?-u", "mode=parameter?{url}?FUZZ=value",
                 "mode=url?-u", "mode=url?{url}", "-w", "{wordlist}", "-mc", "{match_codes}", "-x", "{_proxy}",
                 "-rate", "{_rate}", "-t", "5", "-s", "-noninteractive"),
        "checks": {"url": _U, "wordlist": _WL, "mode": Check("choice", ("directory", "vhost", "parameter", "url")),
                   "match_codes": Check("csv", maxlen=100), "additional_args": _ARGS},
        "deny": ("x", "replay-proxy", "rate", "p", "t", "input-cmd", "input-shell", "input-num", "config", "scrapers",
                 "scraperfile"),
        "overrides": {"wordlist": WORDLIST},
        "example": {"url": "https://app.example.com", "mode": "directory"},
    },
    "amass_scan": {
        "argv": ("amass", "{mode}", "-passive", "-d", "{domain}"),
        "checks": {"domain": _H, "mode": Check("choice", ("enum",)), "additional_args": _ARGS},
        "deny": ("active", "brute", "alts", "aw", "awm", "w", "wm", "rf", "r", "tr", "trf", "src", "ip", "config",
                 "max-dns-queries", "dns-qps"),
    },
    "subfinder_scan": {
        "argv": ("subfinder", "-d", "{domain}", "silent?-silent", "all_sources?-all", "-proxy", "{_proxy}",
                 "-timeout", "20"),
        "checks": {"domain": _H, "silent": Check("bool"), "all_sources": Check("bool"), "additional_args": _ARGS},
        "deny": ("active", "nW", "ip", "r", "rL", "rlist", "pc", "provider-config", "config"),
    },
    "list_files": {
        "argv": ("ls", "-la", "--", "{directory}"),
        "checks": {"directory": Check("path")},
        "free_args": False,
    },
    "feroxbuster_scan": {
        "argv": ("feroxbuster", "-u", "{url}", "-w", "{wordlist}", "-t", "{threads}", "--proxy", "{_proxy}",
                 "--rate-limit", "{_rate}", "--no-state", "--silent"),
        "checks": {"url": _U, "wordlist": _WL, "threads": Check("int", lo=1, hi=10), "additional_args": _ARGS},
        "deny": ("p", "P", "burp", "burp-replay", "rate-limit", "t", "threads", "parallel", "stdin", "L",
                 "scan-limit", "resume-from", "time-limit"),
        "overrides": {"wordlist": WORDLIST},
    },
    "wfuzz_scan": {
        "argv": ("wfuzz", "-w", "{wordlist}", "-p", "{_proxy_hostport}:HTTP", "-s", "{_delay_s}", "-t", "1",
                 "{additional_args}", "{url}"),
        "checks": {"url": _U, "wordlist": _WL, "additional_args": _ARGS},
        "deny": ("p", "s", "t", "script", "script-args", "dump-recipe", "recipe", "Z"),
        "overrides": {"wordlist": WORDLIST},
        "example": {"url": "https://app.example.com/FUZZ"},
    },
    "dirsearch_scan": {
        "argv": ("dirsearch", "-u", "{url}", "-e", "{extensions}", "-w", "{wordlist}", "-t", "{threads}",
                 "recursive?-r", "--proxy", "{_proxy}", "--delay", "{_delay_s}", "--max-rate", "{_rate}",
                 "--no-color", "-q"),
        "checks": {"url": _U, "extensions": Check("csv", maxlen=200), "wordlist": _WL,
                   "threads": Check("int", lo=1, hi=30), "recursive": Check("bool"), "additional_args": _ARGS},
        "deny": ("proxy-list", "proxies-file", "replay-proxy", "tor", "delay", "max-rate", "config", "t", "threads",
                 "session", "s"),
        "overrides": {"wordlist": WORDLIST},
    },
    "katana_crawl": {
        "argv": ("katana", "-u", "{url}", "-d", "{depth}", "js_crawl?-jc", "form_extraction?-fx",
                 "output_format=json?-jsonl", "-proxy", "{_proxy}", "-rl", "{_rate}", "-c", "2", "-silent", "-nc",
                 "-duc"),
        "checks": {"url": _U, "depth": Check("int", lo=1, hi=3), "js_crawl": Check("bool"),
                   "form_extraction": Check("bool"), "output_format": Check("choice", ("json", "text")),
                   "additional_args": _ARGS},
        "deny": ("d", "depth", "rl", "rate-limit", "rlm", "rate-limit-minute", "c", "concurrency", "p", "parallelism",
                 "config", "fc", "field-config", "fs", "field-scope", "cs", "crawl-scope", "ns", "no-scope"),
    },
    "gau_discovery": {
        "argv": ("gau", "--config", "{_conf}", "--providers", "{providers}", "--proxy", "{_proxy}", "--threads", "1",
                 "--retries", "2", "--timeout", "30", "blacklist?--blacklist", "blacklist?{blacklist}",
                 "include_subs?--subs", "{additional_args}", "{domain}"),
        "checks": {"domain": _H, "providers": Check("csv", GAU_PROVIDERS), "include_subs": Check("bool"),
                   "blacklist": Check("csv", maxlen=200), "additional_args": _ARGS},
        "deny": ("config", "threads", "providers", "o", "output", "mc", "fc"),
        "overrides": {"providers": ",".join(GAU_PROVIDERS)},
        # Own config file: ~/.gau.toml (which could point urlscan/otx at another host) is never read (tools.archive).
        "conf": 'threads = 1\nretries = 2\nsubdomains = false\nproviders = ["wayback", "otx", "urlscan"]\n'
        '[urlscan]\n  apikey = ""\n',
        "example": {"domain": "example.com", "include_subs": False},
    },
    "waybackurls_discovery": {
        "argv": ("waybackurls", "get_versions?-get-versions", "no_subs?-no-subs", "{additional_args}", "{domain}"),
        "checks": {"domain": _H, "get_versions": Check("bool"), "no_subs": Check("bool"), "additional_args": _ARGS},
    },
    "arjun_parameter_discovery": {
        "argv": ("arjun", "-u", "{url}", "-m", "{method}", "-t", "{threads}", "wordlist?-w", "wordlist?{wordlist}",
                 "delay?-d", "delay?{delay}", "!delay?-d", "!delay?{_delay_s}", "-T", "10", "stable?--stable", "-q"),
        "checks": {"url": _U, "method": Check("choice", ("GET", "POST", "JSON", "XML")), "wordlist": _WL,
                   "delay": Check("int", lo=0, hi=60), "threads": Check("int", lo=1, hi=25), "stable": Check("bool"),
                   "additional_args": _ARGS},
        "deny": ("d", "t", "c", "rate-limit", "i", "import"),
    },
    "dalfox_xss_scan": {
        "argv": ("dalfox", "scan", "{url}", "--proxy", "{_proxy}", "--rate-limit", "{_rate}", "--workers", "5",
                 "--timeout", "10", "-S", "--no-color", "-f", "json"),
        "checks": {"url": _U, "pipe_mode": _locked("one URL per run"),
                   "blind": _locked("a blind XSS callback is a third-party host"),
                   "mining_dom": _locked("dalfox 3 has no such switch; not passed"),
                   "mining_dict": _locked("dalfox 3 has no such switch; not passed"),
                   "custom_payload": _locked("no caller-supplied payloads"), "additional_args": _ARGS},
        "deny": ("rate-limit", "workers", "delay", "b", "blind", "remote-payloads", "remote-wordlists", "found-action",
                 "found-action-shell", "waf-evasion", "custom-payload", "custom-payload-file", "config",
                 "har-file-path"),
    },
    "httpx_probe": {
        "argv": ("httpx-toolkit", "targets?-u", "targets?{targets}", "target_file?-l", "target_file?{target_file}",
                 "ports?-p", "ports?{ports}", "-x", "{methods}", "status_code?-mc", "status_code?{status_code}",
                 "content_length?-cl", "-sc", "-title", "-server", "-http-proxy", "{_proxy}", "-rl", "{_rate}", "-t",
                 "5", "-nfs", "-silent", "-nc"),
        "checks": {"targets": Check("hosts", maxlen=2000), "target_file": _WL, "ports": Check("csv", maxlen=100),
                   "methods": Check("csv", ("GET", "HEAD")), "status_code": Check("csv", maxlen=100),
                   "content_length": Check("bool"), "output_file": _OUT, "additional_args": _ARGS},
        "deny": ("path", "paths", "rl", "rate-limit", "rlm", "rate-limit-minute", "t", "threads", "x", "u", "l",
                 "config", "resume"),
        "need_one": ("targets", "target_file"),
        "example": {"targets": "https://app.example.com"},
    },
    "xxd_hexdump": {
        "argv": ("xxd", "-s", "{offset}", "length?-l", "length?{length}", "{file_path}"),
        "checks": {"file_path": Check("path"), "offset": Check("offset"), "length": Check("offset"),
                   "additional_args": _ARGS},
        "free_args": False,
        "example": {"file_path": "sample.bin", "length": "256"},
    },
    "strings_extract": {
        "argv": ("strings", "-n", "{min_len}", "--", "{file_path}"),
        "checks": {"file_path": Check("path"), "min_len": Check("int", lo=2, hi=64), "additional_args": _ARGS},
        "free_args": False,
        "example": {"file_path": "sample.bin"},
    },
    "objdump_analyze": {
        "argv": ("objdump", "disassemble?-d", "!disassemble?-x", "--", "{binary}"),
        "checks": {"binary": Check("path"), "disassemble": Check("bool"), "additional_args": _ARGS},
        "free_args": False,
        "example": {"binary": "sample.bin"},
    },
    "binwalk_analyze": {
        "argv": ("binwalk", "{file_path}"),
        "checks": {"file_path": Check("path"), "extract": _locked("extraction writes files; not ported"),
                   "additional_args": _ARGS},
        "free_args": False,
        "example": {"file_path": "sample.bin"},
    },
    "exiftool_extract": {
        "argv": ("exiftool", "output_format=json?-j", "output_format=xml?-X", "output_format=csv?-csv", "--",
                 "{file_path}"),
        "checks": {"file_path": Check("path"), "output_format": Check("choice", ("", "json", "xml", "csv")),
                   "tags": _locked("exiftool tag options can write or evaluate code; read all tags instead"),
                   "additional_args": _ARGS},
        "free_args": False,
        "example": {"file_path": "sample.jpg"},
    },
    "hakrawler_crawl": {
        "argv": ("hakrawler", "-d", "{depth}", "forms?-s", "-u", "-proxy", "{_proxy}", "-t", "2", "-timeout", "10"),
        "stdin": "{url}\n",
        "checks": {"url": _U, "depth": Check("int", lo=1, hi=3), "forms": Check("bool"),
                   "robots": _locked("hakrawler 2 has no such switch; not passed"),
                   "sitemap": _locked("hakrawler 2 has no such switch; not passed"),
                   "wayback": _locked("hakrawler 2 has no such switch; not passed"), "additional_args": _ARGS},
        "deny": ("proxy", "d", "t", "subs"),
    },
    "arjun_scan": {
        "argv": ("arjun", "-u", "{url}", "-m", "{method}", "data?--include", "data?{data}", "headers?--headers",
                 "headers?{headers}", "timeout?-T", "timeout?{timeout}", "!timeout?-T", "!timeout?10", "-t", "5",
                 "-d", "{_delay_s}", "-q"),
        "checks": {"url": _U, "method": Check("choice", ("GET", "POST", "JSON", "XML")),
                   "data": Check("text", maxlen=2048), "headers": Check("text", maxlen=1024),
                   "timeout": Check("offset"), "output_file": _OUT, "additional_args": _ARGS},
        "deny": ("d", "t", "c", "rate-limit", "i", "import"),
    },
    "wafw00f_scan": {
        "argv": ("wafw00f", "{target}", "-p", "{_proxy}"),
        "checks": {"target": _U, "additional_args": _ARGS},
        "deny": ("p", "i", "input-file"),
    },
}  # fmt: skip


# CLI parsers where `-dVALUE` means `-d VALUE` and `-ab` means `-a -b` (getopt, argparse, optparse, pflag, clap,
# Ruby OptionParser). Go's flag package (ProjectDiscovery tools, hakrawler, amass, waybackurls) has neither.
_POSIX = frozenset(
    {"gobuster", "feroxbuster", "gau", "dalfox", "sqlmap", "arjun", "dirsearch", "wafw00f", "wfuzz", "wpscan", "dirb"}
)


def _why(klass: str, binary: str, why: str, ported: bool) -> str:
    if why or ported:
        return why
    if klass in ("refused", "no-route"):
        return "refused"
    if not binary:
        return "not ported: HexStrike server logic, nothing to run here"
    return f"not ported: {binary} is not in the sandbox image"


def _build() -> tuple[dict[str, Tool], dict[str, tuple[int, ...]]]:
    lines: dict[str, list[int]] = {}
    for spec in _SPECS:
        lines.setdefault(spec[1], []).append(spec[0])
    dups = {n: tuple(ls) for n, ls in lines.items() if len(ls) > 1}
    tools: dict[str, Tool] = {}
    for line, name, cat, klass, binary, sig, help_, why in _SPECS:
        if name in dups and line != dups[name][-1]:
            continue  # the last definition is the one FastMCP keeps
        port = _PORTS.get(name)
        ported = port is not None and klass not in ("refused", "no-route")
        p = port or {}
        tools[name] = Tool(
            name=name,
            category=cat,
            params=parse_signature(sig),
            binary=binary,
            argv=tuple(p.get("argv", ())) if ported else (),
            klass=klass,
            ported=ported,
            origin=line,
            help=help_,
            why=_why(klass, binary, why, ported),
            checks=dict(p.get("checks", {})),
            deny=tuple(p.get("deny", ())),
            stdin=p.get("stdin", ""),
            overrides=dict(p.get("overrides", {})),
            need_one=tuple(p.get("need_one", ())),
            free_args=p.get("free_args", True),
            conf=p.get("conf", ""),
            example=dict(p.get("example", {})),
            duplicates=tuple(x for x in dups.get(name, ()) if x != line),
            posix=(port or {}).get("posix", binary in _POSIX),
        )
    return tools, dups


TOOLS, DUPLICATES = _build()
SPEC_COUNT = len(_SPECS)  # functions decorated with @mcp.tool() in hexstrike_mcp.py (151)


def categories() -> list[str]:
    return sorted({t.category for t in TOOLS.values()})


def klass_of(name: object) -> str | None:
    """Class of a HexStrike tool by name, for the PreToolUse hook (tool_run is classed by `arguments.name`)."""
    t = TOOLS.get(name) if isinstance(name, str) else None
    return t.klass if t else None
