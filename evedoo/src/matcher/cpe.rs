//! CPE matching logic for correlating software to CVEs.
//!
//! Phase 1.5: Strict vendor/product matching to reduce false positives.
//! Phase 3:   Token-based curated matching with weighted confidence scoring.
//!
//! Uses a three-layer approach:
//!   1. Curated mapping table — tokenised match with publisher-boosted scoring
//!   2. Publisher → vendor correlation for unknown software
//!   3. Product-name-only exact match as fallback
//!
//! SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use rusqlite::{params, Connection};
use tracing::{debug, info};

use super::dict::DictIndex;
use super::index::CpeIndex;
use crate::error::{Result, ScanError};
use crate::normalize::names::extract_product_name;
use crate::normalize::tokens::{classify_token, is_subset, tokenize, TokenClass};
use crate::models::{
    CpeMatchRecord, CveRecord, DetectedSoftware, MatchConfidence, Remediation, Severity,
    Vulnerability,
};

/// Minimum score for a curated mapping to be accepted. Below this we fall
/// through to publisher → vendor correlation or reject the match entirely.
pub(crate) const CURATED_MIN_SCORE: f32 = 0.60;

/// Score boundaries that map the `f32` score back to the `MatchConfidence`
/// enum for human-facing reports. Tuned so that:
///   * a subset match + publisher confirmation + vendor-in-name → Exact
///   * a subset match + publisher confirmation → High
///   * a subset match alone → Medium
#[allow(dead_code)]
pub(crate) const SCORE_EXACT: f32 = 0.90;
#[allow(dead_code)]
pub(crate) const SCORE_HIGH: f32 = 0.75;
#[allow(dead_code)]
pub(crate) const SCORE_MEDIUM: f32 = 0.55;

/// A resolved CPE identity from the matching layers
#[derive(Debug, Clone)]
struct CpeIdentity {
    vendor: String,
    product: String,
    confidence: MatchConfidence,
}

/// A curated display-name → CPE identity mapping. One CPE identity can
/// carry several display-name patterns (aliases), so the most-specific
/// alias matches with zero extra tokens and wins on score.
struct CuratedMapping {
    /// Display-name patterns that all resolve to the same CPE identity.
    aliases: &'static [&'static str],
    vendor: &'static str,
    product: &'static str,
}

/// Compact constructor keeping the table readable.
const fn m(
    aliases: &'static [&'static str],
    vendor: &'static str,
    product: &'static str,
) -> CuratedMapping {
    CuratedMapping { aliases, vendor, product }
}

/// Curated mappings for the most common Windows applications and their
/// exact CPE identifiers. Grow aliases before growing heuristics.
const KNOWN_MAPPINGS: &[CuratedMapping] = &[
    // ── Browsers ──────────────────────────────────────────────────────
    m(&["Google Chrome"], "google", "chrome"),
    m(&["Mozilla Firefox"], "mozilla", "firefox"),
    m(&["Microsoft Edge"], "microsoft", "edge_chromium"),
    m(&["Brave Browser"], "brave", "brave"),
    m(&["Opera"], "opera", "opera_browser"),
    m(&["Vivaldi"], "vivaldi", "vivaldi"),
    m(&["Tor Browser"], "torproject", "tor"),
    m(&["Thunderbird"], "mozilla", "thunderbird"),
    // ── Microsoft products ────────────────────────────────────────────
    m(&["Microsoft Office"], "microsoft", "office"),
    m(&["Microsoft 365"], "microsoft", "365_apps"),
    m(&["Microsoft Word"], "microsoft", "word"),
    m(&["Microsoft Excel"], "microsoft", "excel"),
    m(&["Microsoft PowerPoint"], "microsoft", "powerpoint"),
    m(&["Microsoft Outlook"], "microsoft", "outlook"),
    m(&["Microsoft Access"], "microsoft", "access"),
    m(&["Microsoft Visual Studio Code"], "microsoft", "visual_studio_code"),
    m(&["Microsoft Visual Studio"], "microsoft", "visual_studio"),
    m(
        &[
            "Visual C++ 2005 Redistributable",
            "Visual C++ 2008 Redistributable",
            "Visual C++ 2010 Redistributable",
            "Visual C++ 2012 Redistributable",
            "Visual C++ 2013 Redistributable",
            "Visual C++ v14 Redistributable",
            "Microsoft Visual C++ Redistributable",
        ],
        "microsoft",
        "visual_c%2b%2b",
    ),
    m(&["Microsoft .NET Framework"], "microsoft", ".net_framework"),
    m(&["Microsoft .NET Runtime"], "microsoft", ".net"),
    m(&[".NET SDK"], "microsoft", ".net"),
    m(&["Windows Desktop Runtime"], "microsoft", ".net_runtime"),
    m(&["Microsoft OneDrive"], "microsoft", "onedrive"),
    m(&["Microsoft Teams"], "microsoft", "teams"),
    m(&["Windows SDK"], "microsoft", "windows_sdk"),
    m(&["Windows 11 Installation Assistant"], "microsoft", "windows_11"),
    m(&["Microsoft Update Health Tools"], "microsoft", "update_health_tools"),
    m(&["Microsoft Skype", "Skype"], "microsoft", "skype"),
    m(&["Microsoft SQL Server"], "microsoft", "sql_server"),
    m(&["SQL Server Management Studio"], "microsoft", "sql_server_management_studio"),
    m(&["Microsoft PowerShell", "PowerShell"], "microsoft", "powershell"),
    m(&["Microsoft Azure CLI"], "microsoft", "azure_command-line_interface"),
    m(&["Internet Explorer"], "microsoft", "internet_explorer"),
    m(&["Microsoft XML"], "microsoft", "xml_core_services"),
    m(&["PowerToys"], "microsoft", "powertoys"),
    m(&["Windows Terminal"], "microsoft", "windows_terminal"),
    m(&["Windows Defender"], "microsoft", "windows_defender"),
    // ── Adobe ─────────────────────────────────────────────────────────
    m(&["Adobe Acrobat"], "adobe", "acrobat"),
    m(
        &[
            "Adobe Acrobat Reader DC",
            "Adobe Acrobat Reader",
            "Adobe Reader",
            "Acrobat Reader",
        ],
        "adobe",
        "acrobat_reader_dc",
    ),
    m(&["Adobe Creative Cloud"], "adobe", "creative_cloud_desktop_application"),
    m(&["Adobe Photoshop"], "adobe", "photoshop"),
    m(&["Adobe Illustrator"], "adobe", "illustrator"),
    m(&["Adobe Premiere"], "adobe", "premiere_pro"),
    m(&["Adobe After Effects"], "adobe", "after_effects"),
    m(&["Adobe Flash"], "adobe", "flash_player"),
    m(&["Adobe InDesign"], "adobe", "indesign"),
    m(&["Adobe Lightroom"], "adobe", "lightroom_classic"),
    m(&["Adobe XD"], "adobe", "xd"),
    m(&["Adobe Substance"], "adobe", "substance_3d_painter"),
    m(&["Adobe Animate"], "adobe", "animate"),
    m(&["Adobe Bridge"], "adobe", "bridge"),
    m(&["Adobe Dreamweaver"], "adobe", "dreamweaver"),
    // ── Development tools ─────────────────────────────────────────────
    m(&["Git ", "Git version"], "git-scm", "git"),
    m(&["Python"], "python", "python"),
    m(&["Node.js", "Node "], "nodejs", "node.js"),
    m(&["Rust "], "rust-lang", "rust"),
    m(&["Go Programming"], "golang", "go"),
    m(&["CMake"], "cmake", "cmake"),
    m(&["Ruby"], "ruby-lang", "ruby"),
    m(&["PHP"], "php", "php"),
    m(&["Perl"], "perl", "perl"),
    m(&["Lua"], "lua", "lua"),
    m(&["Erlang"], "erlang", "erlang/otp"),
    m(&["IntelliJ IDEA", "JetBrains IntelliJ"], "jetbrains", "intellij_idea"),
    m(&["PyCharm"], "jetbrains", "pycharm"),
    m(&["WebStorm"], "jetbrains", "webstorm"),
    m(&["CLion"], "jetbrains", "clion"),
    m(&["Rider"], "jetbrains", "rider"),
    m(&["GoLand"], "jetbrains", "goland"),
    m(&["DataGrip"], "jetbrains", "datagrip"),
    m(&["RubyMine"], "jetbrains", "rubymine"),
    m(&["PhpStorm"], "jetbrains", "phpstorm"),
    m(&["Android Studio"], "google", "android_studio"),
    m(&["Sublime Text"], "sublimehq", "sublime_text"),
    m(&["Postman"], "postman", "postman"),
    m(&["Eclipse IDE", "Eclipse "], "eclipse", "eclipse_ide"),
    m(&["Apache Maven"], "apache", "maven"),
    m(&["Apache Subversion"], "apache", "subversion"),
    m(&["TortoiseSVN"], "tigris", "tortoisesvn"),
    m(&["TortoiseGit"], "tortoisegit", "tortoisegit"),
    m(&["Mercurial"], "mercurial", "mercurial"),
    m(&["Gradle"], "gradle", "gradle"),
    m(&["LLVM"], "llvm", "llvm"),
    m(&["MinGW"], "mingw", "mingw-w64"),
    m(&["Beyond Compare"], "scootersoftware", "beyond_compare"),
    m(&["WinMerge"], "winmerge", "winmerge"),
    m(&["pgAdmin"], "postgresql", "pgadmin_4"),
    m(&["DBeaver"], "dbeaver", "dbeaver"),
    // ── Common apps ───────────────────────────────────────────────────
    m(&["7-Zip"], "7-zip", "7-zip"),
    m(&["VLC media player"], "videolan", "vlc_media_player"),
    m(&["Notepad++"], "notepad-plus-plus", "notepad++"),
    m(&["WinRAR"], "rarlab", "winrar"),
    m(&["PuTTY"], "putty", "putty"),
    m(&["WinSCP"], "winscp", "winscp"),
    m(&["FileZilla"], "filezilla-project", "filezilla_client"),
    m(&["KeePass"], "keepass", "keepass"),
    m(&["Wireshark"], "wireshark", "wireshark"),
    m(&["WinZip"], "winzip_computing", "winzip"),
    m(&["Total Commander"], "ghisler", "total_commander"),
    m(&["AutoHotkey"], "autohotkey", "autohotkey"),
    // ── Gaming / Media ────────────────────────────────────────────────
    m(&["Steam"], "valvesoftware", "steam_client"),
    m(&["Discord"], "discord", "discord"),
    m(&["Spotify"], "spotify", "spotify"),
    m(&["OBS Studio"], "obsproject", "obs_studio"),
    m(&["Audacity"], "audacityteam", "audacity"),
    m(&["Blender"], "blender", "blender"),
    m(&["Krita"], "krita", "krita"),
    m(&["DaVinci Resolve"], "blackmagicdesign", "davinci_resolve"),
    m(&["Shotcut"], "meltytech", "shotcut"),
    // ── Database ──────────────────────────────────────────────────────
    m(&["SQLite"], "sqlite", "sqlite"),
    m(&["PostgreSQL"], "postgresql", "postgresql"),
    m(&["MySQL"], "oracle", "mysql"),
    m(&["MongoDB"], "mongodb", "mongodb"),
    m(&["Redis"], "redis", "redis"),
    m(&["Elasticsearch"], "elastic", "elasticsearch"),
    m(&["MariaDB"], "mariadb", "mariadb"),
    m(&["Kibana"], "elastic", "kibana"),
    m(&["Apache Cassandra"], "apache", "cassandra"),
    m(&["InfluxDB"], "influxdata", "influxdb"),
    // ── Runtimes ──────────────────────────────────────────────────────
    m(&["Java "], "oracle", "jdk"),
    m(&["OpenJDK"], "oracle", "openjdk"),
    m(&["AdoptOpenJDK"], "eclipse", "adoptopenjdk"),
    m(&["Amazon Corretto"], "amazon", "corretto"),
    // ── Virtualization / Containers ───────────────────────────────────
    m(&["Docker Desktop"], "docker", "docker_desktop"),
    // NVD files VirtualBox under vm_virtualbox (464 CVEs); `virtualbox` holds
    // a single 2008 entry, so mapping there hid every modern VirtualBox CVE.
    m(&["VirtualBox"], "oracle", "vm_virtualbox"),
    m(&["VMware"], "vmware", "workstation"),
    m(&["Vagrant"], "hashicorp", "vagrant"),
    // ── Communication ─────────────────────────────────────────────────
    m(&["Zoom"], "zoom", "zoom"),
    m(&["Slack"], "slack", "slack"),
    m(&["Telegram"], "telegram", "telegram_desktop"),
    m(&["Signal"], "signal", "signal_desktop"),
    // ── Cloud / DevOps tools ──────────────────────────────────────────
    m(&["AWS CLI"], "amazon", "aws_command_line_interface"),
    m(&["Google Cloud SDK"], "google", "cloud_sdk"),
    m(&["Terraform"], "hashicorp", "terraform"),
    m(&["Vault"], "hashicorp", "vault"),
    m(&["Consul"], "hashicorp", "consul"),
    m(&["Packer"], "hashicorp", "packer"),
    m(&["Helm"], "helm", "helm"),
    // ── Security tools ────────────────────────────────────────────────
    m(&["Malwarebytes"], "malwarebytes", "malwarebytes"),
    m(&["WireGuard"], "wireguard", "wireguard"),
    m(&["OpenVPN"], "openvpn", "openvpn"),
    m(&["Nmap"], "nmap", "nmap"),
    m(&["1Password"], "agilebits", "1password"),
    m(&["LastPass"], "logmein", "lastpass"),
    m(&["Bitwarden"], "bitwarden", "bitwarden"),
    m(
        &["Avast Free Antivirus", "Avast Antivirus"],
        "avast",
        "avast_free_antivirus",
    ),
    m(&["AVG AntiVirus"], "avg", "avg_antivirus"),
    m(&["Norton"], "symantec", "norton_security"),
    m(&["Kaspersky"], "kaspersky", "kaspersky_anti-virus"),
    m(&["ESET NOD32"], "eset", "nod32"),
    m(&["ESET Smart Security"], "eset", "smart_security"),
    m(&["Bitdefender"], "bitdefender", "bitdefender_antivirus"),
    m(&["CCleaner"], "piriform", "ccleaner"),
    m(&["CrowdStrike Falcon"], "crowdstrike", "falcon"),
    m(&["SentinelOne"], "sentinelone", "sentinelone"),
    m(&["Carbon Black"], "vmware", "carbon_black_cloud_sensor"),
    m(&["Sophos Endpoint"], "sophos", "endpoint_protection"),
    m(&["Sophos"], "sophos", "sophos_anti-virus"),
    m(&["Trend Micro"], "trendmicro", "officescan"),
    m(&["McAfee Agent"], "mcafee", "agent"),
    m(&["McAfee"], "mcafee", "endpoint_security"),
    m(&["Fortinet FortiClient", "FortiClient"], "fortinet", "forticlient"),
    m(&["Webroot"], "webroot", "secureanywhere"),
    m(&["Cylance"], "blackberry", "cylanceprotect"),
    // ── Enterprise monitoring ─────────────────────────────────────────
    m(&["Splunk Universal Forwarder"], "splunk", "universal_forwarder"),
    m(&["Splunk Enterprise", "Splunk"], "splunk", "splunk"),
    m(&["Grafana"], "grafana", "grafana"),
    m(&["Datadog Agent"], "datadog", "agent"),
    m(&["Zabbix Agent"], "zabbix", "zabbix_agent"),
    m(&["New Relic"], "newrelic", "infrastructure_agent"),
    // ── Networking / VPN ──────────────────────────────────────────────
    m(&["Cisco AnyConnect"], "cisco", "anyconnect_secure_mobility_client"),
    m(&["GlobalProtect"], "paloaltonetworks", "globalprotect"),
    m(&["Pulse Secure"], "ivanti", "connect_secure"),
    m(&["OpenSSH"], "openbsd", "openssh"),
    m(&["Tailscale"], "tailscale", "tailscale"),
    m(&["ZeroTier"], "zerotier", "zerotierone"),
    // ── Remote access ─────────────────────────────────────────────────
    m(&["TeamViewer"], "teamviewer", "teamviewer"),
    m(&["AnyDesk"], "anydesk", "anydesk"),
    m(&["Citrix Workspace"], "citrix", "workspace_app"),
    m(&["Citrix Receiver"], "citrix", "receiver"),
    m(&["RustDesk"], "rustdesk", "rustdesk"),
    // ── Enterprise software ───────────────────────────────────────────
    m(&["SAP GUI"], "sap", "gui_for_windows"),
    m(&["SAP Business Client"], "sap", "business_client"),
    m(&["Sourcetree"], "atlassian", "sourcetree"),
    // ── Media / Office ────────────────────────────────────────────────
    m(&["iTunes"], "apple", "itunes"),
    m(&["QuickTime"], "apple", "quicktime"),
    m(&["GIMP"], "gimp", "gimp"),
    m(&["LibreOffice"], "libreoffice", "libreoffice"),
    m(&["OpenOffice"], "apache", "openoffice"),
    m(&["FFmpeg"], "ffmpeg", "ffmpeg"),
    m(&["HandBrake"], "handbrake", "handbrake"),
    m(&["Inkscape"], "inkscape", "inkscape"),
    m(&["Paint.NET"], "dotpdn", "paint.net"),
    // ── Web servers ───────────────────────────────────────────────────
    m(&["Apache HTTP Server"], "apache", "http_server"),
    m(&["nginx"], "nginx", "nginx"),
    m(&["Apache Tomcat"], "apache", "tomcat"),
    // ── Phase A expansion: Microsoft ──────────────────────────────────
    m(&["Mozilla Firefox ESR"], "mozilla", "firefox_esr"),
    m(&["Microsoft OneNote"], "microsoft", "onenote"),
    m(&["Microsoft Publisher"], "microsoft", "publisher"),
    m(&["Microsoft Visio"], "microsoft", "visio"),
    m(&["Microsoft Project"], "microsoft", "project"),
    m(&["Microsoft SharePoint Server"], "microsoft", "sharepoint_server"),
    m(&["Microsoft Exchange Server"], "microsoft", "exchange_server"),
    m(&["Microsoft Dynamics 365"], "microsoft", "dynamics_365"),
    m(&["Microsoft Power BI", "Power BI Desktop"], "microsoft", "power_bi"),
    m(&["Microsoft Remote Desktop"], "microsoft", "remote_desktop"),
    m(
        &["Microsoft Office LTSC"],
        "microsoft",
        "office_long_term_servicing_channel",
    ),
    m(&["Azure Data Studio"], "microsoft", "azure_data_studio"),
    m(&["Microsoft Silverlight"], "microsoft", "silverlight"),
    m(&["Microsoft DirectX"], "microsoft", "directx"),
    m(&["Windows Media Player"], "microsoft", "windows_media_player"),
    m(&["Sysinternals Suite"], "microsoft", "sysinternals"),
    m(&["Process Explorer"], "sysinternals", "process_explorer"),
    // ── Phase A expansion: Adobe ──────────────────────────────────────
    m(&["Adobe Acrobat DC"], "adobe", "acrobat_dc"),
    m(&["Adobe ColdFusion"], "adobe", "coldfusion"),
    m(&["Adobe FrameMaker"], "adobe", "framemaker"),
    m(&["Adobe Audition"], "adobe", "audition"),
    m(&["Adobe Media Encoder"], "adobe", "media_encoder"),
    m(&["Adobe Character Animator"], "adobe", "character_animator"),
    m(&["Adobe InCopy"], "adobe", "incopy"),
    m(&["Adobe Dimension"], "adobe", "dimension"),
    m(&["Adobe RoboHelp"], "adobe", "robohelp"),
    m(&["Adobe Captivate"], "adobe", "captivate"),
    m(&["Adobe Digital Editions"], "adobe", "digital_editions"),
    m(&["Adobe AIR"], "adobe", "air"),
    m(&["Adobe Shockwave Player"], "adobe", "shockwave_player"),
    // ── Phase A expansion: runtimes / languages ───────────────────────
    m(&["Java SE Development Kit", "Oracle Java"], "oracle", "java_se"),
    m(&["Java Runtime Environment"], "oracle", "jre"),
    m(&["Azul Zulu"], "azul", "zulu"),
    m(&["Oracle Database"], "oracle", "database"),
    m(&["Scala"], "scala-lang", "scala"),
    m(&["Julia"], "julialang", "julia"),
    // ── Phase A expansion: dev tools ──────────────────────────────────
    m(&["ReSharper"], "jetbrains", "resharper"),
    m(&["TeamCity"], "jetbrains", "teamcity"),
    m(&["YouTrack"], "jetbrains", "youtrack"),
    m(&["Kotlin"], "jetbrains", "kotlin"),
    m(&["JetBrains Toolbox"], "jetbrains", "toolbox"),
    m(&["MobaXterm"], "mobatek", "mobaxterm"),
    m(&["SoapUI"], "smartbear", "soapui"),
    m(&["Obsidian"], "obsidian", "obsidian"),
    m(&["Atlassian Jira", "Jira"], "atlassian", "jira"),
    m(&["Confluence"], "atlassian", "confluence"),
    m(&["Bitbucket"], "atlassian", "bitbucket"),
    m(&["GitHub CLI"], "github", "cli"),
    m(&["GitLab"], "gitlab", "gitlab"),
    m(&["Jenkins"], "jenkins", "jenkins"),
    m(&["Ansible"], "ansible", "ansible"),
    m(&["Kubernetes"], "kubernetes", "kubernetes"),
    m(&["Docker Engine"], "docker", "engine"),
    m(&["Podman"], "podman_project", "podman"),
    m(&["HashiCorp Nomad"], "hashicorp", "nomad"),
    m(&["HashiCorp Boundary"], "hashicorp", "boundary"),
    // ── Phase A expansion: remote access / terminals ──────────────────
    m(&["TeamViewer Remote"], "teamviewer", "remote"),
    m(&["RealVNC Server", "VNC Server"], "realvnc", "vnc_server"),
    m(&["VNC Viewer"], "realvnc", "vnc_viewer"),
    m(&["TigerVNC"], "tigervnc", "tigervnc"),
    m(&["UltraVNC"], "uvnc", "ultravnc"),
    m(&["TightVNC"], "tightvnc", "tightvnc"),
    m(&["Splashtop Streamer"], "splashtop", "streamer"),
    m(
        &["ScreenConnect", "ConnectWise Control"],
        "connectwise",
        "screenconnect",
    ),
    m(&["BeyondTrust Remote Support"], "beyondtrust", "remote_support"),
    m(&["mRemoteNG"], "mremoteng", "mremoteng"),
    m(&["Bitvise SSH Client"], "bitvise", "ssh_client"),
    m(&["Bitvise SSH Server"], "bitvise", "ssh_server"),
    m(&["SecureCRT"], "vandyke", "securecrt"),
    m(&["KiTTY"], "9bis", "kitty"),
    m(&["Termius"], "termius", "termius"),
    m(&["Tabby"], "tabby", "tabby"),
    m(&["Cmder"], "cmder", "cmder"),
    m(&["Starship"], "starship", "starship"),
    // ── Phase A expansion: file transfer / sync ───────────────────────
    m(&["SmartFTP"], "smartftp", "smartftp"),
    m(&["Core FTP"], "coreftp", "core_ftp"),
    m(&["Cyberduck"], "cyberduck", "cyberduck"),
    m(&["Rclone"], "rclone", "rclone"),
    m(&["Syncthing"], "syncthing", "syncthing"),
    m(&["Dropbox"], "dropbox", "dropbox"),
    m(&["Google Drive"], "google", "drive"),
    m(&["Nextcloud Desktop", "Nextcloud"], "nextcloud", "desktop"),
    m(&["ownCloud"], "owncloud", "owncloud"),
    // ── Phase A expansion: communication ──────────────────────────────
    m(&["Zoom Workplace"], "zoom", "workplace"),
    m(&["Zoom Rooms"], "zoom", "rooms"),
    m(
        &["Cisco Webex Meetings", "Webex Meetings"],
        "cisco",
        "webex_meetings",
    ),
    m(&["Webex Teams"], "cisco", "webex_teams"),
    m(&["Cisco Jabber"], "cisco", "jabber"),
    m(&["RingCentral"], "ringcentral", "ringcentral"),
    m(
        &["Mattermost Desktop", "Mattermost"],
        "mattermost",
        "mattermost_desktop",
    ),
    m(&["Rocket.Chat"], "rocket.chat", "rocket.chat"),
    m(&["Element"], "element", "element"),
    m(&["Mumble"], "mumble", "mumble"),
    m(&["TeamSpeak 3"], "teamspeak", "teamspeak3"),
    m(&["TeamSpeak"], "teamspeak", "teamspeak"),
    // ── Phase A expansion: gaming / GPU / hardware ────────────────────
    m(&["Epic Games Launcher"], "epicgames", "launcher"),
    m(&["Origin"], "ea", "origin"),
    m(&["GOG Galaxy"], "gog", "galaxy"),
    m(&["Battle.net"], "blizzard", "battle.net"),
    m(&["Razer Synapse"], "razer", "synapse"),
    m(&["Corsair iCUE", "iCUE"], "corsair", "icue"),
    m(&["NVIDIA GeForce Experience"], "nvidia", "geforce_experience"),
    m(&["NVIDIA Graphics Driver"], "nvidia", "gpu_display_driver"),
    m(&["NVIDIA CUDA Toolkit"], "nvidia", "cuda_toolkit"),
    m(&["AMD Radeon Software"], "amd", "radeon_software"),
    m(&["Intel Graphics Driver"], "intel", "graphics_driver"),
    m(&["ASUS Armoury Crate"], "asus", "armoury_crate"),
    m(&["MSI Afterburner"], "msi", "afterburner"),
    m(&["EVGA Precision X1"], "evga", "precision_x1"),
    m(&["CPU-Z"], "cpuid", "cpu-z"),
    // ── Phase A expansion: system utilities / backup ──────────────────
    m(&["Wise Care 365"], "wisecleaner", "wise_care_365"),
    m(&["Advanced SystemCare"], "iobit", "advanced_systemcare"),
    m(&["Driver Booster"], "iobit", "driver_booster"),
    m(&["Glary Utilities"], "glarysoft", "glary_utilities"),
    m(&["BleachBit"], "bleachbit", "bleachbit"),
    m(&["ImgBurn"], "imgburn", "imgburn"),
    m(&["PowerISO"], "poweriso", "poweriso"),
    m(&["UltraISO"], "ezbsystems", "ultraiso"),
    m(&["WinImage"], "winimage", "winimage"),
    m(&["DAEMON Tools"], "daemon-tools", "daemon_tools"),
    m(&["Acronis True Image"], "acronis", "true_image"),
    m(&["Acronis Cyber Protect"], "acronis", "cyber_protect"),
    m(&["Veritas Backup Exec"], "veritas", "backup_exec"),
    m(&["Macrium Reflect"], "macrium", "reflect"),
    m(&["EaseUS Todo Backup"], "easeus", "todo_backup"),
    m(&["MiniTool Partition Wizard"], "minitool", "partition_wizard"),
    // ── Phase A expansion: security ───────────────────────────────────
    m(&["Avira Antivirus"], "avira", "antivirus"),
    m(&["Avira Free Antivirus"], "avira", "free_antivirus"),
    m(&["F-Secure SAFE"], "f-secure", "safe"),
    m(&["F-Secure Internet Security"], "f-secure", "internet_security"),
    m(&["G DATA Antivirus"], "gdata", "antivirus"),
    m(&["Panda Dome"], "pandasecurity", "panda_dome"),
    m(&["Comodo Internet Security"], "comodo", "internet_security"),
    m(&["Comodo Antivirus"], "comodo", "antivirus"),
    m(&["ZoneAlarm"], "checkpoint", "zonealarm"),
    m(
        &["Check Point Endpoint Security"],
        "checkpoint",
        "endpoint_security",
    ),
    m(
        &["Check Point Harmony Endpoint", "Harmony Endpoint"],
        "checkpoint",
        "harmony_endpoint",
    ),
    m(
        &["Symantec Endpoint Protection"],
        "symantec",
        "endpoint_protection",
    ),
    m(&["Qualys Cloud Agent"], "qualys", "cloud_agent"),
    m(&["Rapid7 Insight Agent"], "rapid7", "insight_agent"),
    m(&["Nessus Agent"], "tenable", "nessus_agent"),
    m(&["Nessus"], "tenable", "nessus"),
    m(&["Metasploit"], "rapid7", "metasploit"),
    m(&["Burp Suite"], "portswigger", "burp_suite"),
    m(&["Hashcat"], "hashcat", "hashcat"),
    m(&["Aircrack-ng"], "aircrack-ng", "aircrack-ng"),
    m(&["Npcap"], "nmap", "npcap"),
    m(&["WinPcap"], "winpcap", "winpcap"),
    m(&["mitmproxy"], "mitmproxy", "mitmproxy"),
    m(&["Telerik Fiddler", "Fiddler"], "telerik", "fiddler"),
    m(&["Charles"], "charlesproxy", "charles"),
    m(&["tcpdump"], "tcpdump", "tcpdump"),
    // ── Phase A expansion: database tools ─────────────────────────────
    m(&["MongoDB Compass"], "mongodb", "compass"),
    m(&["HeidiSQL"], "heidisql", "heidisql"),
    m(&["Oracle SQL Developer"], "oracle", "sql_developer"),
    m(&["MySQL Workbench"], "oracle", "mysql_workbench"),
    m(&["phpMyAdmin"], "phpmyadmin", "phpmyadmin"),
    m(&["Adminer"], "adminer", "adminer"),
    m(&["Hoppscotch"], "hoppscotch", "hoppscotch"),
    // ── Phase A expansion: Apache / big data ──────────────────────────
    m(&["Apache Kafka"], "apache", "kafka"),
    m(&["Apache ZooKeeper"], "apache", "zookeeper"),
    m(&["Apache Spark"], "apache", "spark"),
    m(&["Apache Hadoop"], "apache", "hadoop"),
    m(&["Apache Airflow"], "apache", "airflow"),
    m(&["Apache NiFi"], "apache", "nifi"),
    m(&["Apache ActiveMQ"], "apache", "activemq"),
    m(&["Apache CouchDB"], "apache", "couchdb"),
    m(&["Apache Solr"], "apache", "solr"),
    m(&["Apache Struts"], "apache", "struts"),
    m(&["Apache Log4j"], "apache", "log4j"),
    // ── Phase A expansion: monitoring / observability ─────────────────
    m(&["RabbitMQ"], "vmware", "rabbitmq"),
    m(&["Telegraf"], "influxdata", "telegraf"),
    m(&["Prometheus"], "prometheus", "prometheus"),
    m(&["Grafana Loki"], "grafana", "loki"),
    m(&["Grafana Tempo"], "grafana", "tempo"),
    m(&["Logstash"], "elastic", "logstash"),
    m(&["Filebeat"], "elastic", "filebeat"),
    m(&["Fluentd"], "fluentd", "fluentd"),
    m(&["Dynatrace OneAgent"], "dynatrace", "oneagent"),
    m(&["Nagios XI"], "nagios", "nagios_xi"),
    m(&["Zabbix"], "zabbix", "zabbix"),
    m(&["PRTG Network Monitor"], "paessler", "prtg_network_monitor"),
    m(&["SolarWinds Orion"], "solarwinds", "orion_platform"),
    // ── Phase A expansion: IT management ──────────────────────────────
    m(
        &["ManageEngine Desktop Central"],
        "zohocorp",
        "manageengine_desktop_central",
    ),
    m(
        &["ManageEngine ServiceDesk Plus"],
        "zohocorp",
        "manageengine_servicedesk_plus",
    ),
    m(&["Ivanti Endpoint Manager"], "ivanti", "endpoint_manager"),
    m(&["Ivanti Automation"], "ivanti", "automation"),
    m(&["Lansweeper"], "lansweeper", "lansweeper"),
    m(&["Scoop"], "scoop", "scoop"),
    // ── Phase A expansion: PDF / imaging ──────────────────────────────
    m(&["Foxit Reader"], "foxitsoftware", "foxit_reader"),
    m(&["Foxit PDF Reader"], "foxit", "pdf_reader"),
    m(&["Foxit PDF Editor"], "foxit", "pdf_editor"),
    m(&["Sumatra PDF", "SumatraPDF"], "sumatrapdfreader", "sumatrapdf"),
    m(&["Nitro Pro"], "gonitro", "nitro_pro"),
    m(
        &["Wondershare PDFelement", "PDFelement"],
        "wondershare",
        "pdfelement",
    ),
    m(&["ABBYY FineReader"], "abbyy", "finereader"),
    m(&["IrfanView"], "irfanview", "irfanview"),
    m(&["XnView"], "xnview", "xnview"),
    m(&["FastStone Image Viewer"], "faststone", "image_viewer"),
    m(&["ImageMagick"], "imagemagick", "imagemagick"),
    m(&["TechSmith Snagit", "Snagit"], "techsmith", "snagit"),
    m(&["Loom"], "loom", "loom"),
    m(&["MediaInfo"], "mediaarea", "mediainfo"),
    // ── Phase A expansion: media / downloads ──────────────────────────
    m(&["Ardour"], "ardour", "ardour"),
    m(&["MuseScore"], "musescore", "musescore"),
    m(&["Winamp"], "winamp", "winamp"),
    m(&["AIMP"], "aimp", "aimp"),
    m(&["Plex Media Server"], "plex", "media_server"),
    m(&["Jellyfin"], "jellyfin", "jellyfin"),
    m(&["Kodi"], "kodi", "kodi"),
    m(&["qBittorrent"], "qbittorrent", "qbittorrent"),
    m(&["BitTorrent"], "bittorrent", "bittorrent"),
    m(&["uTorrent"], "utorrent", "utorrent"),
    m(&["Transmission"], "transmissionbt", "transmission"),
    m(&["Deluge"], "deluge-torrent", "deluge"),
    m(
        &["Internet Download Manager"],
        "tonec",
        "internet_download_manager",
    ),
    m(
        &["Free Download Manager"],
        "freedownloadmanager",
        "free_download_manager",
    ),
    m(&["Wget"], "gnu", "wget"),
    m(&["cURL"], "haxx", "curl"),
    m(&["HTTPie"], "httpie", "httpie"),
    // ── Phase A expansion: package managers / science ─────────────────
    m(&["Yarn"], "yarnpkg", "yarn"),
    m(&["pnpm"], "pnpm", "pnpm"),
    m(&["Bower"], "bower", "bower"),
    m(&["Composer"], "getcomposer", "composer"),
    m(&["RubyGems"], "rubygems", "rubygems"),
    m(&["Jupyter Notebook"], "jupyter", "notebook"),
    m(&["JupyterLab"], "jupyter", "jupyterlab"),
    m(&["Scilab"], "scilab", "scilab"),
    m(&["MiKTeX"], "miktex", "miktex"),
    m(&["TeX Live"], "tug", "texlive"),
    // ── Phase A expansion: productivity / notes ───────────────────────
    m(&["Notion"], "notion", "notion"),
    m(&["Evernote"], "evernote", "evernote"),
    m(&["Joplin"], "joplinapp", "joplin"),
    m(&["Typora"], "typora", "typora"),
    m(&["MarkText", "Mark Text"], "marktext", "marktext"),
    m(&["Zettlr"], "zettlr", "zettlr"),
    m(&["Trello"], "trello", "trello"),
    m(&["ClickUp"], "clickup", "clickup"),
    m(&["Todoist"], "doist", "todoist"),
    m(&["Grammarly"], "grammarly", "grammarly"),
    // ── Phase A expansion: design / diagramming ───────────────────────
    m(&["Figma Desktop", "Figma"], "figma", "desktop"),
    m(&["Sketch"], "sketch", "sketch"),
    m(&["draw.io", "drawio"], "diagrams", "drawio"),
    m(&["yEd"], "yworks", "yed"),
    m(&["Graphviz"], "graphviz", "graphviz"),
    m(&["PlantUML"], "plantuml", "plantuml"),
    m(&["Excalidraw"], "excalidraw", "excalidraw"),
    m(&["Miro"], "miro", "miro"),
    // ── Phase A expansion: 3D / CAD / game engines ────────────────────
    m(&["Unreal Engine"], "epicgames", "unreal_engine"),
    m(&["Godot Engine"], "godotengine", "godot_engine"),
    m(&["Autodesk Maya", "Maya"], "autodesk", "maya"),
    m(&["Autodesk 3ds Max", "3ds Max"], "autodesk", "3ds_max"),
    m(&["AutoCAD"], "autodesk", "autocad"),
    m(&["Autodesk Fusion 360", "Fusion 360"], "autodesk", "fusion_360"),
    m(&["Autodesk Revit"], "autodesk", "revit"),
    m(&["Autodesk Inventor"], "autodesk", "inventor"),
    m(&["Autodesk SketchBook"], "autodesk", "sketchbook"),
    m(&["SketchUp"], "trimble", "sketchup"),
    m(&["Siemens NX"], "siemens", "nx"),
    m(&["Solid Edge"], "siemens", "solid_edge"),
    m(&["OpenSCAD"], "openscad", "openscad"),
    m(&["Altium Designer"], "altium", "designer"),
    m(&["Arduino IDE"], "arduino", "arduino_ide"),
    // ── Windows OS releases (os_version scanner) ──────────────────────
    // Release-specific only — the generic windows_10/windows_11 products
    // aggregate all releases and would over-match.
    m(&["Windows 10 1507"], "microsoft", "windows_10_1507"),
    m(&["Windows 10 1511"], "microsoft", "windows_10_1511"),
    m(&["Windows 10 1607"], "microsoft", "windows_10_1607"),
    m(&["Windows 10 1703"], "microsoft", "windows_10_1703"),
    m(&["Windows 10 1709"], "microsoft", "windows_10_1709"),
    m(&["Windows 10 1803"], "microsoft", "windows_10_1803"),
    m(&["Windows 10 1809"], "microsoft", "windows_10_1809"),
    m(&["Windows 10 1903"], "microsoft", "windows_10_1903"),
    m(&["Windows 10 1909"], "microsoft", "windows_10_1909"),
    m(&["Windows 10 2004"], "microsoft", "windows_10_2004"),
    m(&["Windows 10 20H2"], "microsoft", "windows_10_20h2"),
    m(&["Windows 10 21H1"], "microsoft", "windows_10_21h1"),
    m(&["Windows 10 21H2"], "microsoft", "windows_10_21h2"),
    m(&["Windows 10 22H2"], "microsoft", "windows_10_22h2"),
    m(&["Windows 11 21H2"], "microsoft", "windows_11_21h2"),
    m(&["Windows 11 22H2"], "microsoft", "windows_11_22h2"),
    m(&["Windows 11 23H2"], "microsoft", "windows_11_23h2"),
    m(&["Windows 11 24H2"], "microsoft", "windows_11_24h2"),
    m(&["Windows 11 25H2"], "microsoft", "windows_11_25h2"),
    m(&["Windows 11 26H1"], "microsoft", "windows_11_26h1"),
    m(&["Windows Server 2016"], "microsoft", "windows_server_2016"),
    m(&["Windows Server 2019"], "microsoft", "windows_server_2019"),
    m(&["Windows Server 2022"], "microsoft", "windows_server_2022"),
    m(&["Windows Server 2025"], "microsoft", "windows_server_2025"),
    // ── Bundled libraries (DLL fingerprinting) ────────────────────────
    m(&["zlib"], "zlib", "zlib"),
    m(&["libxml2"], "xmlsoft", "libxml2"),
    m(&["libpng"], "libpng", "libpng"),
    m(&["FreeType"], "freetype", "freetype"),
    m(&["libjpeg-turbo"], "libjpeg-turbo", "libjpeg-turbo"),
    // ── pip packages ──────────────────────────────────────────────────
    m(&["django"],        "djangoproject",          "django"),
    m(&["flask"],         "palletsprojects",         "flask"),
    m(&["requests"],      "python-requests",         "requests"),
    m(&["pillow"],        "python-pillow",           "pillow"),
    m(&["urllib3"],       "urllib3",                 "urllib3"),
    m(&["cryptography"],  "cryptography-developers", "cryptography"),
    m(&["paramiko"],      "paramiko",                "paramiko"),
    m(&["numpy"],         "numpy",                   "numpy"),
    m(&["tensorflow"],    "google",                  "tensorflow"),
    m(&["setuptools"],    "python",                  "setuptools"),
    m(&["pip"],           "pypa",                    "pip"),
    m(&["jinja2"],        "palletsprojects",         "jinja2"),
    m(&["pyyaml"],        "pyyaml",                  "pyyaml"),
    m(&["certifi"],       "certifi",                 "python-certifi"),
    m(&["tornado"],       "tornadoweb",              "tornado"),
    m(&["aiohttp"],       "aio-libs",                "aiohttp"),
    // ── npm packages ──────────────────────────────────────────────────
    m(&["lodash"],        "lodash",                  "lodash"),
    m(&["express"],       "openjsf",                 "express"),
    m(&["axios"],         "axios",                   "axios"),
    m(&["minimist"],      "minimist_project",        "minimist"),
    m(&["tough-cookie"],  "salesforce",              "tough-cookie"),
    m(&["jquery"],        "jquery",                  "jquery"),
    m(&["node-fetch"],    "node-fetch",              "node-fetch"),
    m(&["qs"],            "ljharb",                  "qs"),
    m(&["json5"],         "json5",                   "json5"),
    m(&["marked"],        "marked",                  "marked"),
    m(&["ws"],            "ws_project",              "ws"),
    m(&["tar"],           "npm",                     "tar"),
    m(&["semver"],        "npmjs",                   "semver"),
    // ── cargo / rust crates ───────────────────────────────────────────
    m(&["openssl"],       "openssl",                 "openssl"),
    m(&["hyper"],         "hyper",                   "hyper"),
    m(&["rustls"],        "rustls",                  "rustls"),
];

/// Total number of display-name patterns (aliases) across all curated
/// mappings — the "table size" for seeding logs and coverage tests.
fn curated_alias_count() -> usize {
    KNOWN_MAPPINGS.iter().map(|e| e.aliases.len()).sum()
}

/// Phase B: explicit "this name is NOT this product" overrides.
///
/// Each entry vetoes a (vendor, product) identity for any software whose
/// display name contains every pattern token. Catches wrong-product matches
/// that scoring alone cannot separate — companion tools that carry the parent
/// product's name but their own (tiny) version stream, so every historical
/// CVE range "matches". The canonical case: "Microsoft Edge Update" v1.3.x
/// flagged with the full Edge browser CVE history.
/// A product of `"*"` vetoes every product for that vendor — used for
/// updater/companion tools whose own version stream is wrong against any
/// of the vendor's real products (the Edge updater carries the Edge name
/// but a 1.3.x version, so it "matches" both edge_chromium and legacy edge).
const NEGATIVE_MAPPINGS: &[(&str, &str, &str)] = &[
    ("Microsoft Edge Update", "microsoft", "*"),
    ("Microsoft Edge WebView", "microsoft", "edge_chromium"),
    ("Google Update", "google", "*"),
    ("Google Chrome Elevation Service", "google", "*"),
    ("Mozilla Maintenance Service", "mozilla", "*"),
    ("Python Launcher", "python", "python"),
    ("Java Auto Updater", "oracle", "*"),
    ("Adobe Genuine Service", "adobe", "*"),
];

/// Does a negative mapping veto this (name, vendor, product) combination?
fn is_negated(name_tokens: &[String], vendor: &str, product: &str) -> bool {
    NEGATIVE_MAPPINGS.iter().any(|(pattern, v, p)| {
        *v == vendor
            && (*p == "*" || *p == product)
            && is_subset(&tokenize(pattern), name_tokens)
    })
}

/// CPE `target_sw` values that identify ecosystem-scoped rows. Desktop
/// software must not match them, and each package ecosystem only matches
/// its own (plus wildcard rows).
const ECOSYSTEM_TARGET_SW: &[&str] = &[
    "python", "node.js", "nodejs", "rust", "ruby", "perl", "php",
    "wordpress", "drupal", "joomla", "jenkins", "magento", "shopify",
];

/// Is a CPE row with this `target_sw` applicable to software detected via
/// `scheme` (the `registry_key` prefix: `pip`, `npm`, `cargo`, `registry`,
/// `pe`, ...)? `None`/wildcard rows apply to everything; ecosystem-scoped
/// rows only apply to their own ecosystem's packages.
fn target_sw_applies(scheme: &str, target_sw: Option<&str>) -> bool {
    let Some(t) = target_sw else { return true };
    let t = t.to_ascii_lowercase();
    match scheme {
        "pip" => t == "python" || !ECOSYSTEM_TARGET_SW.contains(&t.as_str()),
        "npm" => t == "node.js" || t == "nodejs" || !ECOSYSTEM_TARGET_SW.contains(&t.as_str()),
        "cargo" => t == "rust" || !ECOSYSTEM_TARGET_SW.contains(&t.as_str()),
        _ => !ECOSYSTEM_TARGET_SW.contains(&t.as_str()),
    }
}

/// Publisher name → CPE vendor mapping
const PUBLISHER_VENDORS: &[(&str, &str)] = &[
    ("Microsoft Corporation", "microsoft"),
    ("Microsoft", "microsoft"),
    ("Google LLC", "google"),
    ("Google Inc", "google"),
    ("Mozilla", "mozilla"),
    ("Adobe Inc.", "adobe"),
    ("Adobe Systems", "adobe"),
    ("Oracle Corporation", "oracle"),
    ("Oracle", "oracle"),
    ("Apple Inc.", "apple"),
    ("Valve Corporation", "valvesoftware"),
    ("Valve", "valvesoftware"),
    ("Discord Inc.", "discord"),
    ("Python Software Foundation", "python"),
    ("The Git Development Community", "git-scm"),
    ("Node.js Foundation", "nodejs"),
    ("OpenJS Foundation", "nodejs"),
    ("Igor Pavlov", "7-zip"),
    ("VideoLAN", "videolan"),
    ("Notepad++ Team", "notepad-plus-plus"),
    ("Don HO", "notepad-plus-plus"),
    ("win.rar GmbH", "rarlab"),
    ("RARLAB", "rarlab"),
    ("Simon Tatham", "putty"),
    ("Martin Prikryl", "winscp"),
    ("Tim Kosse", "filezilla-project"),
    ("Wireshark Foundation", "wireshark"),
    ("Gerald Combs", "wireshark"),
    ("OBS", "obsproject"),
    ("Docker Inc.", "docker"),
    ("Zoom Video Communications", "zoom"),
    ("Slack Technologies", "slack"),
    ("Telegram FZ-LLC", "telegram"),
    ("Telegram", "telegram"),
    ("Brave Software Inc", "brave"),
    ("Opera Software", "opera"),
    ("SQLite Development Team", "sqlite"),
    ("PostgreSQL Global Development", "postgresql"),
    ("VMware, Inc.", "vmware"),
    ("Malwarebytes", "malwarebytes"),
    ("WireGuard LLC", "wireguard"),
    ("OpenVPN", "openvpn"),
    ("Spotify AB", "spotify"),
    ("Spotify", "spotify"),
    ("Nmap Project", "nmap"),
    ("AgileBits", "agilebits"),
    ("LogMeIn", "logmein"),
    ("Bitwarden Inc.", "bitwarden"),
    ("Avast Software", "avast"),
    ("AVG Technologies", "avg"),
    ("Symantec", "symantec"),
    ("NortonLifeLock", "symantec"),
    ("Gen Digital", "symantec"),
    ("Kaspersky Lab", "kaspersky"),
    ("ESET", "eset"),
    ("Bitdefender", "bitdefender"),
    ("Piriform", "piriform"),
    ("Skype Technologies", "microsoft"),
    ("JetBrains", "jetbrains"),
    ("Google LLC", "google"),
    ("Android Studio", "google"),
    ("Sublime HQ", "sublimehq"),
    ("Postman, Inc.", "postman"),
    ("Postman Inc", "postman"),
    ("Apache Software Foundation", "apache"),
    ("The Document Foundation", "libreoffice"),
    ("GIMP developers", "gimp"),
    ("Inkscape", "inkscape"),
    ("FFmpeg", "ffmpeg"),
    ("Apple Inc.", "apple"),
    ("TeamViewer", "teamviewer"),
    ("AnyDesk Software", "anydesk"),
    ("Citrix Systems", "citrix"),
    ("WinZip Computing", "winzip_computing"),
    ("HandBrake", "handbrake"),
    ("ruby-lang", "ruby-lang"),
    ("The PHP Group", "php"),
    ("pgAdmin Development Team", "postgresql"),
    ("DBeaver Corp", "dbeaver"),
    // --- Security vendors ---
    ("CrowdStrike", "crowdstrike"),
    ("SentinelOne", "sentinelone"),
    ("Carbon Black", "vmware"),
    ("Sophos", "sophos"),
    ("Trend Micro", "trendmicro"),
    ("McAfee", "mcafee"),
    ("Fortinet", "fortinet"),
    ("Webroot", "webroot"),
    ("Cylance", "blackberry"),
    // --- Networking / VPN ---
    ("Cisco Systems", "cisco"),
    ("Cisco", "cisco"),
    ("Palo Alto Networks", "paloaltonetworks"),
    ("Tailscale", "tailscale"),
    ("ZeroTier", "zerotier"),
    ("Pulse Secure", "pulsesecure"),
    // --- Cloud / DevOps ---
    ("HashiCorp", "hashicorp"),
    ("Amazon Web Services", "amazon"),
    ("Amazon.com", "amazon"),
    // --- Databases ---
    ("MongoDB Inc", "mongodb"),
    ("MongoDB, Inc.", "mongodb"),
    ("Redis Ltd", "redis"),
    ("Elastic", "elastic"),
    ("MariaDB", "mariadb"),
    ("MariaDB Corporation", "mariadb"),
    ("InfluxData", "influxdata"),
    ("Apache Cassandra", "apache"),
    // --- Monitoring ---
    ("Splunk", "splunk"),
    ("Grafana Labs", "grafana"),
    ("Datadog", "datadog"),
    ("Zabbix", "zabbix"),
    ("New Relic", "newrelic"),
    // --- Enterprise ---
    ("SAP SE", "sap"),
    ("SAP", "sap"),
    ("Atlassian", "atlassian"),
    // --- Development ---
    ("ActiveState", "activestate"),
    ("Lua.org", "lua"),
    ("Ericsson", "erlang"),
    ("Gradle Inc", "gradle"),
    ("LLVM", "llvm"),
    ("Eclipse Foundation", "eclipse"),
    // --- Media / Creative ---
    ("Audacity Team", "audacityteam"),
    ("Blender Foundation", "blender"),
    ("Krita Foundation", "krita"),
    ("Blackmagic Design", "blackmagicdesign"),
    ("Shotcut", "meltytech"),
    // --- Communication ---
    ("Signal Foundation", "signal"),
    ("Signal Messenger", "signal"),
    // --- Remote access ---
    ("RustDesk", "rustdesk"),
    // --- Virtualization ---
    ("Vagrant", "hashicorp"),
    // --- Misc ---
    ("paint.net", "dotpdn"),
    ("Vivaldi Technologies", "vivaldi"),
    // libcurl.dll commonly embeds "cURL" / "the curl project" as CompanyName
    ("curl", "haxx"),
];

/// CVE matcher that correlates software to vulnerabilities
pub struct CveMatcher {
    conn: Connection,
    /// Phase 4: in-memory CPE index, built once at startup. Replaces the
    /// per-software SQL lookups against `cpe_matches` — ~100× faster on the
    /// 3M-row production DB.
    index: CpeIndex,
    /// Phase C: CPE dictionary title index for broad name matching. Empty
    /// (and inert) when the database predates the `cpe_dictionary` table.
    dict: DictIndex,
}

impl CveMatcher {
    /// Open the CVE database and seed product mappings if needed
    pub fn new(db_path: &str) -> Result<Self> {
        if !Path::new(db_path).exists() {
            return Err(ScanError::DatabaseNotFound(db_path.to_string()));
        }

        let conn = Connection::open(db_path)?;

        // Ensure cpe_matches has a `version` column for exact-version matching.
        // Harmless if already present (ALTER fails silently on duplicate column).
        let _ = conn.execute("ALTER TABLE cpe_matches ADD COLUMN version TEXT", []);

        // Seed the product_mappings table if empty
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM product_mappings",
            [],
            |row| row.get(0),
        ).unwrap_or(0);

        if count == 0 {
            info!("Seeding product_mappings table with {} known mappings", curated_alias_count());
            let tx = conn.unchecked_transaction()?;
            {
                let mut stmt = conn.prepare(
                    "INSERT OR IGNORE INTO product_mappings (display_name_pattern, cpe_vendor, cpe_product, confidence)
                     VALUES (?1, ?2, ?3, 1.0)"
                )?;
                for entry in KNOWN_MAPPINGS {
                    for alias in entry.aliases {
                        stmt.execute(params![alias, entry.vendor, entry.product])?;
                    }
                }
            }
            tx.commit()?;
            info!("Seeded {} product mappings", curated_alias_count());
        }

        info!("Opened CVE database: {}", db_path);

        // Phase 4: build the in-memory CPE index once. This is an ~8s cost
        // on the 3M-row production DB but drops subsequent per-software
        // lookups from prepared-statement SQL to HashMap::get.
        let index = CpeIndex::build(&conn)?;

        // Phase C: CPE dictionary title index (empty on pre-Phase-C DBs).
        let dict = DictIndex::build(&conn);

        Ok(Self { conn, index, dict })
    }

    /// Find vulnerabilities for detected software using token-based matching.
    ///
    /// Phase 3: rank all curated-mapping candidates by a weighted score, then
    /// fall back to publisher-vendor correlation if no curated match clears
    /// the threshold. Jaccard-style token matching kills false positives like
    /// "Python Launcher" matching the `python` CPE product.
    pub fn find_vulnerabilities(
        &self,
        software: &DetectedSoftware,
    ) -> Result<Vec<(Vulnerability, MatchConfidence, Option<String>)>> {
        let version = software.version.as_deref().unwrap_or("");
        let name_tokens = tokenize(&software.name);
        let publisher_vendor = software
            .publisher
            .as_ref()
            .and_then(|p| self.resolve_vendor(p));
        // Detection-source scheme ("pip", "npm", "cargo", "registry", "pe",
        // ...) gates ecosystem-scoped CPE rows via target_sw.
        let scheme = software.registry_key.split("://").next().unwrap_or("");

        // Layer 1: score every curated mapping and pick the best above threshold.
        if let Some(mut identity) =
            self.lookup_curated_mapping(&name_tokens, publisher_vendor)
        {
            if ecosystem_exact_alias(scheme, &name_tokens, &identity.vendor, &identity.product) {
                identity.confidence = MatchConfidence::Exact;
            }
            debug!(
                "Curated match: {} → {}:{} (confidence: {:?})",
                software.name, identity.vendor, identity.product, identity.confidence
            );
            return self.find_cves_for_identity(&identity, version, scheme, Some(&software.name));
        }

        // Layer 1.5 (Phase C): CPE dictionary title match. Broad coverage
        // from the official NVD dictionary, gated behind a stricter score
        // threshold than the curated table and capped at High confidence
        // because titles are not hand-verified.
        if let Some((score, vendor, product)) = self.dict.lookup(&name_tokens, publisher_vendor) {
            if !is_negated(&name_tokens, vendor, product) {
                debug!(
                    "Dictionary match: {} → {}:{} (score {:.2})",
                    software.name, vendor, product, score
                );
                let confidence = match confidence_from_score(score) {
                    MatchConfidence::Exact => MatchConfidence::High,
                    other => other,
                };
                let identity = CpeIdentity {
                    vendor: vendor.to_string(),
                    product: product.to_string(),
                    confidence,
                };
                let results = self.find_cves_for_identity(&identity, version, scheme, Some(&software.name))?;
                if !results.is_empty() {
                    return Ok(results);
                }
            }
        }

        // Layer 2: Try publisher → vendor correlation
        if let Some(vendor) = publisher_vendor {
            let product = extract_product_name(&software.name);
            if !is_negated(&name_tokens, vendor, &product) {
                debug!(
                    "Publisher match: {} (by {:?}) → {}:{} (confidence: High)",
                    software.name, software.publisher, vendor, product
                );
                let identity = CpeIdentity {
                    vendor: vendor.to_string(),
                    product,
                    confidence: MatchConfidence::High,
                };
                let results = self.find_cves_for_identity(&identity, version, scheme, Some(&software.name))?;
                if !results.is_empty() {
                    return Ok(results);
                }
            }
        }

        // Layer 3: Exact product name match only (no substring matching)
        let product = extract_product_name(&software.name);
        debug!(
            "Fallback exact match: {} → product={}",
            software.name, product
        );
        let identity = CpeIdentity {
            vendor: String::new(), // no vendor filter
            product,
            confidence: MatchConfidence::Medium,
        };
        self.find_cves_for_identity(&identity, version, scheme, Some(&software.name))
    }

    /// Coverage diagnostic: does any matching layer resolve this software to
    /// a CPE identity backed by at least one row in the index? Distinguishes
    /// "identity resolved, currently no applicable CVEs" (healthy) from
    /// "never correlated" (a coverage gap worth curating). Returns a human-
    /// readable `vendor:product (layer)` description on success.
    pub fn resolves_identity(&self, software: &DetectedSoftware) -> Option<String> {
        let name_tokens = tokenize(&software.name);
        let publisher_vendor = software
            .publisher
            .as_ref()
            .and_then(|p| self.resolve_vendor(p));

        if let Some(identity) = self.lookup_curated_mapping(&name_tokens, publisher_vendor) {
            if !self
                .find_cpe_strict(&identity.vendor, &identity.product)
                .unwrap_or_default()
                .is_empty()
            {
                return Some(format!("{}:{} (curated)", identity.vendor, identity.product));
            }
        }

        if let Some((_, vendor, product)) = self.dict.lookup(&name_tokens, publisher_vendor) {
            if !is_negated(&name_tokens, vendor, product)
                && !self
                    .find_cpe_strict(vendor, product)
                    .unwrap_or_default()
                    .is_empty()
            {
                return Some(format!("{}:{} (dictionary)", vendor, product));
            }
        }

        if let Some(vendor) = publisher_vendor {
            let product = extract_product_name(&software.name);
            if !is_negated(&name_tokens, vendor, &product)
                && !self
                    .find_cpe_strict(vendor, &product)
                    .unwrap_or_default()
                    .is_empty()
            {
                return Some(format!("{}:{} (publisher)", vendor, product));
            }
        }

        let product = extract_product_name(&software.name);
        if !self
            .find_cpe_product_only(&product)
            .unwrap_or_default()
            .is_empty()
        {
            return Some(format!("*:{} (product-name)", product));
        }

        None
    }

    /// Layer 1: token-scored lookup against the curated mapping table.
    ///
    /// For every entry in `KNOWN_MAPPINGS`, tokenise the pattern and compute a
    /// score in `[0, 1]`. Keep the highest-scoring candidate whose score is at
    /// least `CURATED_MIN_SCORE`. Mapping `f32 → MatchConfidence` keeps the
    /// enum-based display behaviour.
    fn lookup_curated_mapping(
        &self,
        name_tokens: &[String],
        publisher_vendor: Option<&str>,
    ) -> Option<CpeIdentity> {
        let mut best: Option<(f32, &str, &str)> = None;

        for entry in KNOWN_MAPPINGS {
            // Phase B: a negative mapping vetoes this identity for this name.
            if is_negated(name_tokens, entry.vendor, entry.product) {
                continue;
            }
            for alias in entry.aliases {
                let pattern_tokens = tokenize(alias);
                if pattern_tokens.is_empty() {
                    continue;
                }
                let score = score_curated_match(
                    name_tokens,
                    &pattern_tokens,
                    publisher_vendor,
                    entry.vendor,
                );
                if score >= CURATED_MIN_SCORE
                    && score > best.as_ref().map(|(s, _, _)| *s).unwrap_or(0.0)
                {
                    best = Some((score, entry.vendor, entry.product));
                }
            }
        }

        best.map(|(score, vendor, product)| CpeIdentity {
            vendor: vendor.to_string(),
            product: product.to_string(),
            confidence: confidence_from_score(score),
        })
    }

    /// Resolve a publisher name to a CPE vendor
    fn resolve_vendor(&self, publisher: &str) -> Option<&'static str> {
        let publisher_lower = publisher.to_lowercase();
        for (pub_pattern, vendor) in PUBLISHER_VENDORS {
            if publisher_lower.contains(&pub_pattern.to_lowercase()) {
                return Some(vendor);
            }
        }
        None
    }

    /// Find CVEs for a resolved CPE identity using strict matching
    fn find_cves_for_identity(
        &self,
        identity: &CpeIdentity,
        version: &str,
        scheme: &str,
        display_name: Option<&str>,
    ) -> Result<Vec<(Vulnerability, MatchConfidence, Option<String>)>> {
        let cpe_matches = if !identity.vendor.is_empty() {
            // Strict: match both vendor AND product exactly
            self.find_cpe_strict(&identity.vendor, &identity.product)?
        } else {
            // Product-only exact match (no substring)
            self.find_cpe_product_only(&identity.product)?
        };

        if cpe_matches.is_empty() {
            return Ok(Vec::new());
        }

        let mut vulnerabilities = Vec::new();

        // Group by CVE before deciding. NVD publishes several rows per CVE —
        // some with a version range, others unbounded wildcards for a
        // different configuration. Judging each row independently and taking
        // the first "yes" let a wildcard row override a bounded row that had
        // already established the installed version is patched. `cve_is_
        // vulnerable` resolves the whole group at once.
        //
        // Insertion order is preserved so the emitted CVE order (and the
        // representative row chosen below) stays deterministic across runs.
        let mut by_cve: Vec<(String, Vec<CpeMatchRecord>)> = Vec::new();
        let mut cve_slot: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for cpe_match in cpe_matches {
            // Ecosystem gate: a wordpress-plugin or python-library CPE row
            // never applies to a desktop exe, and vice versa.
            if !target_sw_applies(scheme, cpe_match.target_sw.as_deref()) {
                continue;
            }
            match cve_slot.get(&cpe_match.cve_id) {
                Some(&i) => by_cve[i].1.push(cpe_match),
                None => {
                    cve_slot.insert(cpe_match.cve_id.clone(), by_cve.len());
                    by_cve.push((cpe_match.cve_id.clone(), vec![cpe_match]));
                }
            }
        }

        for (cve_id, rows) in by_cve {
            let refs: Vec<&CpeMatchRecord> = rows.iter().collect();
            if !cve_is_vulnerable(version, display_name, &refs) {
                continue;
            }

            // Derive the fixed version from the CPE row that established this
            // finding — see `fixed_version_for`. Reading the bound off a row
            // that had no part in the decision is how a finding came to display
            // "Upgrade to v>2012" next to an installed 18.0.11715.348, and how
            // a PostgreSQL 16.1 install was told to upgrade to 12.21.
            let fixed_version = fixed_version_for(version, display_name, &refs);

            if let Some(vuln) = self.get_cve_details(&cve_id, fixed_version.as_deref())? {
                let vendor = if identity.vendor.is_empty() {
                    None
                } else {
                    Some(identity.vendor.clone())
                };
                vulnerabilities.push((vuln, identity.confidence, vendor));
            }
        }

        debug!(
            "Found {} CVEs for {}:{}",
            vulnerabilities.len(),
            identity.vendor,
            identity.product
        );
        Ok(vulnerabilities)
    }

    /// Strict CPE query: exact vendor + exact product.
    /// Phase 4: served from the in-memory [`CpeIndex`], not SQL.
    fn find_cpe_strict(&self, vendor: &str, product: &str) -> Result<Vec<CpeMatchRecord>> {
        Ok(self.index.find_strict(vendor, product))
    }

    /// Product-only exact match (no vendor filter, no substring).
    /// Phase 4: served from the in-memory [`CpeIndex`], not SQL. The old
    /// path capped the result set at `LIMIT 500`; the in-memory lookup has
    /// no such cap since the index is already bounded by product-key size.
    fn find_cpe_product_only(&self, product: &str) -> Result<Vec<CpeMatchRecord>> {
        Ok(self.index.find_by_product(product))
    }

    /// Check if a software version falls within the vulnerable range
    /// Get CVE details from database. Joins `epss` and `kev` on the left so
    /// findings still surface when those tables are empty (older DBs built
    /// before Phase 5) or when the feeds failed to sync.
    ///
    /// `fixed_version` is derived from CPE range boundaries by the caller.
    pub(crate) fn get_cve_details(
        &self,
        cve_id: &str,
        fixed_version: Option<&str>,
    ) -> Result<Option<Vulnerability>> {
        let mut stmt = self.conn.prepare(
            "SELECT c.cve_id, c.description, c.cvss_v3_score, c.severity, c.published_date,
                    e.score, e.percentile,
                    k.due_date, k.ransomware_use,
                    CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END AS in_kev
             FROM cves c
             LEFT JOIN epss e ON e.cve_id = c.cve_id
             LEFT JOIN kev  k ON k.cve_id = c.cve_id
             WHERE c.cve_id = ?1",
        )?;

        let result = stmt.query_row(params![cve_id], |row| {
            let cve = CveRecord {
                cve_id: row.get(0)?,
                description: row.get(1)?,
                cvss_score: row.get(2)?,
                severity: row.get(3)?,
                published_date: row.get(4)?,
            };
            let epss_score: Option<f64> = row.get(5)?;
            let epss_percentile: Option<f64> = row.get(6)?;
            let kev_due_date: Option<String> = row.get(7)?;
            let kev_ransomware_use: Option<String> = row.get(8)?;
            let in_kev: i64 = row.get(9)?;
            Ok((
                cve,
                epss_score.map(|v| v as f32),
                epss_percentile.map(|v| v as f32),
                kev_due_date,
                kev_ransomware_use,
                in_kev != 0,
            ))
        });

        match result {
            Ok((cve, epss_score, epss_percentile, kev_due_date, kev_ransomware_use, in_kev)) => {
                let (references, kb_articles) = self.get_cve_references_with_kb(cve_id)?;
                let vendor_advisory = references
                    .iter()
                    .find(|r| r.contains("advisory") || r.contains("security"))
                    .cloned();

                let severity = cve
                    .severity
                    .as_ref()
                    .map(|s| Severity::from_str(s))
                    .or_else(|| cve.cvss_score.map(Severity::from_score))
                    .unwrap_or(Severity::Unknown);

                // Build a specific recommendation based on available data
                let recommendation = build_recommendation(fixed_version, &kb_articles);

                Ok(Some(Vulnerability {
                    cve_id: cve.cve_id,
                    description: cve.description,
                    cvss_score: cve.cvss_score,
                    severity,
                    published_date: cve.published_date,
                    references: references.into_iter().take(5).collect(),
                    remediation: Remediation {
                        recommendation,
                        fixed_version: fixed_version.map(|v| v.to_string()),
                        vendor_advisory,
                        kb_articles,
                        upgrade_command: None, // populated later with software context
                    },
                    epss_score,
                    epss_percentile,
                    in_kev,
                    kev_due_date,
                    kev_ransomware_use,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get reference URLs for a CVE and extract Microsoft KB article IDs.
    fn get_cve_references_with_kb(
        &self,
        cve_id: &str,
    ) -> Result<(Vec<String>, Vec<String>)> {
        let mut stmt = self
            .conn
            .prepare("SELECT url, tags FROM cve_references WHERE cve_id = ?1 LIMIT 10")?;

        let rows = stmt.query_map(params![cve_id], |row| {
            let url: String = row.get(0)?;
            let tags: Option<String> = row.get(1)?;
            Ok((url, tags))
        })?;

        let mut urls = Vec::new();
        let mut kb_articles = Vec::new();

        for row in rows.flatten() {
            let (url, tags) = row;

            // Extract KB numbers from Microsoft URLs
            if let Some(kb) = extract_kb_from_url(&url) {
                if !kb_articles.contains(&kb) {
                    kb_articles.push(kb);
                }
            }

            // Also check tags for "Patch" indicator (NVD tags KB-related refs)
            if let Some(ref t) = tags {
                if t.contains("Patch") || t.contains("Vendor Advisory") {
                    if let Some(kb) = extract_kb_from_url(&url) {
                        if !kb_articles.contains(&kb) {
                            kb_articles.push(kb);
                        }
                    }
                }
            }

            urls.push(url);
        }

        Ok((urls, kb_articles))
    }

    /// True when any reference for `cve_id` carries NVD's `Exploit` tag
    /// (FR-63). Deliberately separate from `get_cve_references_with_kb`,
    /// whose `LIMIT 10` would hide the tag on a later reference.
    pub fn has_exploit_reference(&self, cve_id: &str) -> Result<bool> {
        let found: i64 = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM cve_references
                            WHERE cve_id = ?1 AND tags LIKE '%\"Exploit\"%')",
            params![cve_id],
            |r| r.get(0),
        )?;
        Ok(found == 1)
    }

    /// Get database statistics. CPE count comes from the in-memory index so
    /// we don't re-count the 3M-row table on every CLI invocation.
    pub fn get_stats(&self) -> Result<(i64, i64)> {
        let cve_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM cves", [], |row| row.get(0))?;

        Ok((cve_count, self.index.len() as i64))
    }

    /// Access the underlying SQLite connection.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

// ── Patch recommendation helpers ──────────────────────────────────────────────

/// Extract a Microsoft KB article number from a reference URL.
fn extract_kb_from_url(url: &str) -> Option<String> {
    let lower = url.to_lowercase();
    // support.microsoft.com/kb/1234567 or /help/1234567
    if lower.contains("support.microsoft.com") {
        if let Some(pos) = lower.find("/kb/").or_else(|| lower.find("/help/")) {
            let digits_start = if lower[pos..].starts_with("/help/") {
                &url[pos + 6..]
            } else {
                &url[pos + 4..]
            };
            let kb_num: String = digits_start.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !kb_num.is_empty() {
                return Some(format!("KB{}", kb_num));
            }
        }
    }
    // portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-...
    // These don't have KB numbers, but catalog.update.microsoft.com does:
    // catalog.update.microsoft.com/Search.aspx?q=KB1234567
    if lower.contains("catalog.update.microsoft.com") {
        if let Some(pos) = lower.find("kb") {
            let after = &url[pos + 2..];
            let kb_num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !kb_num.is_empty() {
                return Some(format!("KB{}", kb_num));
            }
        }
    }
    None
}

/// Build a human-readable recommendation string from available patch data.
fn build_recommendation(fixed_version: Option<&str>, kb_articles: &[String]) -> String {
    match (fixed_version, kb_articles.is_empty()) {
        (Some(ver), false) => format!(
            "Update to version {} or later. Apply Microsoft patch {}.",
            ver,
            kb_articles.join(", ")
        ),
        (Some(ver), true) => format!("Update to version {} or later.", ver),
        (None, false) => format!(
            "Apply Microsoft patch {}.",
            kb_articles.join(", ")
        ),
        (None, true) => "Update to the latest patched version.".to_string(),
    }
}

/// Generate an upgrade command based on the software's source (registry_key
/// scheme prefix) and the target version or package name.
pub fn build_upgrade_command(
    registry_key: &str,
    software_name: &str,
    fixed_version: Option<&str>,
) -> Option<String> {
    let scheme = &registry_key[..registry_key.find("://")?];

    // Normalise the package name for CLI tools (lowercase, no spaces)
    let pkg = software_name.to_lowercase().replace(' ', "-");

    match scheme {
        "winget" | "registry" => {
            // winget can upgrade by name; --version pin if we know the target
            match fixed_version {
                Some(ver) => Some(format!(
                    "winget upgrade --name \"{}\" --version {}",
                    software_name, ver
                )),
                None => Some(format!("winget upgrade --name \"{}\"", software_name)),
            }
        }
        "chocolatey" => {
            match fixed_version {
                Some(ver) => Some(format!("choco upgrade {} --version={} -y", pkg, ver)),
                None => Some(format!("choco upgrade {} -y", pkg)),
            }
        }
        "scoop" => Some(format!("scoop update {}", pkg)),
        "pip" => {
            match fixed_version {
                Some(ver) => Some(format!("pip install --upgrade {}=={}", pkg, ver)),
                None => Some(format!("pip install --upgrade {}", pkg)),
            }
        }
        "npm" => {
            match fixed_version {
                Some(ver) => Some(format!("npm install -g {}@{}", pkg, ver)),
                None => Some(format!("npm update -g {}", pkg)),
            }
        }
        "cargo" => {
            match fixed_version {
                Some(ver) => Some(format!("cargo install {} --version {}", pkg, ver)),
                None => Some(format!("cargo install {}", pkg)),
            }
        }
        _ => None,
    }
}

// ── Free functions (pub(crate) so tests can call them directly) ───────────────

use crate::normalize::Version;

/// Score a curated mapping candidate against a tokenised software name.
///
/// Returns a value in `[0.0, 1.0]`:
///
/// * `0.0` if the pattern tokens are not a subset of the name tokens (i.e. at
///   least one pattern word is missing from the display name)
/// * `0.70` base for a clean subset match
/// * minus `0.25` per extra *meaningful* name token — pure-numeric tokens like
///   `3`, `13` from `"Python 3.13"` do NOT count as meaningful, so version
///   numbers don't penalise the match, but `"launcher"` in `"Python Launcher"`
///   does
/// * plus `0.25` if the software's publisher resolves to the same CPE vendor
/// * plus `0.05` if the CPE vendor name appears as one of the tokens in the
///   display name (e.g. `"google"` in `"Google Chrome"`)
///
/// The score is clamped to `[0.0, 1.0]`.
/// Is this a package-manager entry whose name is exactly a curated alias of
/// `vendor:product`?
///
/// For `pip://`, `npm://` and `cargo://` entries the name is the registry's own
/// package identifier, not free-text display copy, so an exact alias is an
/// exact identity. Scored like a display name it got 0.70 (Medium), and the
/// default `--min-confidence high` hid real findings such as pip 26.1.2's
/// CVE-2026-13346. Registry and PE names are free text and keep their score.
pub(crate) fn ecosystem_exact_alias(
    scheme: &str,
    name_tokens: &[String],
    vendor: &str,
    product: &str,
) -> bool {
    matches!(scheme, "pip" | "npm" | "cargo")
        && KNOWN_MAPPINGS
            .iter()
            .filter(|e| e.vendor == vendor && e.product == product)
            .flat_map(|e| e.aliases.iter())
            .any(|alias| tokenize(alias) == name_tokens)
}

pub(crate) fn score_curated_match(
    name_tokens: &[String],
    pattern_tokens: &[String],
    publisher_vendor: Option<&str>,
    cpe_vendor: &str,
) -> f32 {
    if pattern_tokens.is_empty() || !is_subset(pattern_tokens, name_tokens) {
        return 0.0;
    }

    let pattern_set: std::collections::HashSet<&String> = pattern_tokens.iter().collect();
    let extra_tokens: Vec<&String> = name_tokens
        .iter()
        .filter(|t| !pattern_set.contains(t))
        .filter(|t| !t.chars().all(|c| c.is_ascii_digit()))
        .collect();

    // An installer/updater/uninstaller word among the extra tokens means this
    // binary is a companion artifact of the product, not the product — it
    // carries the product's name with its own version stream, so matching it
    // would flag every CVE fixed in between. Reject outright.
    if extra_tokens
        .iter()
        .any(|t| classify_token(t) == TokenClass::Artifact)
    {
        return 0.0;
    }

    // Per-token penalty for the remaining extra tokens: identity-bearing
    // words cost full weight, edition qualifiers a token amount, packaging
    // noise nothing.
    let extra_penalty: f32 = extra_tokens
        .iter()
        .map(|t| match classify_token(t) {
            TokenClass::Core => 0.25,
            TokenClass::Qualifier => 0.05,
            TokenClass::Noise | TokenClass::Artifact => 0.0,
        })
        .sum();

    let mut score = 0.70_f32 - extra_penalty;

    if let Some(pv) = publisher_vendor {
        if pv.eq_ignore_ascii_case(cpe_vendor) {
            score += 0.25;
        }
    }

    let cpe_vendor_lower = cpe_vendor.to_ascii_lowercase();
    if name_tokens.contains(&cpe_vendor_lower) {
        score += 0.05;
    }

    score.clamp(0.0, 1.0)
}

/// Map a numeric score back to the `MatchConfidence` display enum.
pub(crate) fn confidence_from_score(score: f32) -> MatchConfidence {
    if score >= SCORE_EXACT {
        MatchConfidence::Exact
    } else if score >= SCORE_HIGH {
        MatchConfidence::High
    } else if score >= SCORE_MEDIUM {
        MatchConfidence::Medium
    } else {
        MatchConfidence::Low
    }
}

/// Check whether `version` (the version of installed software) falls within
/// the vulnerable range or matches the exact version pinned on a CPE entry.
/// The numbering system a version string belongs to.
///
/// Two strings can both parse as versions and still be meaningless to compare:
/// a build number and a release date are different kinds of thing.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum VersionScheme {
    /// `2021-04-10` — an ISO date used as a version bound.
    Date,
    /// `2012` — a bare release year, as in "Visual Studio 2012".
    Year,
    /// `154.0.1`, `18.0.11715.348` — an ordinary dotted version.
    Dotted,
}

fn scheme_of(s: &str) -> VersionScheme {
    let s = s.trim().trim_start_matches('>').trim();

    // YYYY-MM-DD
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() == 3
        && parts[0].len() == 4
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
    {
        if let Ok(y) = parts[0].parse::<u32>() {
            if (1990..=2100).contains(&y) {
                return VersionScheme::Date;
            }
        }
    }

    // A bare four-digit year, with no other components.
    if !s.contains('.') && s.len() == 4 && s.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(y) = s.parse::<u32>() {
            if (1990..=2100).contains(&y) {
                return VersionScheme::Year;
            }
        }
    }

    VersionScheme::Dotted
}

/// Can these two strings be meaningfully compared as versions?
///
/// Both `2.10.91.91 < 2021-04-10` and `18.0.11715.348 < 2012` are arithmetic
/// that parses and means nothing: the first compares a Steam build number to a
/// date, the second a Visual Studio build number to a marketing year. Before
/// this check the matcher performed both and reported the findings.
///
/// A calendar version (`2021.4`) against a year is deliberately allowed —
/// both are year-led, and refusing would drop genuine CalVer findings.
pub(crate) fn schemes_comparable(installed: &str, bound: &str) -> bool {
    let a = scheme_of(installed);
    let b = scheme_of(bound);

    if a == b {
        return true;
    }

    // A dotted version whose first component is a plausible year is CalVer,
    // which is legitimately comparable with a bare year.
    let calver_like = |s: &str| -> bool {
        s.split('.')
            .next()
            .and_then(|h| h.parse::<u32>().ok())
            .is_some_and(|y| (1990..=2100).contains(&y))
    };

    match (a, b) {
        (VersionScheme::Year, VersionScheme::Dotted) => calver_like(bound),
        (VersionScheme::Dotted, VersionScheme::Year) => calver_like(installed),
        // Anything involving a Date on exactly one side is a category error.
        _ => false,
    }
}

/// Does this row carry any version range at all?
fn row_has_range(m: &CpeMatchRecord) -> bool {
    m.version_start_including.is_some()
        || m.version_end_excluding.is_some()
        || m.version_start_excluding.is_some()
        || m.version_end_including.is_some()
}

/// The version an operator should upgrade to, read off the CPE row that
/// established this finding.
///
/// `version_end_excluding` is the first safe version. `version_end_including`
/// means "still vulnerable at that version", so the fix is unknown and is
/// displayed as `>{version}`.
fn fixed_version_for(
    version: &str,
    display_name: Option<&str>,
    rows: &[&CpeMatchRecord],
) -> Option<String> {
    // A CVE spanning several maintained branches publishes one row per branch,
    // each with its own fix. Taking the first row that merely *has* a range
    // advised "upgrade to 12.21" for a PostgreSQL 16.1 install — a version four
    // branches below what was already installed. The row that established the
    // finding is the only one whose bound is advice.
    let representative = rows
        .iter()
        .find(|m| row_has_range(m) && bounded_row_establishes(version, display_name, m))
        .or_else(|| rows.iter().find(|m| row_has_range(m)))?;

    representative
        .version_end_excluding
        .as_deref()
        .map(|v| v.to_string())
        .or_else(|| {
            representative
                .version_end_including
                .as_deref()
                .map(|v| format!(">{}", v))
        })
}

/// Decide vulnerability for ONE CVE given every CPE row NVD published for it
/// under this (vendor, product).
///
/// NVD emits several rows per CVE — some with a version range, others
/// unbounded wildcards covering a different configuration. Evaluating them
/// independently and taking the first "yes" lets a wildcard row silently
/// override a bounded row that already established the installed version is
/// patched. Measured on the live database, 947,205 of 3,175,789 rows (29.8%)
/// are unbounded wildcards, each asserting vulnerability for EVERY version.
///
/// So: **if NVD published a range anywhere for this CVE, the ranges decide.**
/// The wildcard rows are treated as the less specific duplicate they are.
///
/// When NO row carries a range, the wildcard still reports. Absence of version
/// data is not evidence of safety, and dropping the finding there would be a
/// false negative — the failure this project consistently refuses to trade for
/// quieter output.
pub(crate) fn cve_is_vulnerable(
    version: &str,
    display_name: Option<&str>,
    rows: &[&CpeMatchRecord],
) -> bool {
    if rows.is_empty() {
        return false;
    }

    let bounded: Vec<&&CpeMatchRecord> = rows.iter().filter(|m| row_has_range(m)).collect();

    if !bounded.is_empty() {
        return bounded
            .iter()
            .any(|m| bounded_row_establishes(version, display_name, m));
    }

    rows.iter().any(|m| is_version_vulnerable_fn(version, m))
}

/// Extract a four-digit release year from a product's display name.
///
/// "Microsoft® Visual Studio® 2010" carries the year the version string does
/// not: `10.0.60910.0` cannot be compared to a bound of `2012`, but `2010`
/// can. Without this, dropping incomparable pairs would also drop genuine
/// findings against year-named products.
fn year_from_name(name: &str) -> Option<u32> {
    name.split(|c: char| !c.is_ascii_digit())
        .filter(|t| t.len() == 4)
        .filter_map(|t| t.parse::<u32>().ok())
        .find(|y| (1990..=2100).contains(y))
}

/// Does this bounded row establish that the installed version is vulnerable?
///
/// A bound from a different numbering system establishes nothing.
/// `2.10.91.91 < 2021-04-10` and `18.0.11715.348 < 2012` both parse and both
/// mean nothing — the first compares a Steam build number to a date, the
/// second a Visual Studio build number to a marketing year.
///
/// When the version cannot be compared but the DISPLAY NAME carries a year,
/// that year is used instead. This is what keeps "Visual Studio 2010"
/// (genuinely before the 2013 fix) reported while dropping "Visual Studio"
/// BuildTools 18.x, whose name carries no year and whose 18.x build number
/// says nothing about a 2012 boundary.
fn bounded_row_establishes(
    version: &str,
    display_name: Option<&str>,
    m: &CpeMatchRecord,
) -> bool {
    let bounds = [
        m.version_start_including.as_deref(),
        m.version_end_excluding.as_deref(),
        m.version_start_excluding.as_deref(),
        m.version_end_including.as_deref(),
    ];

    let incomparable = bounds
        .into_iter()
        .flatten()
        .any(|b| !schemes_comparable(version, b));

    if !incomparable {
        return is_version_vulnerable_fn(version, m);
    }

    // Fall back to a year lifted from the display name, when there is one and
    // it is actually comparable with the bound.
    let Some(year) = display_name.and_then(year_from_name) else {
        return false;
    };
    let year_str = year.to_string();
    if bounds
        .into_iter()
        .flatten()
        .any(|b| !schemes_comparable(&year_str, b))
    {
        return false;
    }

    is_version_vulnerable_fn(&year_str, m)
}

pub(crate) fn is_version_vulnerable_fn(version: &str, cpe_match: &CpeMatchRecord) -> bool {
    if version.is_empty() {
        return false;
    }

    let installed = match Version::parse(version) {
        Some(v) => v,
        None => return false,
    };

    let has_any_range = cpe_match.version_start_including.is_some()
        || cpe_match.version_end_excluding.is_some()
        || cpe_match.version_start_excluding.is_some()
        || cpe_match.version_end_including.is_some();

    // Phase 2: exact-version fallback when no range is present.
    // NVD often emits `cpe:2.3:a:vendor:product:1.2.3:*` — a single pinned
    // version with no range fields. Without this fallback we silently miss them.
    if !has_any_range {
        return match cpe_match.version.as_deref() {
            None => false,
            // Wildcards mean "any version"
            Some("*") | Some("-") | Some("") => true,
            Some(pinned) => Version::parse(pinned).is_some_and(|p| p == installed),
        };
    }

    if let Some(ref s) = cpe_match.version_start_including {
        if let Some(start) = Version::parse(s) {
            if installed < start { return false; }
        }
    }
    if let Some(ref s) = cpe_match.version_start_excluding {
        if let Some(start) = Version::parse(s) {
            if installed <= start { return false; }
        }
    }
    if let Some(ref e) = cpe_match.version_end_excluding {
        if let Some(end) = Version::parse(e) {
            if installed >= end { return false; }
        }
    }
    if let Some(ref e) = cpe_match.version_end_including {
        if let Some(end) = Version::parse(e) {
            if installed > end { return false; }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(vsi: Option<&str>, vee: Option<&str>, vse: Option<&str>, vei: Option<&str>) -> CpeMatchRecord {
        CpeMatchRecord {
            cve_id: "CVE-2024-9999".into(),
            version: None,
            version_start_including: vsi.map(str::to_string),
            version_end_excluding:   vee.map(str::to_string),
            version_start_excluding: vse.map(str::to_string),
            version_end_including:   vei.map(str::to_string),
            target_sw: None,
        }
    }

    fn rec_exact(version: &str) -> CpeMatchRecord {
        CpeMatchRecord {
            cve_id: "CVE-2024-9999".into(),
            version: Some(version.to_string()),
            version_start_including: None,
            version_end_excluding: None,
            version_start_excluding: None,
            version_end_including: None,
            target_sw: None,
        }
    }

    #[test]
    fn empty_version_not_vulnerable() {
        assert!(!is_version_vulnerable_fn("", &rec(Some("1.0"), Some("2.0"), None, None)));
    }

    #[test]
    fn no_range_not_vulnerable() {
        assert!(!is_version_vulnerable_fn("1.5.0", &rec(None, None, None, None)));
    }

    #[test]
    fn start_including_boundary() {
        let r = rec(Some("1.0.0"), Some("2.0.0"), None, None);
        assert!( is_version_vulnerable_fn("1.0.0", &r));  // at start — vulnerable
        assert!( is_version_vulnerable_fn("1.5.0", &r));  // inside
        assert!(!is_version_vulnerable_fn("0.9.9", &r));  // before start
        assert!(!is_version_vulnerable_fn("2.0.0", &r));  // at end_excluding
        assert!(!is_version_vulnerable_fn("2.1.0", &r));  // past end
    }

    #[test]
    fn end_including_boundary() {
        let r = rec(Some("1.0.0"), None, None, Some("1.9.0"));
        assert!( is_version_vulnerable_fn("1.9.0", &r));  // at end_including — vulnerable
        assert!(!is_version_vulnerable_fn("2.0.0", &r));  // past end_including
    }

    #[test]
    fn start_excluding_boundary() {
        let r = rec(None, None, Some("1.0.0"), Some("2.0.0"));
        assert!(!is_version_vulnerable_fn("1.0.0", &r));  // at start_excluding — NOT vulnerable
        assert!( is_version_vulnerable_fn("1.0.1", &r));  // just above start_excluding
        assert!( is_version_vulnerable_fn("2.0.0", &r));  // at end_including
    }

    // Phase 1: version comparison correctness

    #[test]
    fn prerelease_correctly_excluded_from_range() {
        // Range: 1.2.0 (inclusive) to 2.0.0 (exclusive)
        // "1.2.0-beta" is less than 1.2.0, so should NOT be vulnerable
        let r = rec(Some("1.2.0"), Some("2.0.0"), None, None);
        assert!(!is_version_vulnerable_fn("1.2.0-beta", &r));
        assert!( is_version_vulnerable_fn("1.2.0", &r));
    }

    #[test]
    fn padded_version_equality() {
        // "5.0" and "5.0.0" are the same version
        let r = rec(Some("5.0"), None, None, Some("5.0"));
        assert!(is_version_vulnerable_fn("5.0.0", &r));
        assert!(is_version_vulnerable_fn("5.0", &r));
    }

    #[test]
    fn calendar_version_ordering_correct() {
        // 2023.10.5 is AFTER 2023.9.10 (month 10 > month 9)
        // Vulnerable range: [2023.1.1, 2023.10.0)
        let r = rec(Some("2023.1.1"), Some("2023.10.0"), None, None);
        assert!( is_version_vulnerable_fn("2023.9.10", &r));  // inside
        assert!(!is_version_vulnerable_fn("2023.10.5", &r));  // past end
    }

    #[test]
    fn letter_suffix_ordering() {
        let r = rec(Some("1.0a"), None, None, Some("1.0"));
        assert!( is_version_vulnerable_fn("1.0a", &r));
        assert!( is_version_vulnerable_fn("1.0b", &r));
        assert!( is_version_vulnerable_fn("1.0", &r));
    }

    // Phase 2: exact-version fallback

    #[test]
    fn exact_version_match_when_no_range() {
        let r = rec_exact("1.2.3");
        assert!( is_version_vulnerable_fn("1.2.3", &r));
        assert!( is_version_vulnerable_fn("v1.2.3", &r));
        assert!( is_version_vulnerable_fn("1.2.3.0", &r)); // padded equality
        assert!(!is_version_vulnerable_fn("1.2.4", &r));
        assert!(!is_version_vulnerable_fn("1.2.2", &r));
    }

    #[test]
    fn wildcard_version_matches_anything() {
        let r = rec_exact("*");
        assert!(is_version_vulnerable_fn("1.2.3", &r));
        assert!(is_version_vulnerable_fn("99.0", &r));

        let r = rec_exact("-");
        assert!(is_version_vulnerable_fn("1.2.3", &r));
    }

    #[test]
    fn no_range_and_no_exact_is_not_vulnerable() {
        // Legacy behaviour: nothing to match against → not vulnerable
        assert!(!is_version_vulnerable_fn("1.5.0", &rec(None, None, None, None)));
    }

    // ── Phase 3: token-based curated matching ─────────────────────────────

    use crate::normalize::tokens::tokenize as tk;

    fn s(score: f32) -> f32 {
        (score * 1000.0).round() / 1000.0
    }

    #[test]
    fn score_zero_when_pattern_not_subset_of_name() {
        // "Firefox" pattern against "Google Chrome" — disjoint
        let name = tk("Google Chrome");
        let pattern = tk("Mozilla Firefox");
        assert_eq!(score_curated_match(&name, &pattern, None, "mozilla"), 0.0);
    }

    #[test]
    fn score_exact_match_with_publisher_and_vendor_in_name() {
        // "Google Chrome" with Google publisher → max score
        let name = tk("Google Chrome");
        let pattern = tk("Google Chrome");
        let score = score_curated_match(&name, &pattern, Some("google"), "google");
        // 0.70 base + 0.25 publisher + 0.05 vendor-in-name = 1.00
        assert!((score - 1.0).abs() < 1e-5);
        assert_eq!(confidence_from_score(score), MatchConfidence::Exact);
    }

    #[test]
    fn score_python_launcher_rejected() {
        // "Python Launcher" against pattern "Python" — "launcher" marks a
        // companion artifact, so the match is vetoed outright rather than
        // merely scored below threshold.
        let name = tk("Python Launcher");
        let pattern = tk("Python");
        let score = score_curated_match(&name, &pattern, Some("microsoft"), "python");
        assert_eq!(s(score), 0.000);
        assert!(score < CURATED_MIN_SCORE);
    }

    #[test]
    fn score_python_with_version_numbers_accepted() {
        // "Python 3.13" tokens = [python, 3, 13]. Pattern "Python" is a subset.
        // The extra tokens "3" and "13" are pure-numeric so they do NOT count
        // as meaningful. This should score well enough to clear the threshold.
        let name = tk("Python 3.13");
        let pattern = tk("Python");
        let score = score_curated_match(&name, &pattern, None, "python");
        // 0.70 base + 0 extras + 0 publisher + 0.05 vendor-in-name = 0.75
        assert_eq!(s(score), 0.750);
        assert!(score >= CURATED_MIN_SCORE);
        assert_eq!(confidence_from_score(score), MatchConfidence::High);
    }

    #[test]
    fn score_python_with_publisher_is_exact() {
        // Bare "Python" with Python Software Foundation publisher → Exact
        let name = tk("Python");
        let pattern = tk("Python");
        let score = score_curated_match(&name, &pattern, Some("python"), "python");
        // 0.70 base + 0.25 publisher + 0.05 vendor-in-name = 1.00
        assert!((score - 1.0).abs() < 1e-5);
        assert_eq!(confidence_from_score(score), MatchConfidence::Exact);
    }

    #[test]
    fn score_multiword_name_without_publisher_still_accepted() {
        // "VLC Media Player" pattern is {vlc, media, player}; name is the
        // same. No extras, no publisher — subset match alone gives Medium.
        let name = tk("VLC media player");
        let pattern = tk("VLC media player");
        let score = score_curated_match(&name, &pattern, None, "videolan");
        // 0.70 base, no publisher (videolan is vendor, not in name), no vendor-in-name
        assert_eq!(s(score), 0.700);
        assert!(score >= CURATED_MIN_SCORE);
    }

    #[test]
    fn score_arch_suffixes_are_stripped_by_tokenizer() {
        // "Google Chrome (x64)" tokenises to {google, chrome}; no x64 penalty
        let name = tk("Google Chrome (x64)");
        let pattern = tk("Google Chrome");
        let score = score_curated_match(&name, &pattern, Some("google"), "google");
        assert!((score - 1.0).abs() < 1e-5);
    }

    // ── Phase A: alias + qualifier-aware scoring ──────────────────────

    #[test]
    fn acrobat_reader_dc_specific_alias_beats_loose_pattern() {
        // The Phase A motivating case: "Adobe Acrobat Reader DC" must score
        // 1.00 against its own alias and beat every looser Adobe pattern.
        let name = tk("Adobe Acrobat Reader DC");

        let exact_alias = tk("Adobe Acrobat Reader DC");
        let exact = score_curated_match(&name, &exact_alias, Some("adobe"), "adobe");
        assert!((exact - 1.0).abs() < 1e-5);
        assert_eq!(confidence_from_score(exact), MatchConfidence::Exact);

        // vs the loose "Adobe Acrobat" pattern: extra "reader" (core -0.25)
        // and "dc" (qualifier -0.05) → 0.70 - 0.30 + 0.25 + 0.05 = 0.70
        let loose = tk("Adobe Acrobat");
        let loose_score = score_curated_match(&name, &loose, Some("adobe"), "adobe");
        assert_eq!(s(loose_score), 0.700);
        assert!(exact > loose_score, "specific alias must win");
    }

    #[test]
    fn acrobat_reader_dc_resolves_via_alias_lookup() {
        // End-to-end through KNOWN_MAPPINGS: the multi-alias entry must
        // resolve to acrobat_reader_dc, not acrobat.
        let name = tk("Adobe Acrobat Reader DC");
        let mut best: Option<(f32, &str, &str)> = None;
        for entry in KNOWN_MAPPINGS {
            for alias in entry.aliases {
                let pattern = tokenize(alias);
                if pattern.is_empty() {
                    continue;
                }
                let score = score_curated_match(&name, &pattern, Some("adobe"), entry.vendor);
                if score >= CURATED_MIN_SCORE
                    && score > best.as_ref().map(|(sc, _, _)| *sc).unwrap_or(0.0)
                {
                    best = Some((score, entry.vendor, entry.product));
                }
            }
        }
        let (score, vendor, product) = best.expect("Acrobat Reader DC must match");
        assert_eq!(vendor, "adobe");
        assert_eq!(product, "acrobat_reader_dc");
        assert!((score - 1.0).abs() < 1e-5);
    }

    #[test]
    fn qualifier_tokens_cost_little() {
        // "Microsoft Office Professional Plus" vs "Microsoft Office":
        // "professional" and "plus" are qualifiers (-0.05 each)
        // → 0.70 - 0.10 + 0.25 (publisher) + 0.05 (vendor in name) = 0.90
        let name = tk("Microsoft Office Professional Plus");
        let pattern = tk("Microsoft Office");
        let score = score_curated_match(&name, &pattern, Some("microsoft"), "microsoft");
        assert_eq!(s(score), 0.900);
        assert_eq!(confidence_from_score(score), MatchConfidence::Exact);
    }

    #[test]
    fn noise_tokens_cost_nothing() {
        // "Visual C++ Redistributable Package" vs "Visual C++
        // Redistributable": "package" is packaging noise → no penalty.
        let name = tk("Visual C++ Redistributable Package");
        let pattern = tk("Visual C++ Redistributable");
        let score = score_curated_match(&name, &pattern, Some("microsoft"), "microsoft");
        assert_eq!(s(score), 0.950);
    }

    /// Companion artifacts carry the product's name with their own version
    /// stream. Observed live: "Google Chrome Installer v127" matched every
    /// Chrome CVE fixed since v127 — 2,385 findings, 73% of one scan.
    #[test]
    fn artifact_tokens_veto_the_match() {
        for artifact_name in [
            "Google Chrome Installer",
            "Microsoft Edge Update",
            "Google Chrome Setup",
            "Mozilla Firefox Uninstall",
        ] {
            let name = tk(artifact_name);
            // Match against the bare product pattern the artifact impersonates.
            let pattern: Vec<String> = name[..2].to_vec();
            let score = score_curated_match(&name, &pattern, Some("google"), "google");
            assert_eq!(
                s(score),
                0.000,
                "{artifact_name} must be vetoed as a companion artifact"
            );
        }
    }

    /// A product whose own name legitimately contains an artifact word is
    /// unaffected: the word is part of the pattern, so it is never "extra".
    #[test]
    fn artifact_word_inside_the_product_name_is_fine() {
        let name = tk("Epic Games Launcher");
        let pattern = tk("Epic Games Launcher");
        let score = score_curated_match(&name, &pattern, Some("epicgames"), "epicgames");
        assert!(score >= CURATED_MIN_SCORE, "real product must still match");
    }

    #[test]
    fn core_extra_tokens_still_reject() {
        // Precision guard: a genuinely different word still costs -0.25,
        // so "Python Launcher" stays rejected even post-Phase A.
        let name = tk("Python Launcher");
        let pattern = tk("Python");
        let score = score_curated_match(&name, &pattern, None, "python");
        assert!(score < CURATED_MIN_SCORE);
    }

    #[test]
    fn confidence_enum_boundaries() {
        assert_eq!(confidence_from_score(1.00), MatchConfidence::Exact);
        assert_eq!(confidence_from_score(SCORE_EXACT), MatchConfidence::Exact);
        assert_eq!(confidence_from_score(SCORE_HIGH), MatchConfidence::High);
        assert_eq!(confidence_from_score(SCORE_MEDIUM), MatchConfidence::Medium);
        assert_eq!(confidence_from_score(0.30), MatchConfidence::Low);
        assert_eq!(confidence_from_score(0.0), MatchConfidence::Low);
    }

    // ── Accuracy gate ────────────────────────────────────────────────────

    /// Create the fixture schema (mirrors the cve-db-builder migrations)
    /// in an empty SQLite database. Shared by the frozen and expanded
    /// accuracy-gate fixture builders.
    fn create_fixture_db(file_tag: &str) -> (Connection, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "evedoo_{}_{}.db",
            file_tag,
            std::process::id(),
        ));
        let _ = std::fs::remove_file(&path);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(FIXTURE_SCHEMA).unwrap();
        (conn, path)
    }

    const FIXTURE_SCHEMA: &str = r#"
            CREATE TABLE cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                published_date TEXT NOT NULL,
                modified_date TEXT NOT NULL,
                cvss_v3_score REAL,
                cvss_v3_vector TEXT,
                cvss_v2_score REAL,
                cvss_v2_vector TEXT,
                severity TEXT,
                exploited INTEGER DEFAULT 0,
                attack_vector TEXT, attack_complexity TEXT,
                privileges_required TEXT, user_interaction TEXT,
                scope TEXT, confidentiality_impact TEXT,
                integrity_impact TEXT, availability_impact TEXT
            );
            CREATE TABLE cpe_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                vendor TEXT NOT NULL,
                product TEXT NOT NULL,
                version TEXT,
                version_start_including TEXT,
                version_end_excluding TEXT,
                version_start_excluding TEXT,
                version_end_including TEXT,
                platform TEXT,
                vulnerable INTEGER DEFAULT 1
            );
            CREATE TABLE cve_references (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                url TEXT NOT NULL,
                source TEXT,
                tags TEXT
            );
            CREATE TABLE product_mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                display_name_pattern TEXT NOT NULL,
                cpe_vendor TEXT NOT NULL,
                cpe_product TEXT NOT NULL,
                confidence REAL DEFAULT 1.0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE epss (
                cve_id TEXT PRIMARY KEY,
                score REAL NOT NULL,
                percentile REAL NOT NULL,
                fetched_at TEXT NOT NULL
            );
            CREATE TABLE kev (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT, product TEXT,
                date_added TEXT, due_date TEXT,
                required_action TEXT, ransomware_use TEXT,
                notes TEXT, fetched_at TEXT NOT NULL
            );
            CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO schema_version (version) VALUES (1);
            "#;

    /// Build a self-contained fixture database with known CVEs and CPE
    /// configurations. Returns the path as a String (caller must delete).
    fn build_accuracy_db() -> String {
        let (conn, path) = create_fixture_db("accuracy");

        // ── Fixture CVEs ─────────────────────────────────────────────
        conn.execute_batch(
            r#"
            INSERT INTO cves (cve_id, description, published_date, modified_date, cvss_v3_score, severity)
            VALUES
                ('CVE-TEST-0001', 'Chrome RCE in versions before 121.0',
                 '2024-01-15', '2024-01-15', 8.8, 'HIGH'),
                ('CVE-TEST-0002', 'Firefox use-after-free in 115.0',
                 '2024-02-10', '2024-02-10', 7.5, 'HIGH'),
                ('CVE-TEST-0003', 'Python ReDoS in 3.11.x–3.12.x',
                 '2024-03-20', '2024-03-20', 6.5, 'MEDIUM'),
                ('CVE-TEST-0004', 'Notepad++ heap overflow before 8.7',
                 '2024-04-05', '2024-04-05', 5.5, 'MEDIUM'),
                ('CVE-TEST-0005', 'VirtualBox core flaw in 7.2.8',
                 '2026-06-17', '2026-06-17', 7.5, 'HIGH');
            "#,
        )
        .unwrap();

        // ── Fixture CPE matches ──────────────────────────────────────
        conn.execute_batch(
            r#"
            -- Chrome: all versions before 121.0 (open-ended start)
            INSERT INTO cpe_matches (cve_id, vendor, product, version_end_excluding)
            VALUES ('CVE-TEST-0001', 'google', 'chrome', '121.0');

            -- Firefox: exact version pin
            INSERT INTO cpe_matches (cve_id, vendor, product, version)
            VALUES ('CVE-TEST-0002', 'mozilla', 'firefox', '115.0');

            -- Python: range [3.11.0, 3.13.0)
            INSERT INTO cpe_matches (cve_id, vendor, product, version_start_including, version_end_excluding)
            VALUES ('CVE-TEST-0003', 'python', 'python', '3.11.0', '3.13.0');

            -- Notepad++: all versions before 8.7. Stored exactly as NVD
            -- publishes it and cve-db-builder stored it: CPE 2.3 escapes
            -- intact. This fixture used to say 'notepad%2b%2b' — agreeing
            -- with a wrong curated mapping rather than with real data, which
            -- is how every real Notepad++ CVE went unmatched while this gate
            -- stayed green.
            INSERT INTO cpe_matches (cve_id, vendor, product, version_end_excluding)
            VALUES ('CVE-TEST-0004', 'notepad-plus-plus', 'notepad\+\+', '8.7');

            -- VirtualBox: NVD files it as oracle:vm_virtualbox (464 CVEs); the
            -- curated mapping pointed at oracle:virtualbox (1 CVE, from 2008).
            INSERT INTO cpe_matches (cve_id, vendor, product, version)
            VALUES ('CVE-TEST-0005', 'oracle', 'vm_virtualbox', '7.2.8');
            "#,
        )
        .unwrap();

        // ── Optional enrichment (EPSS for one CVE, KEV for another) ──
        conn.execute_batch(
            r#"
            INSERT INTO epss (cve_id, score, percentile, fetched_at)
            VALUES ('CVE-TEST-0001', 0.87, 0.98, '2024-01-20');

            INSERT INTO kev (cve_id, vendor_project, product, date_added,
                             due_date, required_action, ransomware_use,
                             notes, fetched_at)
            VALUES ('CVE-TEST-0001', 'Google', 'Chrome', '2024-01-16',
                    '2024-02-06', 'Apply update', 'Known', NULL, '2024-01-20');
            "#,
        )
        .unwrap();

        drop(conn);
        path.to_string_lossy().into_owned()
    }

    fn sw(name: &str, version: &str, publisher: &str) -> DetectedSoftware {
        DetectedSoftware {
            name: name.to_string(),
            version: Some(version.to_string()),
            publisher: Some(publisher.to_string()),
            install_location: None,
            install_date: None,
            registry_key: format!("test://{}", name),
            architecture: crate::models::Architecture::Unknown,
        }
    }

    /// End-to-end accuracy gate: frozen software list + expected CVE set.
    ///
    /// Tests the full matching pipeline — curated mapping → publisher
    /// correlation → CpeIndex lookup → version comparison → CVE details —
    /// against a self-contained fixture DB. If a matcher refactor silently
    /// regresses recall or precision, this test catches it.
    #[test]
    fn accuracy_gate_frozen_fixture() {
        let db_path = build_accuracy_db();
        let matcher = CveMatcher::new(&db_path).expect("fixture DB must open");

        // Helper: collect CVE IDs from find_vulnerabilities result
        let cves_for = |software: &DetectedSoftware| -> Vec<String> {
            matcher
                .find_vulnerabilities(software)
                .unwrap()
                .into_iter()
                .map(|(vuln, _conf, _vendor)| vuln.cve_id)
                .collect::<Vec<_>>()
        };

        // ── True positives ───────────────────────────────────────────

        // Chrome 120 is inside the range (< 121.0)
        let chrome_120 = sw("Google Chrome", "120.0.6099.109", "Google LLC");
        let chrome_cves = cves_for(&chrome_120);
        assert!(
            chrome_cves.contains(&"CVE-TEST-0001".to_string()),
            "Chrome 120 must match CVE-TEST-0001, got: {:?}",
            chrome_cves
        );

        // Firefox 115.0 is an exact-version pin
        let ff_115 = sw("Mozilla Firefox", "115.0", "Mozilla");
        let ff_cves = cves_for(&ff_115);
        assert!(
            ff_cves.contains(&"CVE-TEST-0002".to_string()),
            "Firefox 115.0 must match CVE-TEST-0002, got: {:?}",
            ff_cves
        );

        // Python 3.12.0 is inside [3.11.0, 3.13.0)
        let python_312 = sw("Python 3.12", "3.12.0", "Python Software Foundation");
        let py_cves = cves_for(&python_312);
        assert!(
            py_cves.contains(&"CVE-TEST-0003".to_string()),
            "Python 3.12.0 must match CVE-TEST-0003, got: {:?}",
            py_cves
        );

        // Notepad++ 8.6.0 is inside (< 8.7)
        let npp = sw("Notepad++", "8.6.0", "Notepad++ Team");
        let npp_cves = cves_for(&npp);
        assert!(
            npp_cves.contains(&"CVE-TEST-0004".to_string()),
            "Notepad++ 8.6.0 must match CVE-TEST-0004, got: {:?}",
            npp_cves
        );

        // VirtualBox 7.2.8 as the Uninstall key names it: an exact pin under
        // oracle:vm_virtualbox.
        let vbox = sw("Oracle VirtualBox 7.2.8", "7.2.8", "Oracle and/or its affiliates");
        let vbox_cves = cves_for(&vbox);
        assert!(
            vbox_cves.contains(&"CVE-TEST-0005".to_string()),
            "VirtualBox 7.2.8 must match CVE-TEST-0005 (oracle:vm_virtualbox), got: {:?}",
            vbox_cves
        );

        // ── True negatives (version above the fix) ──────────────────

        // Chrome 125 is above the range end (121.0)
        let chrome_125 = sw("Google Chrome", "125.0.0.0", "Google LLC");
        assert!(
            cves_for(&chrome_125).is_empty(),
            "Chrome 125 must NOT match any CVE"
        );

        // Firefox 116 doesn't match the exact pin (115.0)
        let ff_116 = sw("Mozilla Firefox", "116.0", "Mozilla");
        assert!(
            cves_for(&ff_116).is_empty(),
            "Firefox 116 must NOT match any CVE"
        );

        // Python 3.13.0 is at the exclusive end of [3.11.0, 3.13.0)
        let python_313 = sw("Python 3.13", "3.13.0", "Python Software Foundation");
        assert!(
            cves_for(&python_313).is_empty(),
            "Python 3.13.0 must NOT match any CVE"
        );

        // Notepad++ 8.7 is at the exclusive end
        let npp_patched = sw("Notepad++", "8.7", "Notepad++ Team");
        assert!(
            cves_for(&npp_patched).is_empty(),
            "Notepad++ 8.7 must NOT match any CVE"
        );

        // ── Unknown software (no CPE entry at all) ──────────────────

        let unknown = sw("Totally Unknown App", "1.0.0", "Unknown Corp");
        assert!(
            cves_for(&unknown).is_empty(),
            "Unknown software must NOT match any CVE"
        );

        // ── Enrichment spot-check ────────────────────────────────────

        // Chrome CVE has EPSS and KEV data in the fixture
        let chrome_vulns = matcher.find_vulnerabilities(&chrome_120).unwrap();
        let chrome_vuln = chrome_vulns
            .iter()
            .find(|(v, _, _)| v.cve_id == "CVE-TEST-0001")
            .expect("Chrome must have CVE-TEST-0001");
        assert!(chrome_vuln.0.in_kev, "CVE-TEST-0001 must be in KEV");
        assert!(
            chrome_vuln.0.epss_score.is_some(),
            "CVE-TEST-0001 must have an EPSS score"
        );

        // Confidence: curated mapping + publisher → at least High
        assert!(
            chrome_vuln.1 == MatchConfidence::Exact || chrome_vuln.1 == MatchConfidence::High,
            "Chrome curated match should be Exact or High, got {:?}",
            chrome_vuln.1
        );

        // ── Cleanup ──────────────────────────────────────────────────
        let _ = std::fs::remove_file(&db_path);
    }

    // ── Phase B: expanded accuracy gate ──────────────────────────────

    /// One row per product: (display_name, publisher, cpe_vendor, cpe_product).
    /// Each generates a synthetic CVE with range < 2.0.0. The gate asserts a
    /// true positive at 1.2.3 and a true negative at the fixed version 2.0.0.
    const GATE_CASES: &[(&str, &str, &str, &str)] = &[
        ("Google Chrome", "Google LLC", "google", "chrome"),
        ("Mozilla Firefox", "Mozilla Corporation", "mozilla", "firefox"),
        ("Microsoft Edge", "Microsoft Corporation", "microsoft", "edge_chromium"),
        ("Brave Browser", "Brave Software Inc", "brave", "brave"),
        ("Opera", "Opera Software", "opera", "opera_browser"),
        ("Vivaldi", "Vivaldi Technologies", "vivaldi", "vivaldi"),
        ("Thunderbird", "Mozilla Corporation", "mozilla", "thunderbird"),
        ("Python", "Python Software Foundation", "python", "python"),
        ("7-Zip", "Igor Pavlov", "7-zip", "7-zip"),
        ("VLC media player", "VideoLAN", "videolan", "vlc_media_player"),
        // Stored with NVD's CPE 2.3 escaping, as cve-db-builder wrote it.
        ("Notepad++", "Notepad++ Team", "notepad-plus-plus", r"notepad\+\+"),
        ("WinRAR", "win.rar GmbH", "rarlab", "winrar"),
        ("PuTTY", "Simon Tatham", "putty", "putty"),
        ("WinSCP", "Martin Prikryl", "winscp", "winscp"),
        ("FileZilla", "FileZilla Project", "filezilla-project", "filezilla_client"),
        ("KeePass", "Dominik Reichl", "keepass", "keepass"),
        ("Wireshark", "Wireshark Foundation", "wireshark", "wireshark"),
        ("Steam", "Valve Corporation", "valvesoftware", "steam_client"),
        ("Discord", "Discord Inc.", "discord", "discord"),
        ("Spotify", "Spotify AB", "spotify", "spotify"),
        ("OBS Studio", "OBS Project", "obsproject", "obs_studio"),
        ("Audacity", "Audacity Team", "audacityteam", "audacity"),
        ("Blender", "Blender Foundation", "blender", "blender"),
        ("Krita", "Krita Foundation", "krita", "krita"),
        ("PostgreSQL", "PostgreSQL Global Development Group", "postgresql", "postgresql"),
        ("MongoDB", "MongoDB Inc.", "mongodb", "mongodb"),
        ("Redis", "Redis Ltd.", "redis", "redis"),
        ("MariaDB", "MariaDB Corporation", "mariadb", "mariadb"),
        ("Docker Desktop", "Docker Inc.", "docker", "docker_desktop"),
        ("VirtualBox", "Oracle Corporation", "oracle", "vm_virtualbox"),
        ("Vagrant", "HashiCorp", "hashicorp", "vagrant"),
        ("Zoom", "Zoom Video Communications", "zoom", "zoom"),
        ("Slack", "Slack Technologies", "slack", "slack"),
        ("Telegram", "Telegram FZ-LLC", "telegram", "telegram_desktop"),
        ("Signal", "Signal Messenger", "signal", "signal_desktop"),
        ("Terraform", "HashiCorp", "hashicorp", "terraform"),
        ("Helm", "Helm Authors", "helm", "helm"),
        ("Malwarebytes", "Malwarebytes Inc", "malwarebytes", "malwarebytes"),
        ("WireGuard", "WireGuard LLC", "wireguard", "wireguard"),
        ("OpenVPN", "OpenVPN Inc.", "openvpn", "openvpn"),
        ("Nmap", "Nmap Project", "nmap", "nmap"),
        ("Bitwarden", "Bitwarden Inc.", "bitwarden", "bitwarden"),
        ("CCleaner", "Piriform Software", "piriform", "ccleaner"),
        ("TeamViewer", "TeamViewer Germany", "teamviewer", "teamviewer"),
        ("AnyDesk", "AnyDesk Software", "anydesk", "anydesk"),
        ("iTunes", "Apple Inc.", "apple", "itunes"),
        ("GIMP", "The GIMP Team", "gimp", "gimp"),
        ("LibreOffice", "The Document Foundation", "libreoffice", "libreoffice"),
        ("HandBrake", "HandBrake Team", "handbrake", "handbrake"),
        ("Inkscape", "Inkscape Project", "inkscape", "inkscape"),
        ("Grafana", "Grafana Labs", "grafana", "grafana"),
        ("qBittorrent", "qBittorrent Project", "qbittorrent", "qbittorrent"),
        ("MobaXterm", "Mobatek", "mobatek", "mobaxterm"),
    ];

    /// Build the expanded gate fixture: one synthetic CVE per GATE_CASES row
    /// with a vulnerable range below 2.0.0. `tag` must be unique per test —
    /// tests run in parallel and would otherwise collide on the fixture file.
    fn build_expanded_gate_db(tag: &str) -> String {
        let (conn, path) = create_fixture_db(tag);

        let mut cve_stmt = conn
            .prepare(
                "INSERT INTO cves (cve_id, description, published_date,
                 modified_date, cvss_v3_score, severity)
                 VALUES (?1, ?2, '2024-01-01', '2024-01-01', 7.5, 'HIGH')",
            )
            .unwrap();
        let mut cpe_stmt = conn
            .prepare(
                "INSERT INTO cpe_matches (cve_id, vendor, product,
                 version_end_excluding) VALUES (?1, ?2, ?3, '2.0.0')",
            )
            .unwrap();

        for (i, (name, _publisher, vendor, product)) in GATE_CASES.iter().enumerate() {
            let cve_id = format!("CVE-GATE-{:04}", i);
            cve_stmt
                .execute(params![cve_id, format!("{} flaw before 2.0.0", name)])
                .unwrap();
            cpe_stmt.execute(params![cve_id, vendor, product]).unwrap();
        }

        drop(cve_stmt);
        drop(cpe_stmt);
        drop(conn);
        path.to_string_lossy().into_owned()
    }

    /// Phase B accuracy gate: 53 true positives (vulnerable version inside
    /// range), 53 true negatives (patched version at the exclusive range
    /// end), plus wrong-product identity negatives including the negative-
    /// mapping veto cases.
    #[test]
    fn accuracy_gate_expanded() {
        let db_path = build_expanded_gate_db("gate_expanded");
        let matcher = CveMatcher::new(&db_path).expect("fixture DB must open");

        let cves_for = |software: &DetectedSoftware| -> Vec<String> {
            matcher
                .find_vulnerabilities(software)
                .unwrap()
                .into_iter()
                .map(|(vuln, _conf, _vendor)| vuln.cve_id)
                .collect::<Vec<_>>()
        };

        for (i, (name, publisher, _vendor, _product)) in GATE_CASES.iter().enumerate() {
            let cve_id = format!("CVE-GATE-{:04}", i);

            // True positive: 1.2.3 < 2.0.0 → must find its own CVE
            let vulnerable = sw(name, "1.2.3", publisher);
            let found = cves_for(&vulnerable);
            assert!(
                found.contains(&cve_id),
                "TP: {} v1.2.3 must match {}, got {:?}",
                name,
                cve_id,
                found
            );

            // True negative: 2.0.0 is the exclusive range end → no finding
            let patched = sw(name, "2.0.0", publisher);
            let found = cves_for(&patched);
            assert!(
                !found.contains(&cve_id),
                "TN: {} v2.0.0 must NOT match {}, got {:?}",
                name,
                cve_id,
                found
            );
        }

        // ── Wrong-product identity negatives ─────────────────────────

        // Negative mapping veto: the Edge updater carries the Edge name but
        // its own 1.3.x version stream — must not match the browser CVE.
        let edge_update = sw("Microsoft Edge Update", "1.3.225.7", "Microsoft Corporation");
        assert!(
            cves_for(&edge_update).is_empty(),
            "Edge Update must be vetoed by the negative mapping"
        );

        // Negative mapping veto: Chrome's updater service.
        let google_update = sw("Google Update", "1.3.36.152", "Google LLC");
        assert!(
            cves_for(&google_update).is_empty(),
            "Google Update must be vetoed by the negative mapping"
        );

        // Scoring rejection: extra core token drops below threshold.
        let py_launcher = sw("Python Launcher", "1.0.0", "Microsoft Corporation");
        assert!(
            cves_for(&py_launcher).is_empty(),
            "Python Launcher must not match the python CPE"
        );

        // Scoring rejection: two extra core tokens.
        let chrome_helper = sw("Chrome Plugin Helper", "1.0.0", "Example Corp");
        assert!(
            cves_for(&chrome_helper).is_empty(),
            "Chrome Plugin Helper must not match the chrome CPE"
        );

        // Unknown software: no CPE identity at all.
        let unknown = sw("Totally Unknown App", "1.0.0", "Unknown Corp");
        assert!(
            cves_for(&unknown).is_empty(),
            "Unknown software must not match any CVE"
        );

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn exploit_reference_is_detected_beyond_the_first_ten() {
        let db = build_expanded_gate_db("exploit_ref_probe");
        let conn = rusqlite::Connection::open(&db).unwrap();
        for i in 0..12 {
            let tags = if i == 11 { r#"["Exploit"]"# } else { r#"["Patch"]"# };
            conn.execute(
                "INSERT INTO cve_references (cve_id, url, source, tags)
                 VALUES ('CVE-GATE-0000', ?1, 's', ?2)",
                rusqlite::params![format!("https://example.test/{i}"), tags],
            )
            .unwrap();
        }
        drop(conn);
        let matcher = CveMatcher::new(&db).unwrap();
        assert!(
            matcher.has_exploit_reference("CVE-GATE-0000").unwrap(),
            "the Exploit tag sits past LIMIT 10 and must still be found"
        );
    }

    #[test]
    fn windows_release_resolves_to_release_specific_product() {
        // The OS scanner emits "Windows 11 25H2"; it must resolve to the
        // release-specific CPE product, never the over-broad windows_11.
        let name = tk("Windows 11 25H2");
        let mut best: Option<(f32, &str, &str)> = None;
        for entry in KNOWN_MAPPINGS {
            for alias in entry.aliases {
                let pattern = tokenize(alias);
                if pattern.is_empty() {
                    continue;
                }
                let score =
                    score_curated_match(&name, &pattern, Some("microsoft"), entry.vendor);
                if score >= CURATED_MIN_SCORE
                    && score > best.as_ref().map(|(sc, _, _)| *sc).unwrap_or(0.0)
                {
                    best = Some((score, entry.vendor, entry.product));
                }
            }
        }
        let (_, vendor, product) = best.expect("Windows 11 25H2 must match");
        assert_eq!(vendor, "microsoft");
        assert_eq!(product, "windows_11_25h2");
    }

    #[test]
    fn target_sw_gating() {
        // Wildcard/missing target_sw applies to everything.
        assert!(target_sw_applies("registry", None));
        assert!(target_sw_applies("pip", None));

        // Ecosystem rows only apply to their own ecosystem's packages.
        assert!(target_sw_applies("pip", Some("python")));
        assert!(!target_sw_applies("pip", Some("node.js")));
        assert!(target_sw_applies("npm", Some("node.js")));
        assert!(target_sw_applies("npm", Some("nodejs")));
        assert!(!target_sw_applies("npm", Some("wordpress")));
        assert!(target_sw_applies("cargo", Some("rust")));
        assert!(!target_sw_applies("cargo", Some("python")));

        // Desktop software never matches ecosystem-scoped rows...
        assert!(!target_sw_applies("registry", Some("python")));
        assert!(!target_sw_applies("pe", Some("wordpress")));
        assert!(!target_sw_applies("registry", Some("node.js")));

        // ...but non-ecosystem target_sw values (e.g. an OS) still apply.
        assert!(target_sw_applies("registry", Some("windows")));
        assert!(target_sw_applies("pip", Some("windows")));
    }

    #[test]
    fn resolves_identity_distinguishes_matched_from_unmatched() {
        let db_path = build_expanded_gate_db("gate_resolves_identity");
        let matcher = CveMatcher::new(&db_path).expect("fixture DB must open");

        // Known software resolves (curated layer) even when we don't care
        // about CVE outcomes.
        let chrome = sw("Google Chrome", "1.2.3", "Google LLC");
        let resolved = matcher.resolves_identity(&chrome);
        assert!(
            resolved.as_deref().unwrap_or("").contains("google:chrome"),
            "Chrome must resolve, got {:?}",
            resolved
        );

        // Unknown software resolves to nothing — the coverage gap signal.
        let unknown = sw("Totally Unknown App", "1.0.0", "Unknown Corp");
        assert!(matcher.resolves_identity(&unknown).is_none());

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn negative_mapping_vetoes_only_matching_names() {
        // "Microsoft Edge Update" is wildcard-vetoed for every microsoft
        // product — the dictionary layer would otherwise match it to legacy
        // microsoft:edge after the curated edge_chromium veto.
        let update_tokens = tk("Microsoft Edge Update");
        assert!(is_negated(&update_tokens, "microsoft", "edge_chromium"));
        assert!(is_negated(&update_tokens, "microsoft", "edge"));
        assert!(is_negated(&update_tokens, "microsoft", "onenote"));
        // …but not for other vendors…
        assert!(!is_negated(&update_tokens, "google", "chrome"));
        // …and the browser itself is never vetoed.
        let edge_tokens = tk("Microsoft Edge");
        assert!(!is_negated(&edge_tokens, "microsoft", "edge_chromium"));
        // Product-specific entries stay product-specific.
        let launcher_tokens = tk("Python Launcher");
        assert!(is_negated(&launcher_tokens, "python", "python"));
        assert!(!is_negated(&launcher_tokens, "python", "setuptools"));
    }

    #[test]
    fn known_mappings_minimum_count() {
        assert!(
            curated_alias_count() >= 500,
            "KNOWN_MAPPINGS should have at least 500 aliases, got {}",
            curated_alias_count()
        );
    }

    #[test]
    fn publisher_vendors_minimum_count() {
        assert!(
            PUBLISHER_VENDORS.len() >= 120,
            "PUBLISHER_VENDORS should have at least 120 entries, got {}",
            PUBLISHER_VENDORS.len()
        );
    }

    #[test]
    fn no_duplicate_known_mappings() {
        let mut seen = std::collections::HashSet::new();
        for entry in KNOWN_MAPPINGS {
            for alias in entry.aliases {
                let key = format!(
                    "{}|{}|{}",
                    alias.to_lowercase(),
                    entry.vendor,
                    entry.product
                );
                assert!(
                    seen.insert(key.clone()),
                    "Duplicate KNOWN_MAPPINGS entry: ({}, {}, {})",
                    alias,
                    entry.vendor,
                    entry.product
                );
            }
        }
    }

    // ── Patch recommendation tests ───────────────────────────────────

    #[test]
    fn extract_kb_from_support_url() {
        assert_eq!(
            extract_kb_from_url("https://support.microsoft.com/kb/5034763"),
            Some("KB5034763".to_string())
        );
        assert_eq!(
            extract_kb_from_url("https://support.microsoft.com/help/4601354"),
            Some("KB4601354".to_string())
        );
    }

    #[test]
    fn extract_kb_from_catalog_url() {
        assert_eq!(
            extract_kb_from_url("https://catalog.update.microsoft.com/Search.aspx?q=KB5034763"),
            Some("KB5034763".to_string())
        );
    }

    #[test]
    fn extract_kb_returns_none_for_non_ms_urls() {
        assert_eq!(extract_kb_from_url("https://nvd.nist.gov/vuln/detail/CVE-2024-0001"), None);
        assert_eq!(extract_kb_from_url("https://github.com/advisories/GHSA-xxxx"), None);
    }

    #[test]
    fn build_recommendation_with_version_and_kb() {
        let rec = build_recommendation(Some("121.0"), &["KB5034763".to_string()]);
        assert!(rec.contains("121.0"));
        assert!(rec.contains("KB5034763"));
    }

    #[test]
    fn build_recommendation_version_only() {
        let rec = build_recommendation(Some("8.7"), &[]);
        assert!(rec.contains("8.7"));
        assert!(!rec.contains("KB"));
    }

    #[test]
    fn build_recommendation_kb_only() {
        let rec = build_recommendation(None, &["KB5001234".to_string()]);
        assert!(rec.contains("KB5001234"));
    }

    #[test]
    fn build_recommendation_generic_fallback() {
        let rec = build_recommendation(None, &[]);
        assert_eq!(rec, "Update to the latest patched version.");
    }

    #[test]
    fn upgrade_command_winget() {
        let cmd = build_upgrade_command("winget://Google.Chrome", "Google Chrome", Some("121.0"));
        assert_eq!(
            cmd,
            Some("winget upgrade --name \"Google Chrome\" --version 121.0".to_string())
        );
    }

    #[test]
    fn upgrade_command_chocolatey() {
        let cmd = build_upgrade_command("chocolatey://git", "Git", Some("2.44.0"));
        assert_eq!(cmd, Some("choco upgrade git --version=2.44.0 -y".to_string()));
    }

    #[test]
    fn upgrade_command_pip() {
        let cmd = build_upgrade_command("pip://numpy", "numpy", Some("1.26.4"));
        assert_eq!(cmd, Some("pip install --upgrade numpy==1.26.4".to_string()));
    }

    #[test]
    fn upgrade_command_npm() {
        let cmd = build_upgrade_command("npm://ws", "ws", Some("8.17.1"));
        assert_eq!(cmd, Some("npm install -g ws@8.17.1".to_string()));
    }

    #[test]
    fn upgrade_command_cargo() {
        let cmd = build_upgrade_command("cargo://rustls", "rustls", None);
        assert_eq!(cmd, Some("cargo install rustls".to_string()));
    }

    #[test]
    fn upgrade_command_scoop() {
        let cmd = build_upgrade_command("scoop://jq", "jq", None);
        assert_eq!(cmd, Some("scoop update jq".to_string()));
    }

    #[test]
    fn upgrade_command_registry_uses_winget() {
        let cmd = build_upgrade_command("registry://chrome", "Google Chrome", None);
        assert_eq!(
            cmd,
            Some("winget upgrade --name \"Google Chrome\"".to_string())
        );
    }

    #[test]
    fn upgrade_command_unknown_scheme_returns_none() {
        assert_eq!(build_upgrade_command("pe://tool.exe", "Tool", None), None);
    }

    /// A CVE that spans several maintained release branches publishes one CPE
    /// row per branch, each with its own fix. The remediation shown must come
    /// from the branch the installed version is actually on.
    ///
    /// Live case: PostgreSQL 16.1 against CVE-2024-10979, whose rows are
    /// 12.0→12.21, 13.0→13.17, 14.0→14.14, 15.0→15.9, 16.0→16.5, 17.0→17.1.
    /// Reading the bound off the first row that merely *has* a range advised
    /// "update to 12.21" for a 16.1 install — a version four branches below
    /// what is already installed, which reads as nonsense to an operator and
    /// points at an upgrade that would not fix anything.
    #[test]
    fn fixed_version_comes_from_the_branch_the_install_is_on() {
        let rows = [
            rec(Some("12.0"), Some("12.21"), None, None),
            rec(Some("13.0"), Some("13.17"), None, None),
            rec(Some("14.0"), Some("14.14"), None, None),
            rec(Some("15.0"), Some("15.9"), None, None),
            rec(Some("16.0"), Some("16.5"), None, None),
            rec(Some("17.0"), Some("17.1"), None, None),
        ];
        let refs: Vec<&CpeMatchRecord> = rows.iter().collect();

        assert_eq!(
            fixed_version_for("16.1", None, &refs).as_deref(),
            Some("16.5"),
            "a 16.1 install must be told to upgrade within its own 16.x branch"
        );
        assert_eq!(
            fixed_version_for("14.2", None, &refs).as_deref(),
            Some("14.14"),
            "a 14.2 install must be told 14.14, not the 12.x branch fix"
        );
    }

    /// When no row establishes vulnerability for this version, fall back to any
    /// row that carries a range rather than inventing an answer.
    #[test]
    fn fixed_version_falls_back_to_a_bounded_row_when_none_establishes() {
        let rows = [rec(Some("1.0"), Some("2.0"), None, None)];
        let refs: Vec<&CpeMatchRecord> = rows.iter().collect();
        assert_eq!(
            fixed_version_for("9.9", None, &refs).as_deref(),
            Some("2.0")
        );
    }

    /// `version_end_including` means "still vulnerable at that version", so the
    /// true fix is unknown and is displayed as a lower bound.
    #[test]
    fn fixed_version_renders_end_including_as_greater_than() {
        let rows = [rec(Some("1.0"), None, None, Some("1.9"))];
        let refs: Vec<&CpeMatchRecord> = rows.iter().collect();
        assert_eq!(
            fixed_version_for("1.5", None, &refs).as_deref(),
            Some(">1.9")
        );
    }

    /// A package-manager entry's name is the registry's own identifier, so an
    /// exact curated alias is an exact identity. Scored like a free-text
    /// display name it reached only 0.70 — Medium — and the default
    /// `--min-confidence high` hid pip 26.1.2's CVE-2026-13346 that Wazuh
    /// reported on the same host.
    #[test]
    fn an_ecosystem_package_matching_its_curated_alias_exactly_is_exact_confidence() {
        let (conn, path) = create_fixture_db("ecosystem_exact");
        conn.execute_batch(
            "INSERT INTO cves (cve_id, description, published_date, modified_date, cvss_v3_score, severity)
             VALUES ('CVE-TEST-PIP', 'pip URL handling', '2026-07-29', '2026-07-29', 6.5, 'MEDIUM');
             INSERT INTO cpe_matches (cve_id, vendor, product, version_end_excluding)
             VALUES ('CVE-TEST-PIP', 'pypa', 'pip', '26.2');",
        )
        .unwrap();
        drop(conn);
        let matcher = CveMatcher::new(&path.to_string_lossy()).unwrap();

        let pkg = DetectedSoftware {
            name: "pip".into(),
            version: Some("26.1.2".into()),
            publisher: Some("pip".into()),
            install_location: None,
            install_date: None,
            registry_key: "pip://pip".into(),
            architecture: crate::models::Architecture::Unknown,
        };
        let found = matcher.find_vulnerabilities(&pkg).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(found.len(), 1, "pip 26.1.2 must match CVE-TEST-PIP");
        assert_eq!(found[0].1, MatchConfidence::Exact);
    }

    #[test]
    fn a_display_name_matching_an_alias_keeps_its_ordinary_score() {
        // The boost is for package-manager names only. A registry display name
        // "pip" from an Uninstall key is free text and stays as scored.
        assert!(!ecosystem_exact_alias("registry", &["pip".to_string()], "pypa", "pip"));
        assert!(ecosystem_exact_alias("pip", &["pip".to_string()], "pypa", "pip"));
        assert!(!ecosystem_exact_alias(
            "pip",
            &["pip".to_string(), "tools".to_string()],
            "pypa",
            "pip"
        ));
    }

    fn wildcard_row() -> CpeMatchRecord {
        let mut r = rec(None, None, None, None);
        r.version = Some("*".into());
        r
    }

    /// THE FIX. NVD publishes several CPE rows per CVE. Some carry a version
    /// range; others are unbounded wildcards covering a different
    /// configuration. The old code took the first row that said "vulnerable",
    /// so a wildcard row silently overrode a bounded row that had already
    /// established the installed version is patched.
    ///
    /// Measured scale: 947,205 of 3,175,789 rows (29.8%) are unbounded
    /// wildcards, each asserting vulnerability for EVERY installed version.
    /// This is what reported Steam 2.10.91.91 and Visual Studio 18.0.11715.348
    /// as vulnerable — their matching rows had no bounds at all.
    #[test]
    fn a_bounded_row_beats_an_unbounded_wildcard_for_the_same_cve() {
        let bounded = rec(None, Some("52.0"), None, None); // fixed in 52.0
        let wild = wildcard_row();

        assert!(
            !cve_is_vulnerable("154.0.1", None, &[&bounded, &wild]),
            "NVD published a range saying 52.0 is fixed; a wildcard row from \
             another configuration must not resurrect the finding"
        );
        assert!(
            !cve_is_vulnerable("154.0.1", None, &[&wild, &bounded]),
            "row order must not change the verdict"
        );
    }

    /// The bounded row still decides in the other direction.
    #[test]
    fn a_bounded_row_that_includes_the_version_still_reports() {
        let bounded = rec(None, Some("52.0"), None, None);
        let wild = wildcard_row();
        assert!(cve_is_vulnerable("40.0", None, &[&bounded, &wild]));
    }

    /// When NVD published NO version information anywhere for this CVE, we
    /// genuinely cannot tell. The finding still stands — absence of a range is
    /// not evidence of safety, and dropping it would be a false negative.
    #[test]
    fn with_no_bounds_anywhere_the_wildcard_still_reports() {
        let wild = wildcard_row();
        assert!(
            cve_is_vulnerable("154.0.1", None, &[&wild]),
            "no version data at all must not be read as 'patched'"
        );
    }

    /// Several bounded rows: any one of them matching is enough.
    #[test]
    fn any_matching_bounded_row_is_enough() {
        let a = rec(None, Some("2.0"), None, None);
        let b = rec(Some("10.0"), Some("20.0"), None, None);
        assert!(cve_is_vulnerable("15.0", None, &[&a, &b]));
        assert!(!cve_is_vulnerable("25.0", None, &[&a, &b]));
    }

    #[test]
    fn no_rows_is_not_vulnerable() {
        assert!(!cve_is_vulnerable("1.0", None, &[]));
    }

    /// Steam. NVD bounds this CVE by DATE ("Valve Steam before 2021-04-17",
    /// stored as version_end_including = "2021-04-10"). The installed string
    /// is a build number, 2.10.91.91. Both parse as versions, so the old code
    /// compared them: 2.10.91.91 < 2021.4.10 => "vulnerable". That comparison
    /// is a category error — the operand on the left is not a date.
    #[test]
    fn a_build_number_is_not_comparable_to_a_date_bound() {
        assert!(!schemes_comparable("2.10.91.91", "2021-04-10"));
    }

    /// Visual Studio BuildTools. The bound is the RELEASE YEAR 2012; the
    /// installed string is the build number 18.0.11715.348. 18 < 2012 as
    /// arithmetic, and as product identity it means nothing.
    #[test]
    fn a_build_number_is_not_comparable_to_a_year_bound() {
        assert!(!schemes_comparable("18.0.11715.348", "2012"));
    }

    /// Ordinary comparisons must be untouched — this is the guard against
    /// the detector quietly eating real findings.
    #[test]
    fn ordinary_dotted_versions_stay_comparable() {
        assert!(schemes_comparable("154.0.1", "52.0"));
        assert!(schemes_comparable("10.0.26200.9168", "10.0.26200.9000"));
        assert!(schemes_comparable("1.0", "2.0"));
        assert!(schemes_comparable("2.10.91.91", "3.0.0"));
    }

    /// Like against like is fine: two dates compare, two years compare.
    #[test]
    fn same_scheme_on_both_sides_is_comparable() {
        assert!(schemes_comparable("2021-01-01", "2021-04-10"));
        assert!(schemes_comparable("2019", "2012"));
    }

    /// A calendar-versioned product (2021.4) against a year bound is the
    /// awkward middle case. Treat it as comparable: both are year-led, and
    /// refusing here would drop genuine CalVer findings.
    #[test]
    fn calendar_versions_remain_comparable_with_years() {
        assert!(schemes_comparable("2021.4", "2012"));
    }

}
