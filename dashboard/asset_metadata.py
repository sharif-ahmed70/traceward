"""Asset Metadata Layer for United International University (Simulated Campus Environment).

Provides realistic enterprise context for university cyber risk analysis, attack path
detection, and constraint-optimized remediation demonstrations.

DISCLAIMER:
This is a simulated academic demonstration environment inspired by a university digital ecosystem.
It does NOT represent the actual internal network or security architecture of United International University.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Simulated Institution Metadata
# ---------------------------------------------------------------------------
UNIVERSITY_INFO: Dict[str, str] = {
    "organization": "United International University",
    "environment_name": "Simulated Digital Campus Environment",
    "industry": "Higher Education",
    "purpose": "Demonstrate how TraceWard AI protects a modern university digital ecosystem.",
    "crown_jewel": "DB01 — Student Academic Database",
    "disclaimer": (
        "Simulated Environment — For Academic Research & Faculty Demonstration Only. "
        "Does not reflect actual UIU production infrastructure."
    ),
}


# ---------------------------------------------------------------------------
# Comprehensive University Digital Asset Inventory
# ---------------------------------------------------------------------------
CAMPUS_ASSETS: Dict[str, Dict[str, Any]] = {
    # -----------------------------------------------------------------------
    # WEB LAYER
    # -----------------------------------------------------------------------
    "WEB01": {
        "asset_id": "WEB01",
        "name": "University Public Website Server",
        "short_name": "Public Website Server",
        "category": "Web Server",
        "purpose": "Hosts official university website, admissions announcements, faculty directory, and public notices.",
        "technology": "Nginx / React Enterprise Portal",
        "owner": "Center for IT Services (CITS)",
        "environment": "Production (Public DMZ)",
        "criticality": "High",
        "criticality_level": 4,
        "connected_systems": ["APP01", "AUTH01"],
        "internet_exposed": True,
        "business_impact": (
            "Website defacement, dissemination of forged student notices, loss of public trust, "
            "and unauthenticated perimeter foothold allowing lateral pivot into internal services."
        ),
        "vulnerability_context": {
            "issue": "Outdated web server component (CVE-2024-1756) with reverse-proxy header parsing flaw",
            "severity": "High",
            "impact": "Unauthorized perimeter access and request smuggling into backend academic services",
        },
        "recommended_actions": [
            "Upgrade Nginx reverse-proxy service to latest patched release.",
            "Deploy Web Application Firewall (WAF) rate-limiting rules on public endpoints.",
            "Isolate DMZ VLAN to prevent unauthenticated outbound routing to application tiers.",
        ],
    },
    "WEB02": {
        "asset_id": "WEB02",
        "name": "Student Portal Web Server",
        "short_name": "Student Portal Web",
        "category": "Web Server",
        "purpose": "Provides student authentication portal, notices, fee status, and academic service gateway.",
        "technology": "Apache HTTP Server / PHP-FPM",
        "owner": "Center for IT Services (CITS)",
        "environment": "Production (Public DMZ)",
        "criticality": "High",
        "criticality_level": 4,
        "connected_systems": ["APP01", "AUTH01"],
        "internet_exposed": True,
        "business_impact": (
            "Student portal outage during semester registration, credential interception, "
            "and session spoofing targeting university identity tokens."
        ),
        "vulnerability_context": {
            "issue": "Cross-origin session handling misconfiguration",
            "severity": "High",
            "impact": "Session token leakage allowing unauthorized student portal impersonation",
        },
        "recommended_actions": [
            "Enforce strict HTTPOnly, Secure, and SameSite cookie attributes.",
            "Deploy automated DDoS mitigation and CAPTCHA validation on student login endpoints.",
        ],
    },

    # -----------------------------------------------------------------------
    # APPLICATION LAYER
    # -----------------------------------------------------------------------
    "APP01": {
        "asset_id": "APP01",
        "name": "University Comprehensive Academic Manager (UCAM)",
        "short_name": "UCAM Academic Manager",
        "category": "Academic Application",
        "purpose": (
            "Core academic lifecycle management: student profiles, course registration, "
            "academic records, exam results, and official transcript generation."
        ),
        "technology": "Java Spring Boot / Enterprise Middleware",
        "owner": "Office of the Controller of Examinations & Registrar",
        "environment": "Production (Internal App Tier)",
        "criticality": "Critical",
        "criticality_level": 5,
        "connected_systems": ["WEB01", "DB01"],
        "internet_exposed": False,
        "business_impact": (
            "Disruption of course registration, grading freeze, unauthorized grade modifications, "
            "and academic record corruption impacting institutional accreditation."
        ),
        "vulnerability_context": {
            "issue": "Application framework dependency vulnerability (CVE-2024-2187)",
            "severity": "Critical",
            "impact": "Remote code execution (RCE) on academic core leading to direct database compromise",
        },
        "recommended_actions": [
            "Apply priority patch to Spring Boot framework dependencies (removes CVE-2024-2187).",
            "Implement parameterized data access queries preventing internal SQL manipulation.",
            "Restrict database access credentials strictly to dedicated service connection pools.",
        ],
    },
    "APP02": {
        "asset_id": "APP02",
        "name": "Learning Management System (LMS)",
        "short_name": "e-Learning LMS",
        "category": "Learning Platform",
        "purpose": "Manages online course materials, lecture recordings, assignments, quizzes, and continuous assessments.",
        "technology": "Moodle / Python Backend Services",
        "owner": "Center for Excellence in Teaching & Learning",
        "environment": "Production (Internal App Tier)",
        "criticality": "High",
        "criticality_level": 4,
        "connected_systems": ["WEB02", "DB03"],
        "internet_exposed": False,
        "business_impact": (
            "Interruption of online classes, loss of student assignment submissions, "
            "and premature leakage of upcoming examination question papers."
        ),
        "vulnerability_context": {
            "issue": "Insecure file upload validation in assignment submission module",
            "severity": "High",
            "impact": "Arbitrary server script execution via student file uploads",
        },
        "recommended_actions": [
            "Enforce strict MIME-type and antivirus file inspection on all uploaded student materials.",
            "Isolate assignment file storage onto an unprivileged object storage bucket.",
        ],
    },
    "APP03": {
        "asset_id": "APP03",
        "name": "Admission Management System",
        "short_name": "Admission Portal System",
        "category": "Academic Application",
        "purpose": "Handles applicant registration, admission workflows, document screening, and entrance examination scoring.",
        "technology": "Node.js / Express Enterprise API",
        "owner": "Office of Admissions",
        "environment": "Production (Internal App Tier)",
        "criticality": "Critical",
        "criticality_level": 5,
        "connected_systems": ["WEB01", "DB02"],
        "internet_exposed": False,
        "business_impact": (
            "Exposure of prospective student personal identifiable information (PII), "
            "admissions fraud, and enrollment intake interruption."
        ),
        "vulnerability_context": {
            "issue": "Broken Object Level Authorization (BOLA) in application verification endpoints",
            "severity": "Critical",
            "impact": "Mass extraction of confidential applicant records and national identity documents",
        },
        "recommended_actions": [
            "Implement strict JWT scope authorization on all applicant review endpoints.",
            "Enforce field-level encryption on national ID and prior academic history data.",
        ],
    },
    "APP04": {
        "asset_id": "APP04",
        "name": "Library Management System",
        "short_name": "Library Management System",
        "category": "Academic Service",
        "purpose": "Manages book catalogs, student borrowing history, digital journal access, and research paper repository.",
        "technology": "Koha / Perl Web Services",
        "owner": "University Central Library",
        "environment": "Production (Internal Service Tier)",
        "criticality": "Medium",
        "criticality_level": 3,
        "connected_systems": ["DB04", "AUTH01"],
        "internet_exposed": False,
        "business_impact": (
            "Library circulation disruption, inventory catalog inconsistency, "
            "and loss of research journal proxy credentials."
        ),
        "vulnerability_context": {
            "issue": "Unsanitized user search queries in digital catalog lookup",
            "severity": "Medium",
            "impact": "SQL injection leading to extraction of user borrowing history",
        },
        "recommended_actions": [
            "Deploy prepared SQL queries across catalog query modules.",
            "Enforce daily read-only snapshots of the library inventory database.",
        ],
    },
    "APP05": {
        "asset_id": "APP05",
        "name": "Digital Document Preservation System",
        "short_name": "Certificate & Document Vault",
        "category": "Document Vault",
        "purpose": "Stores, cryptographically seals, and verifies student degree certificates, transcripts, and official seals.",
        "technology": "Enterprise Documentum / Cryptographic Vault",
        "owner": "Office of the Registrar",
        "environment": "Secure Vault Subnet",
        "criticality": "High",
        "criticality_level": 4,
        "connected_systems": ["DB01", "BACKUP01"],
        "internet_exposed": False,
        "business_impact": (
            "Generation of fraudulent academic degrees, loss of legal verification capabilities, "
            "and damage to university institutional standing."
        ),
        "vulnerability_context": {
            "issue": "Weak cryptographic signing key storage in export module",
            "severity": "High",
            "impact": "Potential unauthorized certificate forgery with official institutional seal",
        },
        "recommended_actions": [
            "Store digital signing keys inside a Hardware Security Module (HSM).",
            "Implement immutable audit trail for all issued certificate verification requests.",
        ],
    },

    # -----------------------------------------------------------------------
    # DATABASE LAYER
    # -----------------------------------------------------------------------
    "DB01": {
        "asset_id": "DB01",
        "name": "Student Academic Database",
        "short_name": "Student Academic Database",
        "category": "Database Server",
        "purpose": "Stores master student profiles, course registrations, semester exam grades, CGPA, and degree audit data.",
        "technology": "PostgreSQL 15 (Encrypted at Rest)",
        "owner": "Center for IT Services & Office of Controller of Exams",
        "environment": "Internal Secure Tier (Crown Jewel)",
        "criticality": "Critical",
        "criticality_level": 5,
        "connected_systems": ["APP01"],
        "internet_exposed": False,
        "business_impact": (
            "Catastrophic exposure of student confidential records, unauthorized grade alteration, "
            "severe privacy law violations (GDPR/FERPA), and complete loss of academic integrity."
        ),
        "vulnerability_context": {
            "issue": "Database access misconfiguration (CVE-2024-3094) allowing privilege escalation",
            "severity": "Critical",
            "impact": "Direct administrative access to all student records and grade tables",
        },
        "recommended_actions": [
            "Apply urgent vendor security patch (CVE-2024-3094).",
            "Restrict pg_hba.conf client authentication strictly to APP01 dedicated IP.",
            "Rotate all database superuser credentials and enforce TLS-only database sessions.",
        ],
    },
    "DB02": {
        "asset_id": "DB02",
        "name": "Admission Database",
        "short_name": "Admission Applicant DB",
        "category": "Database Server",
        "purpose": "Stores applicant personal information, national IDs, entrance examination scores, and application status.",
        "technology": "MySQL 8 Enterprise",
        "owner": "Office of Admissions",
        "environment": "Internal Database Tier",
        "criticality": "Critical",
        "criticality_level": 5,
        "connected_systems": ["APP03"],
        "internet_exposed": False,
        "business_impact": (
            "Mass leakage of applicant confidential personal documents, identity theft risks, "
            "and legal liability for personal data mishandling."
        ),
        "vulnerability_context": {
            "issue": "Excessive database user privileges allocated to admission web services",
            "severity": "Critical",
            "impact": "Potential full database dump via application service credentials",
        },
        "recommended_actions": [
            "Enforce least-privilege permissions on admission service database user.",
            "Encrypt sensitive identity documents using AES-256 before storage.",
        ],
    },
    "DB03": {
        "asset_id": "DB03",
        "name": "Learning Content Database",
        "short_name": "LMS Content DB",
        "category": "Database Server",
        "purpose": "Stores LMS course materials, grading rubrics, quiz question banks, and student discussion records.",
        "technology": "MariaDB Galera Cluster",
        "owner": "Center for Excellence in Teaching & Learning",
        "environment": "Internal Database Tier",
        "criticality": "High",
        "criticality_level": 4,
        "connected_systems": ["APP02"],
        "internet_exposed": False,
        "business_impact": (
            "Destruction of ongoing semester course evaluations and premature leak of final exam papers."
        ),
        "vulnerability_context": {
            "issue": "Unauthenticated replication cluster management port",
            "severity": "High",
            "impact": "Ransomware attacker can drop tables or hold coursework hostage",
        },
        "recommended_actions": [
            "Enable TLS authentication across all Galera replication nodes.",
            "Implement hourly automated immutable snapshots of active course data.",
        ],
    },
    "DB04": {
        "asset_id": "DB04",
        "name": "Library Database",
        "short_name": "Library Catalog DB",
        "category": "Database Server",
        "purpose": "Stores university library catalog, book inventory, barcode records, and student borrowing history.",
        "technology": "MySQL Community Edition",
        "owner": "University Central Library",
        "environment": "Internal Database Tier",
        "criticality": "Medium",
        "criticality_level": 3,
        "connected_systems": ["APP04"],
        "internet_exposed": False,
        "business_impact": (
            "Temporary loss of book circulation tracking and minor administrative overhead."
        ),
        "vulnerability_context": {
            "issue": "Default sample database accounts left enabled",
            "severity": "Medium",
            "impact": "Unauthorized read access to library inventory and user loan records",
        },
        "recommended_actions": [
            "Purge default administrative accounts and lock down database port 3306.",
        ],
    },

    # -----------------------------------------------------------------------
    # SECURITY & INFRASTRUCTURE LAYER
    # -----------------------------------------------------------------------
    "AUTH01": {
        "asset_id": "AUTH01",
        "name": "University Identity Management Server",
        "short_name": "Identity & SSO Gateway",
        "category": "Security Infrastructure",
        "purpose": "Handles Single Sign-On (SSO), LDAP directory, multi-factor authentication (MFA) for students, faculty, and staff.",
        "technology": "Keycloak / OpenLDAP / OAuth2",
        "owner": "Center for IT Services (Cybersecurity Division)",
        "environment": "Internal Security Management Tier",
        "criticality": "Critical",
        "criticality_level": 5,
        "connected_systems": ["WEB01", "WEB02", "APP01", "APP02", "VPN01"],
        "internet_exposed": False,
        "business_impact": (
            "Campus-wide account takeover, golden ticket generation, and total breach "
            "of all connected university systems and services."
        ),
        "vulnerability_context": {
            "issue": "Authentication configuration weakness (CVE-2024-0921) in token validation",
            "severity": "Critical",
            "impact": "Attacker can forge valid JWT administrative tokens to bypass login controls",
        },
        "recommended_actions": [
            "Apply security patch for CVE-2024-0921 in Keycloak identity service.",
            "Enforce mandatory hardware token MFA (FIDO2) for all IT administrators and faculty.",
            "Enable automated anomaly detection for impossible-travel login requests.",
        ],
    },
    "MAIL01": {
        "asset_id": "MAIL01",
        "name": "University Email Server",
        "short_name": "Campus Email Gateway",
        "category": "Communication Infrastructure",
        "purpose": "Official communication platform for university notices, faculty correspondence, and administrative directives.",
        "technology": "Postfix / Microsoft Exchange Hybrid",
        "owner": "Center for IT Services (CITS)",
        "environment": "Production (Public DMZ)",
        "criticality": "Medium",
        "criticality_level": 3,
        "connected_systems": ["INTERNET", "AUTH01"],
        "internet_exposed": True,
        "business_impact": (
            "Campus-wide spear phishing campaigns, vice-chancellor impersonation, "
            "and disruption to official university communication."
        ),
        "vulnerability_context": {
            "issue": "Open mail relay misconfiguration on secondary submission port",
            "severity": "Medium",
            "impact": "Domain spoofing and campus reputation blacklist by global email providers",
        },
        "recommended_actions": [
            "Enforce strict SPF, DKIM, and DMARC reject policies.",
            "Integrate AI-driven email threat analysis for inbound attachments.",
        ],
    },
    "BACKUP01": {
        "asset_id": "BACKUP01",
        "name": "University Backup Recovery System",
        "short_name": "Backup & Disaster Recovery",
        "category": "Storage & Disaster Recovery",
        "purpose": "Automated immutable snapshots, offsite disaster recovery, and air-gapped system backups for all campus databases.",
        "technology": "Veeam Backup / Immutable ZFS Vault",
        "owner": "Center for IT Services (Infrastructure Operations)",
        "environment": "Air-Gapped Backup Enclave",
        "criticality": "Critical",
        "criticality_level": 5,
        "connected_systems": ["DB01", "DB02", "APP01"],
        "internet_exposed": False,
        "business_impact": (
            "Permanent data loss if primary academic databases are encrypted by ransomware, "
            "preventing institutional recovery."
        ),
        "vulnerability_context": {
            "issue": "Backup agent communication vulnerability (V0040) with remote snapshot tampering risk",
            "severity": "Critical",
            "impact": "Adversary can delete historical backups prior to deploying ransomware",
        },
        "recommended_actions": [
            "Enforce hardware-enforced write-once-read-many (WORM) storage retention.",
            "Disconnect secondary air-gapped tape backup during non-backup windows.",
            "Execute priority patch dispatch V0040 via Smart Remediation scheduler.",
        ],
    },
    "MON01": {
        "asset_id": "MON01",
        "name": "Security Monitoring Server",
        "short_name": "SOC SIEM & Telemetry",
        "category": "Security Infrastructure",
        "purpose": "Collects system logs, firewall telemetry, endpoint alerts, and network flow data for real-time SOC incident correlation.",
        "technology": "Elasticsearch / Wazuh SIEM / Zeek",
        "owner": "Center for IT Services (Cybersecurity Division)",
        "environment": "SOC Core Operations Zone",
        "criticality": "High",
        "criticality_level": 4,
        "connected_systems": ["WEB01", "APP01", "DB01", "AUTH01", "VPN01"],
        "internet_exposed": False,
        "business_impact": (
            "Blinds the SOC team during an active breach, preventing timely containment "
            "and hindering forensic post-mortem investigation."
        ),
        "vulnerability_context": {
            "issue": "Log buffer ingestion queue vulnerability under high attack volume",
            "severity": "High",
            "impact": "Event dropping allowing attacker lateral movement to go unlogged",
        },
        "recommended_actions": [
            "Deploy redundant Kafka ingestion queues with persistent disk buffering.",
            "Configure secondary out-of-band syslog collector.",
        ],
    },
    "VPN01": {
        "asset_id": "VPN01",
        "name": "University Secure Remote Access Gateway",
        "short_name": "Faculty VPN Gateway",
        "category": "Perimeter Security Gateway",
        "purpose": "Provides encrypted remote access for faculty grading from home, researcher remote lab access, and IT staff maintenance.",
        "technology": "WireGuard / OpenVPN Enterprise",
        "owner": "Center for IT Services (Network Operations)",
        "environment": "Perimeter Gateway (External Facing)",
        "criticality": "High",
        "criticality_level": 4,
        "connected_systems": ["EMP01", "AUTH01"],
        "internet_exposed": True,
        "business_impact": (
            "Bypasses external perimeter firewalls, giving external attackers direct ingress "
            "into internal university subnets and staff workstations."
        ),
        "vulnerability_context": {
            "issue": "SSL-VPN session termination vulnerability (V0186)",
            "severity": "Critical",
            "impact": "Remote attacker can gain authenticated intranet access without valid credentials",
        },
        "recommended_actions": [
            "Dispatch priority patch V0186 immediately via CSP remediation plan.",
            "Mandate device health attestation before establishing VPN tunnel.",
        ],
    },
    "EMP01": {
        "asset_id": "EMP01",
        "name": "Academic & Administrative Workstation Subnet",
        "short_name": "Faculty & Staff Workstations",
        "category": "Workstation Subnet",
        "purpose": "Desktop workstations and laptops used by department faculty, academic advisors, and administrative officers.",
        "technology": "Windows 11 Enterprise / Endpoint Protection",
        "owner": "Academic Departments & Faculty Offices",
        "environment": "Internal Campus LAN",
        "criticality": "Medium",
        "criticality_level": 3,
        "connected_systems": ["VPN01", "AUTH01", "APP01"],
        "internet_exposed": False,
        "business_impact": (
            "Endpoint compromise allows pass-the-hash lateral movement and theft "
            "of administrative credentials for academic portals."
        ),
        "vulnerability_context": {
            "issue": "Unpatched third-party desktop utilities with local privilege escalation",
            "severity": "Medium",
            "impact": "Adversary obtains local SYSTEM privileges on faculty machines",
        },
        "recommended_actions": [
            "Enforce centralized patch management across all campus workstations.",
            "Remove local administrative rights for standard user accounts.",
        ],
    },
    "INTERNET": {
        "asset_id": "INTERNET",
        "name": "External Threat Environment (Internet)",
        "short_name": "External Adversary Origin",
        "category": "External Threat Vector",
        "purpose": "Untrusted external network environment and origin point for public cyber adversary attempts.",
        "technology": "Public WAN / Global Threat Actors",
        "owner": "External Threat Environment",
        "environment": "External Untrusted Network",
        "criticality": "Low",
        "criticality_level": 1,
        "connected_systems": ["WEB01", "WEB02", "VPN01", "MAIL01"],
        "internet_exposed": True,
        "business_impact": (
            "Origin vector for continuous automated exploit scanning, phishing campaigns, "
            "and targeted attacks against campus public services."
        ),
        "vulnerability_context": {
            "issue": "Public unauthenticated threat surface",
            "severity": "Low",
            "impact": "Initial adversary probe entry point",
        },
        "recommended_actions": [
            "Maintain DDoS protection and automated geo-blocking for suspicious threat traffic.",
        ],
    },
}


# ---------------------------------------------------------------------------
# Helper Retrieval Functions
# ---------------------------------------------------------------------------
def get_asset(system_id: str) -> Dict[str, Any]:
    """Retrieve full asset metadata dictionary for a system, with robust fallback."""
    sys_upper = str(system_id).strip().upper()
    if sys_upper in CAMPUS_ASSETS:
        return CAMPUS_ASSETS[sys_upper]

    # Clean fallback for any unexpected system ID
    return {
        "asset_id": sys_upper,
        "name": f"Campus System {sys_upper}",
        "short_name": sys_upper,
        "category": "Campus Asset",
        "purpose": f"Operational system component ({sys_upper}) within campus infrastructure.",
        "technology": "Standard Campus Compute",
        "owner": "Center for IT Services",
        "environment": "Production (Campus Network)",
        "criticality": "Medium",
        "criticality_level": 3,
        "connected_systems": [],
        "internet_exposed": False,
        "business_impact": "Disruption of associated departmental service workflows.",
        "vulnerability_context": {
            "issue": "Standard software update required",
            "severity": "Medium",
            "impact": "Potential service degradation",
        },
        "recommended_actions": ["Maintain regular patching and access control reviews."],
    }


def get_asset_name(system_id: str, short: bool = False) -> str:
    """Return friendly, human-readable name for an asset."""
    asset = get_asset(system_id)
    return asset["short_name"] if short else asset["name"]


def format_asset_label(
    system_id: str,
    include_name: bool = True,
    short: bool = True,
    multiline: bool = False,
) -> str:
    """Format an asset ID with its human-readable name for UI components.

    Examples:
        format_asset_label("APP01") -> "APP01 — UCAM Academic Manager"
        format_asset_label("DB01", multiline=True) -> "DB01\\nStudent Academic Database"
    """
    sys_clean = str(system_id).strip().upper()
    if not include_name:
        return sys_clean
    name = get_asset_name(sys_clean, short=short)
    if multiline:
        return f"{sys_clean}\n{name}"
    return f"{sys_clean} — {name}"


def get_system_business_impact(system_id: str) -> str:
    """Return the concrete business impact statement if a system is compromised."""
    return get_asset(system_id).get("business_impact", "")


def get_system_vulnerability_context(system_id: str) -> Dict[str, str]:
    """Return realistic vulnerability scenario details for an asset."""
    return get_asset(system_id).get(
        "vulnerability_context",
        {"issue": "Outdated software component", "severity": "Medium", "impact": "Service disruption"},
    )


def get_all_assets() -> List[Dict[str, Any]]:
    """Return list of all registered campus assets."""
    return list(CAMPUS_ASSETS.values())


def filter_assets(
    search_query: str = "",
    category_filter: str = "All",
    criticality_filter: str = "All",
    owner_filter: str = "All",
) -> List[Dict[str, Any]]:
    """Search and filter university assets by query, category, criticality, and department."""
    results = []
    q = search_query.strip().lower()

    for asset in CAMPUS_ASSETS.values():
        # Exclude INTERNET from standard internal asset inventory
        if asset["asset_id"] == "INTERNET":
            continue

        # Text search matching ID, name, purpose, tech, impact
        if q:
            searchable = (
                f"{asset['asset_id']} {asset['name']} {asset['purpose']} "
                f"{asset['technology']} {asset['owner']} {asset['category']} "
                f"{asset['business_impact']}"
            ).lower()
            if q not in searchable:
                continue

        # Category filter
        if category_filter != "All" and asset["category"] != category_filter:
            continue

        # Criticality filter
        if criticality_filter != "All" and asset["criticality"] != criticality_filter:
            continue

        # Department filter
        if owner_filter != "All" and owner_filter not in asset["owner"]:
            continue

        results.append(asset)

    return results
