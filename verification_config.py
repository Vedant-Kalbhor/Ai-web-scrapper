"""
Configuration for Authoritative Vulnerability Sources
Defines trusted sources for CVE verification and information gathering
"""

# ============================================================================
# TIER 1: AUTHORITATIVE SOURCES (Government/Standards Bodies)
# ============================================================================
TIER1_SOURCES = {
    'NVD': {
        'name': 'National Vulnerability Database (NIST)',
        'url_pattern': 'https://nvd.nist.gov/vuln/detail/{cve_id}',
        'reliability': 100,
        'description': 'US government repository of vulnerability data',
        'api': 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    },
    'MITRE': {
        'name': 'MITRE CVE Database',
        'url_pattern': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}',
        'reliability': 100,
        'description': 'Official CVE naming authority',
        'api': None
    },
    'OPENCVE': {
        'name': 'OpenCVE',
        'url_pattern': 'https://www.opencve.io/cve/{cve_id}',
        'reliability': 100,
        'description': 'Open-source CVE alerting platform',
        'domains': ['opencve.io']
    },
    'CISA': {
        'name': 'CISA Known Exploited Vulnerabilities',
        'url_pattern': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        'reliability': 100,
        'description': 'US CISA actively exploited vulnerabilities',
        'api': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    }
}

# ============================================================================
# TIER 2: VENDOR SECURITY ADVISORIES (Official vendor sources)
# ============================================================================
TIER2_SOURCES = {
    'MICROSOFT': {
        'name': 'Microsoft Security Response Center',
        'url_pattern': 'https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}',
        'reliability': 95,
        'domains': ['microsoft.com', 'msrc.microsoft.com']
    },
    'CISCO': {
        'name': 'Cisco Security Advisories',
        'url_pattern': 'https://sec.cloudapps.cisco.com/security/center/publicationListing.x',
        'reliability': 95,
        'domains': ['cisco.com']
    },
    'ADOBE': {
        'name': 'Adobe Security Bulletins',
        'url_pattern': 'https://helpx.adobe.com/security.html',
        'reliability': 95,
        'domains': ['adobe.com', 'helpx.adobe.com']
    },
    'APPLE': {
        'name': 'Apple Security Updates',
        'url_pattern': 'https://support.apple.com/en-us/HT201222',
        'reliability': 95,
        'domains': ['apple.com', 'support.apple.com']
    },
    'GOOGLE': {
        'name': 'Google Security Bulletins',
        'url_pattern': 'https://source.android.com/security/bulletin',
        'reliability': 95,
        'domains': ['google.com', 'android.com']
    },
    'ORACLE': {
        'name': 'Oracle Critical Patch Updates',
        'url_pattern': 'https://www.oracle.com/security-alerts/',
        'reliability': 95,
        'domains': ['oracle.com']
    },
    'REDHAT': {
        'name': 'Red Hat Security Advisories',
        'url_pattern': 'https://access.redhat.com/security/cve/{cve_id}',
        'reliability': 95,
        'domains': ['redhat.com']
    },
    'DEBIAN': {
        'name': 'Debian Security Tracker',
        'url_pattern': 'https://security-tracker.debian.org/tracker/{cve_id}',
        'reliability': 95,
        'domains': ['debian.org']
    },
    'UBUNTU': {
        'name': 'Ubuntu Security Notices',
        'url_pattern': 'https://ubuntu.com/security/{cve_id}',
        'reliability': 95,
        'domains': ['ubuntu.com']
    },
    'VMWARE': {
        'name': 'VMware Security Advisories',
        'url_pattern': 'https://www.vmware.com/security/advisories.html',
        'reliability': 95,
        'domains': ['vmware.com']
    }
}

# ============================================================================
# TIER 3: REPUTABLE AGGREGATORS (Trusted third-party databases)
# ============================================================================
TIER3_SOURCES = {
    'CVEDETAILS': {
        'name': 'CVE Details',
        'url_pattern': 'https://www.cvedetails.com/cve/{cve_id}',
        'reliability': 85,
        'description': 'Comprehensive CVE database with statistics',
        'domains': ['cvedetails.com']
    },
    'VULNERS': {
        'name': 'Vulners Database',
        'url_pattern': 'https://vulners.com/cve/{cve_id}',
        'reliability': 85,
        'description': 'Vulnerability database with exploit tracking',
        'domains': ['vulners.com']
    },
    'VULNDB': {
        'name': 'VulnDB',
        'url_pattern': 'https://vuldb.com/?id.',
        'reliability': 80,
        'description': 'Commercial vulnerability database',
        'domains': ['vuldb.com']
    }
}

# ============================================================================
# TIER 4: SECURITY NEWS & RESEARCH (Must be cross-verified)
# ============================================================================
TIER4_SOURCES = {
    'BLEEPINGCOMPUTER': {
        'name': 'BleepingComputer',
        'reliability': 75,
        'domains': ['bleepingcomputer.com'],
        'note': 'News site - requires verification from Tier 1-2 sources'
    },
    'THEHACKERNEWS': {
        'name': 'The Hacker News',
        'reliability': 75,
        'domains': ['thehackernews.com'],
        'note': 'News site - requires verification from Tier 1-2 sources'
    },
    'SECURITYWEEK': {
        'name': 'SecurityWeek',
        'reliability': 75,
        'domains': ['securityweek.com'],
        'note': 'News site - requires verification from Tier 1-2 sources'
    },
    'DARKREADING': {
        'name': 'Dark Reading',
        'reliability': 75,
        'domains': ['darkreading.com'],
        'note': 'News site - requires verification from Tier 1-2 sources'
    }
}

# ============================================================================
# EXPLOIT SOURCES (For exploit availability checks)
# ============================================================================
EXPLOIT_SOURCES = {
    'EXPLOITDB': {
        'name': 'Exploit Database',
        'url': 'https://www.exploit-db.com/',
        'reliability': 90,
        'domains': ['exploit-db.com']
    },
    'PACKETSTORM': {
        'name': 'Packet Storm Security',
        'url': 'https://packetstormsecurity.com/',
        'reliability': 85,
        'domains': ['packetstormsecurity.com']
    },
    'METASPLOIT': {
        'name': 'Metasploit Framework',
        'url': 'https://www.rapid7.com/db/',
        'reliability': 90,
        'domains': ['rapid7.com', 'metasploit.com']
    }
}

# ============================================================================
# VERIFICATION RULES
# ============================================================================
VERIFICATION_RULES = {
    'minimum_tier1_sources': 1,  # At least 1 Tier 1 source must verify
    'minimum_total_sources': 2,   # At least 2 sources total must verify
    'accept_tier4_only': False,   # Never accept Tier 4 sources alone
    'max_cve_age_days': 730,      # Only accept CVEs from last 2 years for new searches
    'confidence_thresholds': {
        'high': 80,      # 80%+ = High confidence
        'medium': 60,    # 60-79% = Medium confidence
        'low': 40        # 40-59% = Low confidence (flag for review)
    }
}

# ============================================================================
# BLOCKED/UNTRUSTED SOURCES
# ============================================================================
BLOCKED_SOURCES = [
    'random-blog.com',
    'untrusted-source.net',
    # Add domains that have been found to publish unverified information
]

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_source_reliability(url: str) -> int:
    """
    Get reliability score for a given URL
    Returns 0 if untrusted/blocked
    """
    url_lower = url.lower()
    
    # Check if blocked
    for blocked in BLOCKED_SOURCES:
        if blocked in url_lower:
            return 0
    
    # Check tiers
    for tier_sources in [TIER1_SOURCES, TIER2_SOURCES, TIER3_SOURCES, TIER4_SOURCES]:
        for source_info in tier_sources.values():
            domains = source_info.get('domains', [])
            for domain in domains:
                if domain in url_lower:
                    return source_info.get('reliability', 50)
    
    # Unknown source - low reliability
    return 30


def is_authoritative_source(url: str, min_reliability: int = 80) -> bool:
    """
    Check if URL is from an authoritative source
    """
    return get_source_reliability(url) >= min_reliability


def get_tier1_sources() -> list:
    """Get list of Tier 1 (most authoritative) sources"""
    return list(TIER1_SOURCES.keys())


def get_all_trusted_domains() -> list:
    """Get all trusted domains across all tiers"""
    domains = []
    for tier_sources in [TIER1_SOURCES, TIER2_SOURCES, TIER3_SOURCES]:
        for source_info in tier_sources.values():
            domains.extend(source_info.get('domains', []))
    return domains


def format_verification_report(verified_sources: list, confidence: int) -> str:
    """
    Format a human-readable verification report
    """
    tier1 = [s for s in verified_sources if s in TIER1_SOURCES]
    tier2 = [s for s in verified_sources if s in TIER2_SOURCES]
    tier3 = [s for s in verified_sources if s in TIER3_SOURCES]
    
    report = f"Confidence: {confidence}%\n"
    
    if tier1:
        report += f"✅ Verified by authoritative sources: {', '.join(tier1)}\n"
    if tier2:
        report += f"✅ Confirmed by vendor advisories: {', '.join(tier2)}\n"
    if tier3:
        report += f"ℹ️  Found in databases: {', '.join(tier3)}\n"
    
    if confidence >= 80:
        report += "🟢 HIGH CONFIDENCE - Strongly verified"
    elif confidence >= 60:
        report += "🟡 MEDIUM CONFIDENCE - Likely accurate"
    else:
        report += "🟠 LOW CONFIDENCE - Requires additional verification"
    
    return report


# ============================================================================
# CONFIGURATION SUMMARY
# ============================================================================
def print_config_summary():
    """Print configuration summary"""
    print("="*60)
    print("VULNERABILITY VERIFICATION CONFIGURATION")
    print("="*60)
    print(f"\nTier 1 (Authoritative): {len(TIER1_SOURCES)} sources")
    for name, info in TIER1_SOURCES.items():
        print(f"  - {name}: {info['name']} (Reliability: {info['reliability']}%)")
    
    print(f"\nTier 2 (Vendor Advisories): {len(TIER2_SOURCES)} sources")
    for name, info in TIER2_SOURCES.items():
        print(f"  - {name}: {info['name']} (Reliability: {info['reliability']}%)")
    
    print(f"\nTier 3 (Aggregators): {len(TIER3_SOURCES)} sources")
    for name, info in TIER3_SOURCES.items():
        print(f"  - {name}: {info['name']} (Reliability: {info['reliability']}%)")
    
    print(f"\nVerification Rules:")
    print(f"  - Minimum Tier 1 sources: {VERIFICATION_RULES['minimum_tier1_sources']}")
    print(f"  - Minimum total sources: {VERIFICATION_RULES['minimum_total_sources']}")
    print(f"  - Max CVE age: {VERIFICATION_RULES['max_cve_age_days']} days")
    print(f"  - High confidence threshold: {VERIFICATION_RULES['confidence_thresholds']['high']}%")
    print("="*60)


if __name__ == "__main__":
    print_config_summary()