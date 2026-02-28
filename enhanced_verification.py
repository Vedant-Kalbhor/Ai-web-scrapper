"""
Enhanced Multi-Source CVE Verification System
Prevents LLM hallucinations by verifying against multiple authoritative sources
"""

import requests
import re
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone
import json
from typing import Dict, List, Optional, Tuple
import time

class CVEVerifier:
    """
    Multi-layer CVE verification system using authoritative sources
    """
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Authoritative sources for verification
        self.sources = {
            'nvd': 'https://nvd.nist.gov/vuln/detail/',
            'cisa_kev': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            'mitre': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=',
            'cvedetails': 'https://www.cvedetails.com/cve/',
            'vulners': 'https://vulners.com/cve/',
            'opencve': 'https://www.opencve.io/cve/'
        }
        
        # Cache for API responses (avoid rate limiting)
        self.cache = {}
        self.cache_duration = 3600  # 1 hour
    
    def verify_cve_exists(self, cve_id: str) -> Dict:
        """
        Verify if a CVE ID actually exists across multiple authoritative sources
        Returns detailed verification report
        """
        print(f"\n🔍 Verifying {cve_id} across multiple sources...")
        
        if not self._is_valid_cve_format(cve_id):
            return {
                'exists': False,
                'confidence': 0,
                'reason': 'Invalid CVE ID format',
                'sources_checked': [],
                'verified_sources': []
            }
        
        verification_results = {
            'cve_id': cve_id,
            'exists': False,
            'confidence': 0,  # 0-100
            'verified_sources': [],
            'sources_checked': [],
            'details': {},
            'verified_at': datetime.now(timezone.utc).isoformat() + 'Z'
        }
        
        # Check multiple sources (parallel checks would be faster)
        checks = [
            self._check_nvd(cve_id),
            self._check_mitre(cve_id),
            self._check_cisa_kev(cve_id),
            self._check_cvedetails(cve_id),
            self._check_vulners(cve_id)
        ]
        
        verified_count = 0
        total_checks = len(checks)
        
        for check_result in checks:
            source = check_result.get('source')
            verification_results['sources_checked'].append(source)
            
            if check_result.get('found'):
                verified_count += 1
                verification_results['verified_sources'].append(source)
                
                # Store details from first verified source
                if not verification_results['details']:
                    verification_results['details'] = check_result.get('details', {})
        
        # Calculate confidence score
        verification_results['confidence'] = int((verified_count / total_checks) * 100)
        
        # === STEP B: Dynamic threshold ===
        # - If CVE is from the current year => require 2 sources (higher scrutiny)
        # - Else (older CVE) => require 1 source (allow earlier-but-valid CVEs)
        try:
            cve_year = int(cve_id.split('-')[1])
        except Exception:
            cve_year = None

        current_year = datetime.now(timezone.utc).year
        min_required = 2 if cve_year == current_year else 1

        if verified_count >= min_required:
            verification_results['exists'] = True
            verification_results['reason'] = f"Verified in {verified_count}/{total_checks} authoritative sources (min_required={min_required})"
            print(f"✅ {cve_id} VERIFIED in {verified_count} sources (min_required={min_required})")
        else:
            verification_results['exists'] = False
            verification_results['reason'] = f"Only found in {verified_count}/{total_checks} sources (minimum {min_required} required)"
            print(f"❌ {cve_id} NOT VERIFIED (found in {verified_count} sources; min_required={min_required})") 
        
        return verification_results
    
    def _is_valid_cve_format(self, cve_id: str) -> bool:
        """Check if CVE ID follows valid format"""
        pattern = r'^CVE-\d{4}-\d{4,}$'
        return bool(re.match(pattern, cve_id.upper()))
    
    def _check_nvd(self, cve_id: str) -> Dict:
        """Verify against NVD (NIST)"""
        try:
            url = f"{self.sources['nvd']}{cve_id}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check for error messages indicating CVE doesn't exist
                error_indicators = [
                    'not found',
                    'does not exist',
                    'no results',
                    'invalid cve'
                ]
                
                page_text = soup.get_text().lower()
                if any(indicator in page_text for indicator in error_indicators):
                    return {'source': 'NVD', 'found': False}
                
                # Extract details
                desc_tag = soup.find('p', {'data-testid': 'vuln-description'})
                cvss_tag = soup.find('a', {'data-testid': 'vuln-cvss3-link'})
                
                details = {}
                if desc_tag:
                    details['description'] = desc_tag.get_text(strip=True)
                if cvss_tag:
                    score_match = re.search(r'(\d+\.\d+)', cvss_tag.get_text())
                    if score_match:
                        details['cvss_score'] = float(score_match.group(1))
                
                return {
                    'source': 'NVD',
                    'found': True,
                    'details': details,
                    'url': url
                }
            
            return {'source': 'NVD', 'found': False}
            
        except Exception as e:
            print(f"⚠️  NVD check failed: {e}")
            return {'source': 'NVD', 'found': False, 'error': str(e)}
    
    def _check_mitre(self, cve_id: str) -> Dict:
        """Verify against MITRE CVE database"""
        try:
            url = f"{self.sources['mitre']}{cve_id}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # MITRE shows specific error for non-existent CVEs
                if 'ERROR: Couldn\'t find' in response.text:
                    return {'source': 'MITRE', 'found': False}
                
                # Look for CVE description
                desc_div = soup.find('div', {'id': 'GeneratedTable'})
                if desc_div:
                    desc_text = desc_div.get_text(strip=True)
                    if desc_text and len(desc_text) > 20:
                        return {
                            'source': 'MITRE',
                            'found': True,
                            'details': {'description': desc_text[:500]},
                            'url': url
                        }
            
            return {'source': 'MITRE', 'found': False}
            
        except Exception as e:
            print(f"⚠️  MITRE check failed: {e}")
            return {'source': 'MITRE', 'found': False, 'error': str(e)}
    
    def _check_cisa_kev(self, cve_id: str) -> Dict:
        """Check CISA Known Exploited Vulnerabilities"""
        try:
            # Use cache if available
            cache_key = 'cisa_kev_data'
            if cache_key in self.cache:
                cached_time, data = self.cache[cache_key]
                if time.time() - cached_time < self.cache_duration:
                    kev_data = data
                else:
                    response = requests.get(self.sources['cisa_kev'], timeout=10)
                    kev_data = response.json()
                    self.cache[cache_key] = (time.time(), kev_data)
            else:
                response = requests.get(self.sources['cisa_kev'], timeout=10)
                kev_data = response.json()
                self.cache[cache_key] = (time.time(), kev_data)
            
            # Search for CVE
            for vuln in kev_data.get('vulnerabilities', []):
                if vuln.get('cveID', '').upper() == cve_id.upper():
                    return {
                        'source': 'CISA-KEV',
                        'found': True,
                        'details': {
                            'description': vuln.get('shortDescription'),
                            'vendor': vuln.get('vendorProject'),
                            'product': vuln.get('product'),
                            'exploited': True
                        },
                        'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
                    }
            
            return {'source': 'CISA-KEV', 'found': False}
            
        except Exception as e:
            print(f"⚠️  CISA KEV check failed: {e}")
            return {'source': 'CISA-KEV', 'found': False, 'error': str(e)}
    
    def _check_cvedetails(self, cve_id: str) -> Dict:
        """Verify against CVEDetails"""
        try:
            # Extract CVE number (e.g., CVE-2024-1234 -> 2024-1234)
            cve_num = cve_id.replace('CVE-', '')
            url = f"{self.sources['cvedetails']}{cve_num}"
            
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check if page shows "Not Found" or similar
                if 'not found' in response.text.lower():
                    return {'source': 'CVEDetails', 'found': False}
                
                # Look for CVSS score or description
                cvss_div = soup.find('div', class_='cvssbox')
                if cvss_div:
                    return {
                        'source': 'CVEDetails',
                        'found': True,
                        'url': url
                    }
            
            return {'source': 'CVEDetails', 'found': False}
            
        except Exception as e:
            print(f"⚠️  CVEDetails check failed: {e}")
            return {'source': 'CVEDetails', 'found': False, 'error': str(e)}
    
    def _check_vulners(self, cve_id: str) -> Dict:
        """Verify against Vulners database"""
        try:
            url = f"{self.sources['vulners']}{cve_id}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                # Vulners redirects to 404 page for non-existent CVEs
                if '404' in response.url or 'not found' in response.text.lower():
                    return {'source': 'Vulners', 'found': False}
                
                return {
                    'source': 'Vulners',
                    'found': True,
                    'url': url
                }
            
            return {'source': 'Vulners', 'found': False}
            
        except Exception as e:
            print(f"⚠️  Vulners check failed: {e}")
            return {'source': 'Vulners', 'found': False, 'error': str(e)}
    
    def verify_vendor_advisory(self, vendor: str, cve_id: str) -> Dict:
        """
        Check if vendor has published an advisory for this CVE
        """
        vendor_urls = {
            'microsoft': f'https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}',
            'cisco': f'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{cve_id}',
            'adobe': f'https://helpx.adobe.com/security/{cve_id}.html',
            'apple': f'https://support.apple.com/en-us/HT201222',  # General page
            'oracle': f'https://www.oracle.com/security-alerts/',
            'redhat': f'https://access.redhat.com/security/cve/{cve_id}',
            'debian': f'https://security-tracker.debian.org/tracker/{cve_id}',
            'ubuntu': f'https://ubuntu.com/security/{cve_id}'
        }
        
        vendor_lower = vendor.lower()
        
        # Try exact match first
        if vendor_lower in vendor_urls:
            url = vendor_urls[vendor_lower]
            try:
                response = requests.get(url, headers=self.headers, timeout=10)
                if response.status_code == 200:
                    return {
                        'source': f'{vendor} Security Advisory',
                        'found': True,
                        'url': url
                    }
            except:
                pass
        
        return {'source': f'{vendor} Advisory', 'found': False}
    
    def get_verification_summary(self, cve_id: str) -> str:
        """
        Get a human-readable verification summary
        """
        result = self.verify_cve_exists(cve_id)
        
        if result['exists']:
            sources = ', '.join(result['verified_sources'])
            return f"✅ VERIFIED ({result['confidence']}% confidence) - Found in: {sources}"
        else:
            return f"❌ NOT VERIFIED ({result['confidence']}% confidence) - {result['reason']}"


class VulnerabilityValidator:
    """
    Validates entire vulnerability entries, not just CVE IDs
    """
    
    def __init__(self):
        self.verifier = CVEVerifier()
    
    def validate_vulnerability(self, vuln: Dict) -> Tuple[bool, Dict]:
        """
        Validate a complete vulnerability entry
        Returns: (is_valid, verification_report)
        """
        cve_id = vuln.get('cve_id', '').strip().upper()
        
        # Skip if no CVE ID
        if not cve_id or cve_id == 'N/A' or not cve_id.startswith('CVE-'):
            return False, {
                'valid': False,
                'reason': 'No valid CVE ID provided',
                'confidence': 0
            }
        
        # Verify CVE exists
        verification = self.verifier.verify_cve_exists(cve_id)
        
        if not verification['exists']:
            return False, {
                'valid': False,
                'reason': verification['reason'],
                'confidence': verification['confidence'],
                'cve_id': cve_id
            }
        
        # Cross-reference vulnerability details with verified sources
        if verification['details']:
            vuln_enhanced = vuln.copy()
            vuln_enhanced['verification'] = verification
            vuln_enhanced['verified'] = True
            
            # Add verified details if missing
            if not vuln.get('description') and verification['details'].get('description'):
                vuln_enhanced['description'] = verification['details']['description']
            
            if not vuln.get('cvss_score') and verification['details'].get('cvss_score'):
                vuln_enhanced['cvss_score'] = verification['details']['cvss_score']
            
            return True, {
                'valid': True,
                'confidence': verification['confidence'],
                'verified_sources': verification['verified_sources'],
                'enhanced_data': vuln_enhanced
            }
        
        return True, {
            'valid': True,
            'confidence': verification['confidence'],
            'verified_sources': verification['verified_sources']
        }
    
    def filter_hallucinated_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Filter out hallucinated/fake vulnerabilities from LLM output
        Returns only verified vulnerabilities
        """
        verified_vulns = []
        rejected_vulns = []
        
        print(f"\n🔍 Validating {len(vulnerabilities)} vulnerabilities...")
        
        for vuln in vulnerabilities:
            is_valid, report = self.validate_vulnerability(vuln)
            
            if is_valid:
                if 'enhanced_data' in report:
                    verified_vulns.append(report['enhanced_data'])
                else:
                    vuln['verification'] = report
                    vuln['verified'] = True
                    verified_vulns.append(vuln)
                
                print(f"✅ {vuln.get('cve_id')}: Verified ({report['confidence']}%)")
            else:
                rejected_vulns.append({
                    'cve_id': vuln.get('cve_id'),
                    'reason': report['reason'],
                    'confidence': report['confidence']
                })
                print(f"❌ {vuln.get('cve_id')}: REJECTED - {report['reason']}")
        
        print(f"\n📊 Validation Summary:")
        print(f"   ✅ Verified: {len(verified_vulns)}")
        print(f"   ❌ Rejected: {len(rejected_vulns)}")
        
        return verified_vulns


# Example usage
if __name__ == "__main__":
    # Test verification
    verifier = CVEVerifier()
    validator = VulnerabilityValidator()
    
    # Test with real CVE
    print("\n" + "="*60)
    print("Testing with REAL CVE")
    print("="*60)
    result = verifier.verify_cve_exists("CVE-2024-21413")
    print(f"\nVerification Result:")
    print(json.dumps(result, indent=2))
    
    # Test with fake CVE
    print("\n" + "="*60)
    print("Testing with FAKE CVE")
    print("="*60)
    result = verifier.verify_cve_exists("CVE-2025-98765")
    print(f"\nVerification Result:")
    print(json.dumps(result, indent=2))
    
    # Test vulnerability validation
    print("\n" + "="*60)
    print("Testing Vulnerability Validation")
    print("="*60)
    
    test_vulns = [
        {
            "cve_id": "CVE-2024-21413",
            "title": "Microsoft Outlook Remote Code Execution",
            "severity": "CRITICAL"
        },
        {
            "cve_id": "CVE-2025-98765",
            "title": "Fake Deloitte Vulnerability",
            "severity": "CRITICAL"
        }
    ]
    
    verified = validator.filter_hallucinated_vulnerabilities(test_vulns)
    print(f"\n✅ Verified vulnerabilities: {len(verified)}")