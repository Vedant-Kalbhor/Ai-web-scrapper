import json
import os
import uuid
from datetime import datetime, timezone
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv

load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    google_api_key=GOOGLE_API_KEY,
    temperature=0.2
)

def generate_uuid():
    """Generate a valid UUID for STIX objects"""
    return str(uuid.uuid4())


def get_current_timestamp():
    """Get current timestamp in ISO 8601 format"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def create_stix_vulnerability(vuln_data):
    """Create a STIX vulnerability object from vulnerability data"""
    vuln_id = f"vulnerability--{generate_uuid()}"
    timestamp = get_current_timestamp()
    
    cve_id = vuln_data.get("id", "UNKNOWN")
    
    stix_vuln = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": vuln_id,
        "created": timestamp,
        "modified": timestamp,
        "name": cve_id,
        "description": vuln_data.get("description", "No description available")[:500]  # Limit length
    }
    
    # Add external references if CVE ID exists
    if cve_id.startswith("CVE-"):
        stix_vuln["external_references"] = [
            {
                "source_name": "cve",
                "external_id": cve_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            }
        ]
    
    return stix_vuln, vuln_id


def create_stix_indicator(vuln_data, vuln_id):
    """Create a STIX indicator object for a vulnerability"""
    indicator_id = f"indicator--{generate_uuid()}"
    timestamp = get_current_timestamp()
    
    cve_id = vuln_data.get("id", "UNKNOWN")
    severity = vuln_data.get("severity", "UNKNOWN").upper()
    
    # Create a simple pattern based on vulnerability info
    products = vuln_data.get("affected_products", [])
    if products:
        product_name = products[0].replace(" ", "_").replace("'", "")[:50]
        pattern = f"[software:name = '{product_name}']"
    else:
        pattern = "[file:name = 'exploit.exe']"
    
    stix_indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": timestamp,
        "modified": timestamp,
        "name": f"Exploitation indicator for {cve_id}",
        "description": f"{severity} severity vulnerability exploitation pattern",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": timestamp,
        "labels": ["malicious-activity", "exploit"]
    }
    
    return stix_indicator, indicator_id


def create_stix_relationship(source_id, target_id):
    """Create a STIX relationship object"""
    relationship_id = f"relationship--{generate_uuid()}"
    timestamp = get_current_timestamp()
    
    stix_relationship = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": relationship_id,
        "created": timestamp,
        "modified": timestamp,
        "relationship_type": "indicates",
        "source_ref": source_id,
        "target_ref": target_id
    }
    
    return stix_relationship


def generate_stix_batch_with_ai(vulnerabilities, batch_num):
    """
    Generate STIX objects for a small batch of vulnerabilities using AI.
    Returns list of STIX objects.
    """
    # Prepare minimal vulnerability data
    vuln_summary = []
    for vuln in vulnerabilities[:5]:  # Process only 5 at a time
        summary = {
            "id": vuln.get("id", "UNKNOWN"),
            "title": vuln.get("title", "Unknown")[:100],
            "severity": vuln.get("severity", "UNKNOWN"),
            "products": vuln.get("affected_products", [])[:2]
        }
        vuln_summary.append(summary)
    
    prompt = f"""
You are a cybersecurity data formatter. 
Your task is to generate valid STIX 2.1 JSON objects for vulnerabilities.

Use ONLY the **top 15 vulnerabilities** from the provided list below. 
If there are fewer than 15, include all available.

Generate STIX 2.1 objects for these vulnerabilities and return ONLY a JSON array of objects.

Vulnerabilities (truncated to top 15):
{json.dumps(vuln_summary[:15], indent=2)}

For EACH vulnerability, create exactly 3 STIX objects:
1. A **vulnerability** object  
2. An **indicator** object  
3. A **relationship** object linking the indicator to the vulnerability

Rules:
- Generate unique UUIDs for each ID
- Use current timestamp: {get_current_timestamp()}
- Use "spec_version": "2.1" for ALL objects
- Keep descriptions under 200 characters
- Return ONLY the JSON array — no markdown, no commentary, no extra text

Example output format:
[
  {{
    "type": "vulnerability",
    "spec_version": "2.1",
    "id": "vulnerability--{generate_uuid()}",
    "created": "{get_current_timestamp()}",
    "modified": "{get_current_timestamp()}",
    "name": "CVE-2025-1234",
    "description": "Brief description here",
    "external_references": [{{"source_name": "cve", "external_id": "CVE-2025-1234"}}]
  }},
  {{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--{generate_uuid()}",
    "created": "{get_current_timestamp()}",
    "modified": "{get_current_timestamp()}",
    "name": "Exploit indicator",
    "description": "Exploitation pattern",
    "pattern": "[file:name = 'malware.exe']",
    "pattern_type": "stix",
    "valid_from": "{get_current_timestamp()}",
    "labels": ["malicious-activity"]
  }},
  {{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--{generate_uuid()}",
    "created": "{get_current_timestamp()}",
    "modified": "{get_current_timestamp()}",
    "relationship_type": "indicates",
    "source_ref": "indicator--{generate_uuid()}",
    "target_ref": "vulnerability--{generate_uuid()}"
  }}
]

Now generate the JSON array with a total of {min(len(vuln_summary), 15) * 3} objects.
"""

    try:
        response = llm.invoke(prompt)
        content = response.content.strip()
        
        # Clean markdown
        content = content.replace("```json", "").replace("```", "").strip()
        
        # Parse JSON
        objects = json.loads(content)
        
        if not isinstance(objects, list):
            raise ValueError("Response is not a JSON array")
        
        print(f"  [+] Batch {batch_num}: Generated {len(objects)} STIX objects")
        return objects
        
    except json.JSONDecodeError as e:
        print(f"  [!] Batch {batch_num}: JSON parse error - {e}")
        print(f"  [!] Response preview: {content[:300]}")
        return []
    except Exception as e:
        print(f"  [!] Batch {batch_num}: Error - {e}")
        return []


def generate_stix_from_report(json_report_path="vulnerability_report.json", output_path="vulnerabilities_stix.json"):
    """
    Generate STIX 2.1 format from vulnerability report.
    Uses a hybrid approach: AI for complex formatting + manual creation for reliability.
    """
    print(f"[*] Reading vulnerability data from {json_report_path}...")
    
    if not os.path.exists(json_report_path):
        raise FileNotFoundError(f"Vulnerability report not found: {json_report_path}")
    
    with open(json_report_path, "r", encoding="utf-8") as f:
        vuln_data = json.load(f)
    
    vulnerabilities = vuln_data.get("vulnerabilities", [])
    
    if not vulnerabilities:
        raise ValueError("No vulnerabilities found in the report")
    
    print(f"[*] Processing {len(vulnerabilities)} vulnerabilities...")
    
    # Limit to 30 vulnerabilities to avoid token issues
    vulnerabilities = vulnerabilities[:30]
    
    all_stix_objects = []
    
    # Process in batches of 5 vulnerabilities
    batch_size = 5
    for i in range(0, len(vulnerabilities), batch_size):
        batch = vulnerabilities[i:i+batch_size]
        batch_num = (i // batch_size) + 1
        
        print(f"[*] Processing batch {batch_num} ({len(batch)} vulnerabilities)...")
        
        # Try AI generation first
        ai_objects = generate_stix_batch_with_ai(batch, batch_num)
        
        if ai_objects and len(ai_objects) > 0:
            all_stix_objects.extend(ai_objects)
        else:
            # Fallback: Manual generation
            print(f"  [*] Batch {batch_num}: Using manual generation as fallback")
            for vuln in batch:
                try:
                    # Create vulnerability object
                    vuln_obj, vuln_id = create_stix_vulnerability(vuln)
                    all_stix_objects.append(vuln_obj)
                    
                    # Create indicator object
                    indicator_obj, indicator_id = create_stix_indicator(vuln, vuln_id)
                    all_stix_objects.append(indicator_obj)
                    
                    # Create relationship
                    relationship_obj = create_stix_relationship(indicator_id, vuln_id)
                    all_stix_objects.append(relationship_obj)
                    
                except Exception as e:
                    print(f"    [!] Error creating STIX objects for {vuln.get('id', 'UNKNOWN')}: {e}")
    
    # Create STIX bundle
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{generate_uuid()}",
        "objects": all_stix_objects
    }
    
    print(f"[+] Generated STIX bundle with {len(all_stix_objects)} objects")
    
    # Validate bundle
    if len(all_stix_objects) == 0:
        raise ValueError("No STIX objects were generated")
    
    # Save to file
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(stix_bundle, f, indent=2)
    
    print(f"[+] STIX file saved to {output_path}")
    
    # Print summary
    object_types = {}
    for obj in all_stix_objects:
        obj_type = obj.get("type", "unknown")
        object_types[obj_type] = object_types.get(obj_type, 0) + 1
    
    print(f"[+] Summary: {object_types}")
    
    return output_path


if __name__ == "__main__":
    # Test the generator
    try:
        output = generate_stix_from_report()
        print(f"\n[SUCCESS] STIX file generated: {output}")
    except Exception as e:
        print(f"\n[ERROR] {e}")