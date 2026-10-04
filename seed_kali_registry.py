import json
import os
import hashlib

def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

tools = [
    {"name": "nmap", "display": "Nmap", "desc": "Network exploration tool and security / port scanner", "tags": ["scanning", "network", "discovery"]},
    {"name": "metasploit", "display": "Metasploit Framework", "desc": "Exploit development and penetration testing framework", "tags": ["exploitation", "framework"]},
    {"name": "wireshark", "display": "Wireshark", "desc": "Network protocol analyzer", "tags": ["sniffing", "network", "packet-analysis"]},
    {"name": "sqlmap", "display": "sqlmap", "desc": "Automatic SQL injection detection and testing tool", "tags": ["web", "database", "exploitation"]},
    {"name": "john", "display": "John the Ripper", "desc": "Password hash auditing and recovery tool", "tags": ["password", "cracking", "audit"]},
    {"name": "aircrack-ng", "display": "Aircrack-ng", "desc": "WiFi security auditing tools suite", "tags": ["wireless", "cracking", "audit"]},
    {"name": "gobuster", "display": "Gobuster", "desc": "Directory, DNS and virtual host discovery tool", "tags": ["web", "bruteforce", "content-discovery"]},
    {"name": "burpsuite", "display": "Burp Suite", "desc": "Web application security testing proxy and scanner", "tags": ["web", "proxy", "scanner"]},
    {"name": "hydra", "display": "Hydra", "desc": "Network login auditing tool", "tags": ["password", "bruteforce", "audit"]},
    {"name": "hashcat", "display": "Hashcat", "desc": "Advanced password hash recovery utility", "tags": ["password", "cracking", "gpu"]},
    {"name": "ffuf", "display": "ffuf", "desc": "Fast web fuzzer for content discovery and parameter testing", "tags": ["web", "fuzzing", "content-discovery"]},
    {"name": "feroxbuster", "display": "Feroxbuster", "desc": "Recursive content discovery tool for web assessment", "tags": ["web", "content-discovery", "rust"]},
    {"name": "nikto", "display": "Nikto", "desc": "Web server misconfiguration and exposure scanner", "tags": ["web", "scanner", "misconfiguration"]},
    {"name": "amass", "display": "OWASP Amass", "desc": "Attack surface mapping and external asset discovery", "tags": ["recon", "dns", "attack-surface"]},
    {"name": "theharvester", "display": "theHarvester", "desc": "Email, subdomain and host intelligence gathering tool", "tags": ["recon", "osint", "dns"]},
    {"name": "dnsrecon", "display": "DNSRecon", "desc": "DNS enumeration and reconnaissance utility", "tags": ["recon", "dns", "enumeration"]},
    {"name": "masscan", "display": "Masscan", "desc": "High-speed internet-scale port scanner", "tags": ["scanning", "network", "discovery"]},
    {"name": "rustscan", "display": "RustScan", "desc": "Fast port scanner with Nmap handoff workflow", "tags": ["scanning", "network", "rust"]},
    {"name": "nuclei", "display": "Nuclei", "desc": "Template-driven vulnerability scanner", "tags": ["scanner", "templates", "vulnerability"]},
    {"name": "katana", "display": "Katana", "desc": "Web crawler for discovery and security testing workflows", "tags": ["web", "crawler", "recon"]},
    {"name": "httpx", "display": "httpx", "desc": "HTTP probing and service fingerprinting toolkit", "tags": ["web", "fingerprinting", "recon"]},
    {"name": "subfinder", "display": "Subfinder", "desc": "Passive subdomain discovery tool", "tags": ["recon", "dns", "subdomain"]},
    {"name": "whatweb", "display": "WhatWeb", "desc": "Web technology fingerprinting tool", "tags": ["web", "fingerprinting", "recon"]},
    {"name": "zaproxy", "display": "OWASP ZAP", "desc": "Web application security proxy and scanner", "tags": ["web", "proxy", "scanner"]},
    {"name": "trivy", "display": "Trivy", "desc": "Container, filesystem and IaC vulnerability scanner", "tags": ["devsecops", "container", "scanner"]},
    {"name": "gitleaks", "display": "Gitleaks", "desc": "Secret scanning for Git repositories and filesystems", "tags": ["devsecops", "secrets", "scanner"]},
    {"name": "semgrep", "display": "Semgrep", "desc": "Static analysis for code and security rules", "tags": ["devsecops", "sast", "scanner"]},
    {"name": "syft", "display": "Syft", "desc": "Software bill of materials generator", "tags": ["devsecops", "sbom", "supply-chain"]},
    {"name": "grype", "display": "Grype", "desc": "Vulnerability scanner for container images and SBOMs", "tags": ["devsecops", "sbom", "scanner"]},
    {"name": "cosign", "display": "Cosign", "desc": "Container signing, verification and supply-chain attestations", "tags": ["devsecops", "signing", "supply-chain"]},
    {"name": "ghidra", "display": "Ghidra", "desc": "Reverse engineering and binary analysis suite", "tags": ["reverse-engineering", "binary", "analysis"]},
    {"name": "radare2", "display": "Radare2", "desc": "Reverse engineering framework and binary analysis toolkit", "tags": ["reverse-engineering", "binary", "debugging"]},
    {"name": "binwalk", "display": "Binwalk", "desc": "Firmware extraction and analysis tool", "tags": ["reverse-engineering", "firmware", "analysis"]},
    {"name": "yara", "display": "YARA", "desc": "Pattern matching for malware research and file classification", "tags": ["malware-analysis", "rules", "scanner"]},
    {"name": "volatility3", "display": "Volatility 3", "desc": "Memory forensics framework", "tags": ["forensics", "memory", "incident-response"]},
    {"name": "autopsy", "display": "Autopsy", "desc": "Digital forensics platform", "tags": ["forensics", "timeline", "incident-response"]},
]

registry_dir = "registry-data"
tools_dir = os.path.join(registry_dir, "tools")
os.makedirs(tools_dir, exist_ok=True)

index_tools = []

for t in tools:
    name = t["name"]
    version = "1.0.0"
    
    # Create the manifest content
    dummy_tar_content = b"dummy"
    tar_sha = sha256(dummy_tar_content)
    
    manifest_rel_path = f"tools/{name}-{version}.json"
    manifest_abs_path = os.path.join(registry_dir, manifest_rel_path)
    
    manifest_data = {
        "schema_version": "1",
        "id": f"org.kali.tools.{name}",
        "name": name,
        "display_name": t["display"],
        "version": version,
        "description": t["desc"],
        "publisher": {"name": "Kali Linux", "id": "pub_kali"},
        "license": "GPL",
        "categories": ["cybersecurity"],
        "tags": t["tags"],
        "platforms": [{
            "os": "linux", "arch": "x86_64", "abi": "gnu",
            "url": f"https://example.com/kali/{name}.tar.gz",
            "sha256": tar_sha,
            "size": 1024,
            "kind": "native"
        }]
    }
    
    with open(manifest_abs_path, 'w') as f:
        json.dump(manifest_data, f, indent=2)
        
    index_tools.append({
        "id": f"org.kali.tools.{name}",
        "name": name,
        "version": version,
        "display_name": t["display"],
        "description": t["desc"],
        "categories": ["cybersecurity"],
        "tags": t["tags"],
        "publisher_id": "pub_kali",
        "publisher_name": "Kali Linux",
        "trust": "community-verified",
        "license": "GPL",
        "manifest": manifest_rel_path
    })

index_data = {
    "schema_version": "1",
    "registry_name": "kali-registry",
    "tools": index_tools
}

with open(os.path.join(registry_dir, "index.json"), 'w') as f:
    json.dump(index_data, f, indent=2)

print(f"Successfully generated {len(tools)} Kali tools in the registry!")
