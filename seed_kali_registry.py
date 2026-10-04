import json
import os
import hashlib

def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

tools = [
    {"name": "nmap", "desc": "Network exploration tool and security / port scanner", "tags": ["scanning", "network"]},
    {"name": "metasploit", "desc": "Penetration testing software", "tags": ["exploitation", "framework"]},
    {"name": "wireshark", "desc": "Network protocol analyzer", "tags": ["sniffing", "network"]},
    {"name": "sqlmap", "desc": "Automatic SQL injection and database takeover tool", "tags": ["web", "database", "exploitation"]},
    {"name": "john", "desc": "John the Ripper password cracker", "tags": ["password", "cracking"]},
    {"name": "aircrack-ng", "desc": "WiFi security auditing tools suite", "tags": ["wireless", "cracking"]},
    {"name": "gobuster", "desc": "Directory/File, DNS and VHost busting tool", "tags": ["web", "bruteforce"]},
    {"name": "burpsuite", "desc": "Web vulnerability scanner", "tags": ["web", "scanner"]},
    {"name": "hydra", "desc": "Network logon cracker", "tags": ["password", "bruteforce"]},
    {"name": "hashcat", "desc": "World's fastest and most advanced password recovery utility", "tags": ["password", "cracking"]},
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
        "display_name": name.capitalize(),
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
        "display_name": name.capitalize(),
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
