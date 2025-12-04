#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template
import nmap
import shodan
import ipaddress
import re
import os
import requests
import time
import json
from pathlib import Path
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

# Carregar variáveis de ambiente
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

# Configurações
NVD_API_KEY = os.getenv("NVD_API_KEY", None)
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", 'liA1qcT0XxNyNUsmPGgRPXRFxPeLla4O')
shodan_api = shodan.Shodan(SHODAN_API_KEY) if SHODAN_API_KEY != 'liA1qcT0XxNyNUsmPGgRPXRFxPeLla4O' else None

# Cache e controle de rate limiting
CACHE_FILE = Path(__file__).parent / "nvd_cache.json"
LAST_REQUEST_TIME = 0

# CVEs conhecidos pré-carregados
COMMON_CVES = {
    "CVE-2021-44228": 10.0,  # Log4j
    "CVE-2021-45046": 9.0,    # Log4j
    "CVE-2017-0144": 8.1,     # EternalBlue
    "CVE-2019-0708": 9.8,     # BlueKeep
    "CVE-2020-1472": 10.0,    # Zerologon
}

app = Flask(__name__)
nm = nmap.PortScanner()

# Funções de cache
def load_cache():
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}

def save_cache(cache):
    try:
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f)
    except IOError:
        pass

# Função otimizada para obter CVSS
def obter_cvss_do_nvd(cve_id):
    global LAST_REQUEST_TIME
    
    # Verifica CVEs comuns primeiro
    if cve_id in COMMON_CVES:
        return COMMON_CVES[cve_id]
    
    # Verifica cache
    cache = load_cache()
    if cve_id in cache:
        return cache[cve_id]
    
    # Rate limiting (6 requisições por segundo)
    elapsed = time.time() - LAST_REQUEST_TIME
    if elapsed < 0.17:
        time.sleep(0.17 - elapsed)
    
    LAST_REQUEST_TIME = time.time()
    
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if vulnerabilities:
                vuln = vulnerabilities[0]
                metrics = vuln.get("cve", {}).get("metrics", {})
                
                if "cvssMetricV31" in metrics:
                    score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV30" in metrics:
                    score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics:
                    score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                else:
                    score = 0.0
                
                # Atualiza cache
                cache[cve_id] = float(score)
                save_cache(cache)
                return float(score)
                
        return 0.0
        
    except Exception as e:
        print(f"Erro ao consultar CVE {cve_id}: {str(e)}")
        return 0.0

# Função para buscar vulnerabilidades no Shodan
def buscar_vulnerabilidades_shodan(ip):
    if not shodan_api or ipaddress.ip_address(ip).is_private:
        return []
    
    try:
        host = shodan_api.host(ip)
        resultado = []
        
        for vuln_id in host.get('vulns', []):
            cve_id = vuln_id.upper() if vuln_id.upper().startswith('CVE-') else f"CVE-{vuln_id}"
            resultado.append({
                "id": cve_id,
                "cvss": host.get('cvss', {}).get(vuln_id, 0.0),
                "descricao": host.get('vulns', {}).get(vuln_id, "Descrição não disponível"),
                "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "shodan_link": f"https://www.shodan.io/host/{ip}#vulnerabilities",
                "fonte": "Shodan"
            })
        return resultado
    except shodan.APIError as e:
        print(f"Erro na API do Shodan: {str(e)}")
        return []
    except Exception as e:
        print(f"Erro ao buscar vulnerabilidades no Shodan: {str(e)}")
        return []

# Função para processar saída do Nmap
def parse_nmap_script_output(script_name, script_output):
    vulns = []
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    
    if isinstance(script_output, str):
        cves = list(set(re.findall(cve_pattern, script_output, re.IGNORECASE)))
        
        # Processamento paralelo dos CVEs
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_cve = {
                executor.submit(obter_cvss_do_nvd, cve.upper()): cve.upper()
                for cve in cves
            }
            
            for future in as_completed(future_to_cve):
                cve_id = future_to_cve[future]
                try:
                    cvss_score = future.result()
                    vulns.append({
                        "id": cve_id,
                        "cvss": cvss_score,
                        "descricao": f"Vulnerabilidade encontrada pelo script {script_name}",
                        "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "fonte": "Nmap Script"
                    })
                except Exception as e:
                    print(f"Erro ao processar CVE {cve_id}: {str(e)}")
                    continue
    
    return vulns

# Função principal de scan
def scan_network(network):
    try:
        # Argumentos otimizados para velocidade
        print(f"Iniciando scan na rede: {network}")
        nm.scan(hosts=network, arguments='-sV -T4 --open --script vulners,banner --min-rate 500 --max-retries 1')
    except Exception as e:
        return {"success": False, "error": str(e), "results": []}

    results = []
    for host in nm.all_hosts():
        host_info = {
            "ip": host,
            "hostname": nm[host].hostname(),
            "ports": [],
            "vulnerabilities": []
        }

        # Busca vulnerabilidades no Shodan (apenas para IPs públicos)
        if not ipaddress.ip_address(host).is_private and shodan_api:
            host_info["shodan_vulnerabilities"] = buscar_vulnerabilidades_shodan(host)

        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                port_info = nm[host][proto][port]
                service_name = port_info.get('name', '')
                service_version = port_info.get('version', '')
                service_product = port_info.get('product', '')
                
                # Processa vulnerabilidades
                vulns = []
                if 'script' in port_info:
                    for script_name, script_output in port_info['script'].items():
                        if 'vuln' in script_name.lower() or 'cve' in script_name.lower():
                            vulns.extend(parse_nmap_script_output(script_name, script_output))

                port_data = {
                    "port": port,
                    "protocol": proto,
                    "state": port_info.get("state", ""),
                    "service": {
                        "name": service_name,
                        "product": service_product,
                        "version": service_version,
                        "extrainfo": port_info.get('extrainfo', '')
                    },
                    "vulnerabilities": vulns,
                    "scripts": []
                }

                if 'script' in port_info:
                    for script_name, script_output in port_info['script'].items():
                        port_data['scripts'].append({
                            "name": script_name,
                            "output": str(script_output)
                        })

                host_info["ports"].append(port_data)
        
        results.append(host_info)
    
    return {"success": True, "results": results}

# Rotas Flask
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400
    
    data = request.get_json()
    network = data.get('network', '').strip()
    
    if not network:
        return jsonify({"success": False, "error": "Network range not specified"}), 400
    
    result = scan_network(network)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)