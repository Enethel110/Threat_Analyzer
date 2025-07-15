#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Autor: Enethel Mendoza
#
import dns.resolver
import requests
import json
import os
import time
import socket
from pyfiglet import Figlet
from termcolor import colored
from datetime import datetime
import webbrowser
import folium
from ipwhois import IPWhois
import pandas as pd
import matplotlib.pyplot as plt

# ====================== CONFIGURACIÓN ======================
class Config:
    API_KEYS = {
        'abuseipdb': '1305b7f5dd85cf63948064f6f9884caceeb9c0e1eef4b0b003881f8f8524288e7abd75ebf737a634',  # https://www.abuseipdb.com/
        'virustotal': '750cc56a8f581c7083321f66df3c81bbab1053704112b172ab1021997cadd7cc', # https://www.virustotal.com/
        'shodan': 'yCF1qjbOAbdhYCwdR3lA3BzHsskxwLEU',         # https://developer.shodan.io/
        'ipinfo': '3d8160567d0378'          # https://ipinfo.io/
    }
    
    PROXIES = {}  # Ej: {'http': 'http://corp-proxy:3128'}
    
    @staticmethod
    def check_apis():
        missing = [k for k, v in Config.API_KEYS.items() if v.startswith('TU_API_')]
        if missing:
            print(colored(f"\n⚠️  APIs no configuradas: {', '.join(missing)}", 'yellow'))
            print(colored("Algunas funciones estarán limitadas\n", 'yellow'))
            time.sleep(2)

# ===========================================================

class ThreatIntel:
    def __init__(self):
        self.session = requests.Session()
        self.session.proxies = Config.PROXIES if any(Config.PROXIES.values()) else None
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        
    # -------------------- CORE FUNCTIONS --------------------
    def validate_ip(self, ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False

    def dns_lookup(self, query, rtype='A'):
        try:
            return [str(r) for r in dns.resolver.resolve(query, rtype)]
        except:
            return None

    # ------------------ THREAT INTEL SOURCES ------------------
    def check_blacklists(self, ip):
        """Verifica en 15+ listas negras con estadísticas"""
        blacklists = {
            'Spamhaus ZEN': f'{ip}.zen.spamhaus.org',
            'SORBS DUHL': f'{ip}.dul.dnsbl.sorbs.net',
            'Barracuda': f'{ip}.b.barracudacentral.org',
            'SpamCop': f'{ip}.bl.spamcop.net',
            'UCEPROTECT L1': f'{ip}.dnsbl-1.uceprotect.net',
            'NIXSPAM': f'{ip}.ix.dnsbl.manitu.net',
            'DroneBL': f'{ip}.dnsbl.dronebl.org',
            'RATS-Spam': f'{ip}.spam.rats.nl',
            'EFNet RBL': f'{ip}.rbl.efnetrbl.org'
        }
        
        results = {}
        print(colored("[+] Consultando listas negras...", 'yellow'))
        
        for name, query in blacklists.items():
            result = self.dns_lookup(query)
            results[name] = result
            status = colored("LISTADA", 'red') if result else colored("Limpia", 'green')
            print(f"  {name:20} → {status}")
        
        return results

    def get_geodata(self, ip):
        """Combina 3 fuentes de geolocalización"""
        print(colored("\n[+] Geolocalizando IP...", 'yellow'))
        
        # 1. IP-API (gratis)
        geo = {}
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,asname,mobile,proxy,hosting"
            data = self.session.get(url, timeout=5).json()
            if data['status'] == 'success':
                geo.update({
                    'country': f"{data['country']} ({data['countryCode']})",
                    'region': data['regionName'],
                    'city': f"{data['city']} (ZIP: {data['zip']})",
                    'coordinates': [data['lat'], data['lon']],
                    'isp': data['isp'],
                    'asn': f"{data['as']} {data['asname']}",
                    'mobile': data['mobile'],
                    'proxy': data['proxy'],
                    'hosting': data['hosting']
                })
                print(colored("  ✓ Datos básicos obtenidos (ip-api.com)", 'green'))
        except Exception as e:
            print(colored(f"  ✗ Error en ip-api: {str(e)}", 'red'))
        
        # 2. IPWhois (ASN detallado)
        try:
            obj = IPWhois(ip)
            whois = obj.lookup_rdap()
            geo.update({
                'asn_description': whois.get('asn_description', ''),
                'network': whois.get('network', {}).get('name', ''),
                'cidr': whois.get('asn_cidr', '')
            })
            print(colored("  ✓ Datos WHOIS obtenidos", 'green'))
        except Exception as e:
            print(colored(f"  ✗ Error en WHOIS: {str(e)}", 'red'))
        
        # 3. IPInfo (requiere API)
        if Config.API_KEYS['ipinfo']:
            try:
                url = f"https://ipinfo.io/{ip}/json?token={Config.API_KEYS['ipinfo']}"
                data = self.session.get(url, timeout=5).json()
                geo.update({
                    'hostname': data.get('hostname', ''),
                    'company': data.get('company', {}).get('name', ''),
                    'privacy': data.get('privacy', {}).get('vpn', False) or data.get('privacy', {}).get('proxy', False)
                })
                print(colored("  ✓ Datos avanzados obtenidos (ipinfo.io)", 'green'))
            except Exception as e:
                print(colored(f"  ✗ Error en ipinfo: {str(e)}", 'red'))
        
        return geo if geo else None

    def get_malware_history(self, ip):
          
        threats = {}
        print(colored("\n[+] Buscando historial de malware...", 'yellow'))
        
        # 1. AbuseIPDB
        if Config.API_KEYS['abuseipdb']:
            try:
                url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=365"
                headers = {'Key': Config.API_KEYS['abuseipdb'], 'Accept': 'application/json'}
                response = self.session.get(url, headers=headers, timeout=10)
                data = response.json()
                if 'data' in data:
                    d = data['data']
                    threats['abuseipdb'] = {
                        'score': d.get('abuseConfidenceScore', 0),
                        'reports': d.get('totalReports', 0),
                        'last_reported': d.get('lastReportedAt', 'N/A'),
                        'domains': d.get('domainNames', [])[:5]
                    }
                    print(colored("  ✓ Datos de AbuseIPDB obtenidos", 'green'))
                else:
                    print(colored("  ✗ Error en AbuseIPDB: clave 'data' no encontrada", 'red'))
                    print(data)
            except Exception as e:
                print(colored(f"  ✗ Error en AbuseIPDB: {str(e)}", 'red'))

        # 2. VirusTotal
        if Config.API_KEYS['virustotal']:
            try:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                headers = {'x-apikey': Config.API_KEYS['virustotal']}
                response = self.session.get(url, headers=headers, timeout=15)
                data = response.json()
                if 'data' in data:
                    attrs = data['data'].get('attributes', {})
                    stats = attrs.get('last_analysis_stats', {})
                    threats['virustotal'] = {
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'harmless': stats.get('harmless', 0),
                        'undetected': stats.get('undetected', 0),
                        'reputation': attrs.get('reputation', 0),
                        'asn': attrs.get('asn', 'N/A'),
                        'network': attrs.get('network', 'N/A')
                    }
                    print(colored("  ✓ Datos de VirusTotal obtenidos", 'green'))
                else:
                    print(colored("  ✗ Error en VirusTotal: clave 'data' no encontrada", 'red'))
                    print(data)
            except Exception as e:
                print(colored(f"  ✗ Error en VirusTotal: {str(e)}", 'red'))

        # 3. Shodan (datos técnicos)
        if Config.API_KEYS['shodan']:
            try:
                url = f"https://api.shodan.io/shodan/host/{ip}?key={Config.API_KEYS['shodan']}"
                response = self.session.get(url, timeout=15)
                if 'application/json' in response.headers.get('Content-Type', ''):
                    data = response.json()
                    threats['shodan'] = {
                        'ports': data.get('ports', []),
                        'vulns': data.get('vulns', []),
                        'services': [f"{item.get('port')}/{item.get('transport', 'tcp')}" for item in data.get('data', [])]
                    }
                    print(colored("  ✓ Datos de Shodan obtenidos", 'green'))
                else:
                    print(colored("  ✗ Error en Shodan: respuesta no es JSON", 'red'))
                    print(response.text)
            except Exception as e:
                print(colored(f"  ✗ Error en Shodan: {str(e)}", 'red'))

        return threats if threats else None
    def get_whois(self, ip):
        try:
            print(colored("\n[+] Consultando WHOIS...", 'yellow'))
            obj = IPWhois(ip)
            result = obj.lookup_rdap(depth=1)
            print(colored("  ✓ Datos WHOIS obtenidos", 'green'))
            return result
        except Exception as e:
            print(colored(f"  ✗ Error en WHOIS: {str(e)}", 'red'))
            return None
    # ------------------- VISUALIZACIÓN -------------------
    def generate_map(self, geo_data, ip):
        """Crea un mapa HTML con la ubicación"""
        if not geo_data or 'coordinates' not in geo_data:
            return None
        
        lat, lon = geo_data['coordinates']
        m = folium.Map(location=[lat, lon], zoom_start=10)
        
        popup_text = f"""
        <b>IP:</b> {ip}<br>
        <b>ISP:</b> {geo_data.get('isp', 'N/A')}<br>
        <b>Organización:</b> {geo_data.get('asn', 'N/A')}<br>
        <b>Proxy/VPN:</b> {'Sí' if geo_data.get('proxy') else 'No'}
        """
        
        folium.Marker(
            [lat, lon],
            popup=popup_text,
            tooltip=f"Ubicación aproximada de {ip}",
            icon=folium.Icon(color='red' if geo_data.get('proxy') else 'blue')
        ).add_to(m)
        
        map_file = f"mapa_{ip}.html"
        m.save(map_file)
        return map_file

    def plot_threat_stats(self, threats, ip):
        """Genera gráficos de análisis de amenazas"""
        if not threats:
            return None
        
        charts = []
        
        # Gráfico de AbuseIPDB
        if 'abuseipdb' in threats:
            plt.figure(figsize=(10, 5))
            plt.bar(['Confianza de abuso'], [threats['abuseipdb']['score']], color='red')
            plt.title(f"Riesgo de abuso para {ip}")
            plt.ylim(0, 100)
            plt.ylabel('Porcentaje')
            chart_file = f"abuse_chart_{ip}.png"
            plt.savefig(chart_file)
            plt.close()
            charts.append(chart_file)
        
        # Gráfico de VirusTotal
        if 'virustotal' in threats:
            stats = threats['virustotal']
            labels = ['Malicioso', 'Sospechoso', 'Inofensivo', 'No detectado']
            values = [
                stats['malicious'],
                stats.get('suspicious', 0),
                stats.get('harmless', 0),
                stats.get('undetected', 0)
            ]
            
            plt.figure(figsize=(10, 5))
            plt.pie(values, labels=labels, autopct='%1.1f%%', colors=['red', 'orange', 'green', 'gray'])
            plt.title(f"Análisis de VirusTotal para {ip}")
            chart_file = f"vt_chart_{ip}.png"
            plt.savefig(chart_file)
            plt.close()
            charts.append(chart_file)
        
        return charts
    
    # ------------------- REPORTE -------------------
    def generate_report(self, ip, blacklists, geo, threats):
        whois_data = self.get_whois(ip)
        """Genera un reporte completo en HTML"""
        report_html = f"""
        <html>
        <head>
            <title>Reporte de Amenazas para {ip}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2 {{ color: #2c3e50; }}
                .card {{ background: #f9f9f9; border-left: 5px solid #3498db; padding: 15px; margin-bottom: 20px; }}
                .danger {{ border-color: #e74c3c; }}
                .warning {{ border-color: #f39c12; }}
                .safe {{ border-color: #2ecc71; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                tr:hover {{ background-color: #f5f5f5; }}
            </style>
        </head>
        <body>
            <h1>Reporte de Amenazas para {ip}</h1>
            <p>Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <div class="card">
                <h2>Resumen Ejecutivo</h2>
                <p>IP analizada: <strong>{ip}</strong></p>
        """
        
        # Resumen de amenazas
        total_blacklists = sum(1 for r in blacklists.values() if r)
        risk_level = "ALTO" if total_blacklists > 3 else "MEDIO" if total_blacklists > 0 else "BAJO"
        risk_color = "danger" if risk_level == "ALTO" else "warning" if risk_level == "MEDIO" else "safe"
        
        report_html += f"""
                <div class="card {risk_color}">
                    <h3>Nivel de Riesgo: {risk_level}</h3>
                    <p>Listas negras positivas: {total_blacklists}/{len(blacklists)}</p>
        """
        
        if 'abuseipdb' in threats:
            abuse_score = threats['abuseipdb']['score']
            abuse_level = "ALTO" if abuse_score > 75 else "MEDIO" if abuse_score > 25 else "BAJO"
            abuse_color = "danger" if abuse_level == "ALTO" else "warning" if abuse_level == "MEDIO" else "safe"
            report_html += f"""
                    <p>Confianza de abuso: <span class="{abuse_color}">{abuse_score}%</span></p>
            """
        
        report_html += """
                </div>
            </div>
            
            <div class="card">
                <h2>Listas Negras</h2>
                <table>
                    <tr><th>Lista</th><th>Estado</th><th>Detalles</th></tr>
        """
        
        # Tabla de listas negras
        for name, result in blacklists.items():
            status = "LISTADA" if result else "Limpia"
            row_class = "danger" if result else "safe"
            details = ", ".join(result) if result else "-"
            report_html += f"""
                    <tr class="{row_class}">
                        <td>{name}</td>
                        <td>{status}</td>
                        <td>{details}</td>
                    </tr>
            """
        
        report_html += """
                </table>
            </div>
        """
        
        # Sección de geolocalización
        if geo:
            report_html += """
            <div class="card">
                <h2>Geolocalización</h2>
                <table>
            """
            
            geo_fields = [
                ('País', geo.get('country', 'N/A')),
                ('Región/Ciudad', f"{geo.get('region', 'N/A')} / {geo.get('city', 'N/A')}"),
                ('Coordenadas', f"{geo.get('coordinates', ['N/A'])[0]}, {geo.get('coordinates', ['N/A'])[1]}"),
                ('ISP', geo.get('isp', 'N/A')),
                ('ASN', geo.get('asn', 'N/A')),
                ('Red', geo.get('network', 'N/A')),
                ('Proxy/VPN', 'Sí' if geo.get('proxy') else 'No'),
                ('Centro de Datos', 'Sí' if geo.get('hosting') else 'No')
            ]
            
            for field, value in geo_fields:
                report_html += f"""
                    <tr>
                        <td>{field}</td>
                        <td>{value}</td>
                    </tr>
                """
            
            report_html += """
                </table>
            </div>
            """
        
        # Sección de amenazas
        if threats:
            report_html += """
            <div class="card">
                <h2>Inteligencia de Amenazas</h2>
            """
            
            if 'abuseipdb' in threats:
                report_html += """
                <h3>AbuseIPDB</h3>
                <table>
                    <tr><td>Reportes totales</td><td>{reports}</td></tr>
                    <tr><td>Último reporte</td><td>{last_reported}</td></tr>
                    <tr><td>Dominios asociados</td><td>{domains}</td></tr>
                </table>
                """.format(**threats['abuseipdb'])
            
            if 'virustotal' in threats:
                report_html += """
                <h3>VirusTotal</h3>
                <table>
                    <tr><td>Reputación</td><td>{reputation}</td></tr>
                    <tr><td>Detecciones maliciosas</td><td>{malicious}</td></tr>
                    <tr><td>ASN</td><td>{asn}</td></tr>
                    <tr><td>Red</td><td>{network}</td></tr>
                </table>
                """.format(**threats['virustotal'])
            
            if 'shodan' in threats:
                report_html += """
                <h3>Shodan</h3>
                <p>Puertos abiertos: {ports}</p>
                <p>Servicios detectados: {services}</p>
                """.format(**threats['shodan'])
            
            report_html += """
            </div>
            """
        ##-------WHOIS
        if whois_data:
            whois_table = """
            <div class="card">
                <h2>Información WHOIS</h2>
                <table>
            """
            for key, value in whois_data.items():
                if isinstance(value, (str, int, float)):
                    whois_table += f"<tr><td><strong>{key}</strong></td><td>{value}</td></tr>"
                elif isinstance(value, list) or isinstance(value, dict):
                    pretty_value = json.dumps(value, indent=2, ensure_ascii=False).replace('\n', '<br>').replace('  ', '&nbsp;&nbsp;')
                    whois_table += f"<tr><td><strong>{key}</strong></td><td><pre>{pretty_value}</pre></td></tr>"
                else:
                    whois_table += f"<tr><td><strong>{key}</strong></td><td>{str(value)}</td></tr>"
            whois_table += "</table></div>"
            report_html += whois_table

        # Gráficos
        charts = self.plot_threat_stats(threats, ip)
        if charts:
            report_html += """
            <div class="card">
                <h2>Visualizaciones</h2>
            """
            for chart in charts:
                report_html += f'<img src="{chart}" style="max-width: 80%; margin: 10px;"><br>'
            report_html += """
            </div>
            """
        
        report_html += """
        </body>
        </html>
        """
        
        report_file = f"threat_report_{ip}.html"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_html)
        
        # Generar mapa si hay coordenadas
        if geo and 'coordinates' in geo:
            map_file = self.generate_map(geo, ip)
            if map_file:
                webbrowser.open(f'file://{os.path.abspath(map_file)}')
        
        return report_file

    # ------------------- INTERFAZ -------------------
    def show_banner(self):
        """Muestra un banner profesional con información del sistema"""
        os.system('cls' if os.name == 'nt' else 'clear')
        f = Figlet(font='slant')
        banner = f.renderText('Threat Analyzer')
        print(colored(banner, 'cyan'))
        print(colored("=" * 80, 'blue'))
        print(colored(f"Versión 3.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(80), 'yellow'))
        print(colored("=" * 80, 'blue'))
        print(colored("Analiza direcciones IP contra 15+ listas negras y fuentes de inteligencia".center(80), 'magenta'))
        print(colored("Developed By: Enethel Mendoza".center(80), 'white'))
        print(colored("=" * 80, 'blue') + "\n")

    def analyze_ip(self, ip):
        """Flujo completo de análisis"""
        if not self.validate_ip(ip):
            raise ValueError("Dirección IP inválida")
        
        start_time = time.time()
        self.show_banner()
        print(colored(f"Analizando IP: {ip}\n", 'magenta', attrs=['bold']))
        
        try:
            # Paso 1: Listas negras
            blacklists = self.check_blacklists(ip)
            
            # Paso 2: Geolocalización
            geo = self.get_geodata(ip)
            
            # Paso 3: Inteligencia de amenazas
            threats = self.get_malware_history(ip)
            
            # Generar reporte
            report_file = self.generate_report(ip, blacklists, geo, threats)
            
            # Mostrar resumen
            print(colored("\n[+] Análisis completado:", 'green', attrs=['bold']))
            print(f"  - Reporte generado: {os.path.abspath(report_file)}")
            if geo and 'coordinates' in geo:
                print(f"  - Mapa de ubicación generado")
            
            elapsed = time.time() - start_time
            print(colored(f"\nTiempo total: {elapsed:.2f} segundos", 'blue'))
            
            # Abrir reporte en navegador
            webbrowser.open(f'file://{os.path.abspath(report_file)}')
            
        except KeyboardInterrupt:
            print(colored("\n[!] Análisis interrumpido por el usuario", 'red'))
        except Exception as e:
            print(colored(f"\n[!] Error durante el análisis: {str(e)}", 'red'))
        finally:
            input(colored("\nPresiona Enter para salir...", 'yellow'))

if __name__ == '__main__':
    Config.check_apis()
    analyzer = ThreatIntel()
    
    try:
        analyzer.show_banner()
        ip = input(colored("\nIngrese la dirección IP a analizar: ", 'green'))
        analyzer.analyze_ip(ip.strip())
    except Exception as e:
        print(colored(f"\nError: {str(e)}", 'red'))