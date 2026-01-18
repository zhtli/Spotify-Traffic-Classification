#!/usr/bin/env python3
"""
Spotify Traffic Capture Tool - Con persistencia de IPs
Guarda las IPs detectadas en un archivo para reutilizarlas

Uso: sudo python3 spotify_capture_v2.py -i eth0 -d 60
     sudo python3 spotify_capture_v2.py --scan          # Solo escanear nuevas IPs
     sudo python3 spotify_capture_v2.py --list          # Ver IPs guardadas
     sudo python3 spotify_capture_v2.py --clear         # Limpiar IPs guardadas
"""

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR
from collections import defaultdict
import argparse
import time
import json
import os
from datetime import datetime
from threading import Thread, Event
from pathlib import Path


# Archivo de configuración para IPs persistentes
CONFIG_DIR = Path.home() / '.spotify_capture'
IPS_FILE = CONFIG_DIR / 'known_ips.json'
CAPTURES_DIR = Path('./captures')


class IPDatabase:
    """Gestiona la base de datos de IPs conocidas de Spotify"""
    
    def __init__(self):
        self.config_dir = CONFIG_DIR
        self.ips_file = IPS_FILE
        self.data = {
            'ips': {},  # ip -> {first_seen, last_seen, times_seen, source, domains}
            'domains': {},  # domain -> [ips]
            'stats': {
                'total_scans': 0,
                'last_scan': None
            }
        }
        self._ensure_config_dir()
        self._load()
    
    def _ensure_config_dir(self):
        """Crea el directorio de configuración si no existe"""
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def _load(self):
        """Carga las IPs desde el archivo"""
        if self.ips_file.exists():
            try:
                with open(self.ips_file, 'r') as f:
                    self.data = json.load(f)
                print(f"[*] Cargadas {len(self.data['ips'])} IPs conocidas desde {self.ips_file}")
            except (json.JSONDecodeError, KeyError) as e:
                print(f"[!] Error cargando IPs, iniciando base de datos nueva: {e}")
                self.data = {'ips': {}, 'domains': {}, 'stats': {'total_scans': 0, 'last_scan': None}}
    
    def _save(self):
        """Guarda las IPs al archivo"""
        with open(self.ips_file, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    def add_ip(self, ip: str, source: str = 'traffic', domain: str = None) -> bool:
        """
        Añade una IP a la base de datos
        
        Returns:
            True si es nueva, False si ya existía
        """
        now = datetime.now().isoformat()
        is_new = ip not in self.data['ips']
        
        if is_new:
            self.data['ips'][ip] = {
                'first_seen': now,
                'last_seen': now,
                'times_seen': 1,
                'source': source,
                'domains': [domain] if domain else []
            }
        else:
            self.data['ips'][ip]['last_seen'] = now
            self.data['ips'][ip]['times_seen'] += 1
            if domain and domain not in self.data['ips'][ip]['domains']:
                self.data['ips'][ip]['domains'].append(domain)
        
        # Actualizar mapeo de dominios
        if domain:
            if domain not in self.data['domains']:
                self.data['domains'][domain] = []
            if ip not in self.data['domains'][domain]:
                self.data['domains'][domain].append(ip)
        
        self._save()
        return is_new
    
    def get_all_ips(self) -> set:
        """Retorna todas las IPs conocidas"""
        return set(self.data['ips'].keys())
    
    def get_ip_count(self) -> int:
        """Retorna el número de IPs conocidas"""
        return len(self.data['ips'])
    
    def update_scan_stats(self):
        """Actualiza estadísticas de escaneo"""
        self.data['stats']['total_scans'] += 1
        self.data['stats']['last_scan'] = datetime.now().isoformat()
        self._save()
    
    def clear(self):
        """Limpia todas las IPs"""
        self.data = {'ips': {}, 'domains': {}, 'stats': {'total_scans': 0, 'last_scan': None}}
        self._save()
    
    def remove_ip(self, ip: str) -> bool:
        """Elimina una IP específica"""
        if ip in self.data['ips']:
            del self.data['ips'][ip]
            # Limpiar de dominios
            for domain in self.data['domains']:
                if ip in self.data['domains'][domain]:
                    self.data['domains'][domain].remove(ip)
            self._save()
            return True
        return False
    
    def print_summary(self):
        """Imprime resumen de IPs conocidas"""
        print(f"\n{'='*70}")
        print("BASE DE DATOS DE IPs DE SPOTIFY")
        print(f"{'='*70}")
        print(f"[*] Archivo: {self.ips_file}")
        print(f"[*] Total IPs: {len(self.data['ips'])}")
        print(f"[*] Total dominios: {len(self.data['domains'])}")
        print(f"[*] Escaneos realizados: {self.data['stats']['total_scans']}")
        print(f"[*] Último escaneo: {self.data['stats']['last_scan'] or 'Nunca'}")
        
        if self.data['ips']:
            print(f"\n{'─'*70}")
            print("IPs CONOCIDAS:")
            print(f"{'─'*70}")
            print(f"{'IP':<20} {'Veces vista':<12} {'Fuente':<10} {'Dominios'}")
            print(f"{'─'*70}")
            
            # Ordenar por veces vistas
            sorted_ips = sorted(
                self.data['ips'].items(),
                key=lambda x: x[1]['times_seen'],
                reverse=True
            )
            
            for ip, info in sorted_ips:
                domains = ', '.join(info['domains'][:2]) if info['domains'] else '-'
                if len(info['domains']) > 2:
                    domains += f" (+{len(info['domains'])-2})"
                print(f"{ip:<20} {info['times_seen']:<12} {info['source']:<10} {domains}")
        
        if self.data['domains']:
            print(f"\n{'─'*70}")
            print("DOMINIOS DETECTADOS:")
            print(f"{'─'*70}")
            for domain, ips in sorted(self.data['domains'].items()):
                print(f"  {domain}")
                for ip in ips[:3]:
                    print(f"    └─ {ip}")
                if len(ips) > 3:
                    print(f"    └─ ... (+{len(ips)-3} más)")
        
        print(f"{'='*70}\n")


class SpotifyCaptureV2:
    """Captura tráfico de Spotify con persistencia de IPs"""
    
    SPOTIFY_DOMAINS = [
        'spotify.com', 'scdn.co', 'spotifycdn.com',
        'audio-ak', 'audio4-ak', 'audio-fa',
        'audio-akp', 'spotilocal.com'
    ]
    
    AKAMAI_PREFIXES = [
        '23.', '104.64.', '104.65.', '104.66.', '104.67.',
        '104.68.', '104.69.', '104.70.', '104.71.',
        '184.24.', '184.25.', '184.26.', '184.27.',
        '184.28.', '184.29.', '184.30.', '184.31.',
        '2.16.', '2.17.', '2.18.', '2.19.',
        '2.20.', '2.21.', '2.22.', '2.23.',
        '35.186.', '35.190.', '35.201.',
        '34.107.', '34.117.',
        '151.101.',  # Fastly (también usado por Spotify)
        '199.232.',  # Fastly
    ]
    
    def __init__(self, interface: str, duration: int, output_dir: str, scan_time: int = 30):
        self.interface = interface
        self.duration = duration
        self.output_dir = Path(output_dir)
        self.scan_time = scan_time
        
        self.ip_db = IPDatabase()
        self.session_ips = set()  # IPs detectadas en esta sesión
        self.packets = []
        self.traffic_stats = defaultdict(lambda: {'bytes': 0, 'packets': 0})
        self.capture_start_time = None
        self.stop_event = Event()
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def is_potential_spotify_ip(self, ip: str) -> bool:
        """Verifica si una IP podría ser de Spotify"""
        for prefix in self.AKAMAI_PREFIXES:
            if ip.startswith(prefix):
                return True
        return False
    
    def is_spotify_domain(self, domain: str) -> bool:
        """Verifica si un dominio es de Spotify"""
        domain = domain.lower().rstrip('.')
        return any(sd in domain for sd in self.SPOTIFY_DOMAINS)
    
    def scan_callback(self, pkt):
        """Callback para escaneo de IPs"""
        if self.stop_event.is_set():
            return
        
        # Procesar DNS
        if DNS in pkt and pkt[DNS].qr == 1:
            try:
                if DNSQR in pkt:
                    query = pkt[DNSQR].qname.decode() if isinstance(pkt[DNSQR].qname, bytes) else str(pkt[DNSQR].qname)
                    
                    if self.is_spotify_domain(query):
                        for i in range(pkt[DNS].ancount):
                            try:
                                rr = pkt[DNS].an[i]
                                if rr.type == 1:  # A record
                                    ip = rr.rdata
                                    if isinstance(ip, bytes):
                                        ip = '.'.join(str(b) for b in ip)
                                    ip = str(ip)
                                    
                                    is_new = self.ip_db.add_ip(ip, source='dns', domain=query.rstrip('.'))
                                    self.session_ips.add(ip)
                                    
                                    status = "NUEVA" if is_new else "conocida"
                                    print(f"[DNS] {query} -> {ip} ({status})")
                            except:
                                pass
            except:
                pass
        
        # Analizar tráfico HTTPS
        if IP in pkt and TCP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            pkt_len = len(pkt)
            
            if sport == 443 or dport == 443:
                remote_ip = src_ip if sport == 443 else dst_ip
                
                if self.is_potential_spotify_ip(remote_ip):
                    self.traffic_stats[remote_ip]['bytes'] += pkt_len
                    self.traffic_stats[remote_ip]['packets'] += 1
    
    def analyze_traffic_for_ips(self):
        """Analiza el tráfico capturado para identificar IPs de Spotify"""
        print("\n[*] Analizando tráfico capturado...")
        
        # IPs con mucho tráfico son probablemente Spotify
        candidates = [
            (ip, stats['bytes'], stats['packets'])
            for ip, stats in self.traffic_stats.items()
            if stats['bytes'] > 30000  # Más de 30KB
        ]
        
        candidates.sort(key=lambda x: x[1], reverse=True)
        
        new_count = 0
        for ip, bytes_count, pkt_count in candidates[:15]:
            is_new = self.ip_db.add_ip(ip, source='traffic')
            self.session_ips.add(ip)
            
            if is_new:
                new_count += 1
                print(f"[+] IP NUEVA (tráfico): {ip} ({bytes_count:,} bytes)")
            else:
                print(f"[·] IP conocida: {ip} ({bytes_count:,} bytes)")
        
        return new_count
    
    def scan_for_ips(self):
        """Escanea la red para detectar IPs de Spotify"""
        print(f"\n{'='*70}")
        print("ESCANEO DE IPs DE SPOTIFY")
        print(f"{'='*70}")
        print(f"\n[*] IPs conocidas en base de datos: {self.ip_db.get_ip_count()}")
        print(f"\n[!] INSTRUCCIONES:")
        print(f"    1. Abre Spotify web (open.spotify.com)")
        print(f"    2. Reproduce música")
        print(f"    3. Espera {self.scan_time} segundos...\n")
        
        try:
            sniff(
                iface=self.interface,
                filter="port 53 or port 443",
                prn=self.scan_callback,
                timeout=self.scan_time,
                store=False
            )
        except Exception as e:
            print(f"[!] Error: {e}")
            return 0
        
        new_ips = self.analyze_traffic_for_ips()
        self.ip_db.update_scan_stats()
        
        print(f"\n[*] Resumen del escaneo:")
        print(f"    - IPs nuevas encontradas: {new_ips}")
        print(f"    - IPs en esta sesión: {len(self.session_ips)}")
        print(f"    - Total IPs en base de datos: {self.ip_db.get_ip_count()}")
        
        return new_ips
    
    def capture_callback(self, pkt):
        """Callback para captura de tráfico"""
        if self.stop_event.is_set():
            return
        
        if IP not in pkt:
            return
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        pkt_len = len(pkt)
        timestamp = float(pkt.time)
        
        all_known_ips = self.ip_db.get_all_ips()
        
        is_spotify = False
        spotify_ip = None
        direction = None
        
        if src_ip in all_known_ips:
            is_spotify = True
            spotify_ip = src_ip
            direction = 'in'
        elif dst_ip in all_known_ips:
            is_spotify = True
            spotify_ip = dst_ip
            direction = 'out'
        
        if is_spotify:
            if self.capture_start_time is None:
                self.capture_start_time = timestamp
            
            relative_time = timestamp - self.capture_start_time
            
            self.packets.append({
                'timestamp': timestamp,
                'relative_time': relative_time,
                'src': src_ip,
                'dst': dst_ip,
                'length': pkt_len,
                'protocol': 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'OTHER',
                'direction': direction,
                'spotify_ip': spotify_ip
            })
    
    def print_progress(self):
        """Muestra progreso en tiempo real"""
        while not self.stop_event.is_set():
            if self.packets:
                total_bytes = sum(p['length'] for p in self.packets)
                # Solo contar paquetes grandes (>500 bytes) como audio
                # Los paquetes pequeños son ACKs, metadata, etc.
                audio_packets = [p for p in self.packets if p['direction'] == 'in' and p['length'] > 500]
                audio_bytes = sum(p['length'] for p in audio_packets)
                incoming_bytes = sum(p['length'] for p in self.packets if p['direction'] == 'in')
                duration = self.packets[-1]['relative_time'] if self.packets else 0
                
                # Bitrate basado en bytes de audio
                bitrate = (audio_bytes * 8 / duration / 1000) if duration > 0 else 0
                
                # Rangos ajustados para web player
                # Web player: Normal=128kbps, High=160kbps (según tu screenshot)
                # Pero hay overhead de protocolo (~10-15%), así que:
                # 128kbps real → ~110-145 kbps medido
                # 160kbps real → ~140-180 kbps medido
                # 320kbps real → ~280-350 kbps medido
                if bitrate < 80:
                    quality = "LOW (<96kbps)"
                elif bitrate < 135:
                    quality = "NORMAL (~128kbps)"  
                elif bitrate < 190:
                    quality = "HIGH (~160kbps)"
                elif bitrate < 270:
                    quality = "HIGH+ (~256kbps)"
                else:
                    quality = "VERY HIGH (~320kbps)"
                
                print(f"\r[📊] Pkts: {len(self.packets):,} | "
                      f"Audio: {audio_bytes:,}B | "
                      f"Bitrate: {bitrate:.1f}kbps | "
                      f"Calidad: {quality}      ", end='', flush=True)
            
            time.sleep(0.5)
    
    def run_capture(self):
        """Ejecuta la captura de tráfico"""
        all_ips = self.ip_db.get_all_ips()
        
        if not all_ips:
            print("\n[!] No hay IPs en la base de datos")
            print("[!] Ejecuta primero: sudo python3 spotify_capture_v2.py --scan")
            return None
        
        print(f"\n{'='*70}")
        print("CAPTURA DE TRÁFICO DE SPOTIFY")
        print(f"{'='*70}")
        print(f"\n[*] Usando {len(all_ips)} IPs de la base de datos")
        print(f"[*] Duración: {self.duration} segundos")
        
        # Mostrar algunas IPs
        print(f"\n[*] IPs monitorizadas (primeras 10):")
        for ip in list(all_ips)[:10]:
            print(f"    - {ip}")
        if len(all_ips) > 10:
            print(f"    ... y {len(all_ips) - 10} más")
        
        # Construir filtro BPF
        ip_filter = " or ".join([f"host {ip}" for ip in all_ips])
        bpf_filter = f"({ip_filter})"
        
        print(f"\n[*] Iniciando captura...")
        print(f"[*] Asegúrate de que Spotify está reproduciendo\n")
        
        progress_thread = Thread(target=self.print_progress, daemon=True)
        progress_thread.start()
        
        try:
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self.capture_callback,
                timeout=self.duration,
                store=False
            )
        except KeyboardInterrupt:
            print("\n\n[!] Captura interrumpida")
        finally:
            self.stop_event.set()
        
        return self.save_capture()
    
    def save_capture(self):
        """Guarda la captura en JSON"""
        if not self.packets:
            print("\n[!] No se capturaron paquetes")
            return None
        
        # Calcular estadísticas
        duration = self.packets[-1]['relative_time']
        total_bytes = sum(p['length'] for p in self.packets)
        incoming_bytes = sum(p['length'] for p in self.packets if p['direction'] == 'in')
        
        # Solo paquetes grandes como audio (>500 bytes, excluye ACKs y metadata pequeña)
        audio_packets = [p for p in self.packets if p['direction'] == 'in' and p['length'] > 500]
        audio_bytes = sum(p['length'] for p in audio_packets)
        
        bitrate = (audio_bytes * 8 / duration / 1000) if duration > 0 else 0
        bitrate_raw = (incoming_bytes * 8 / duration / 1000) if duration > 0 else 0
        
        # Clasificar calidad con rangos ajustados
        if bitrate < 80:
            quality = "low"
        elif bitrate < 135:
            quality = "normal"
        elif bitrate < 190:
            quality = "high"
        elif bitrate < 270:
            quality = "high_premium"
        else:
            quality = "very_high"
        
        # IPs únicas en la captura
        capture_ips = set()
        for pkt in self.packets:
            capture_ips.add(pkt['spotify_ip'])
        
        capture_data = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'interface': self.interface,
                'duration_seconds': round(duration, 2),
                'total_packets': len(self.packets),
                'total_bytes': total_bytes,
                'incoming_bytes': incoming_bytes,
                'audio_bytes': audio_bytes,
                'audio_packets': len(audio_packets),
                'estimated_bitrate_kbps': round(bitrate, 2),
                'raw_bitrate_kbps': round(bitrate_raw, 2),
                'estimated_quality': quality,
                'ips_in_capture': list(capture_ips),
                'total_known_ips': self.ip_db.get_ip_count()
            },
            'packets': self.packets
        }
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"spotify_{quality}_{timestamp}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(capture_data, f, indent=2)
        
        print(f"\n\n{'='*70}")
        print("RESUMEN DE CAPTURA")
        print(f"{'='*70}")
        print(f"[+] Duración: {duration:.2f}s")
        print(f"[+] Paquetes totales: {len(self.packets):,}")
        print(f"[+] Paquetes de audio: {len(audio_packets):,}")
        print(f"[+] Bytes de audio: {audio_bytes:,}")
        print(f"[+] Bitrate (audio): {bitrate:.2f} kbps")
        print(f"[+] Bitrate (raw): {bitrate_raw:.2f} kbps")
        print(f"[+] Calidad estimada: {quality.upper()}")
        print(f"[+] IPs activas: {len(capture_ips)}")
        print(f"[+] Archivo: {filepath}")
        print(f"{'='*70}\n")
        
        return str(filepath)


def main():
    parser = argparse.ArgumentParser(
        description='Captura de tráfico Spotify con persistencia de IPs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Primera vez: escanear para detectar IPs
  sudo python3 spotify_capture_v2.py --scan
  
  # Ver IPs guardadas
  python3 spotify_capture_v2.py --list
  
  # Capturar tráfico (usa IPs guardadas)
  sudo python3 spotify_capture_v2.py -i eth0 -d 60
  
  # Escanear + capturar en un solo comando
  sudo python3 spotify_capture_v2.py -i eth0 -d 60 --scan-first
  
  # Limpiar base de datos de IPs
  python3 spotify_capture_v2.py --clear
        """
    )
    
    parser.add_argument('-i', '--interface', default='eth0',
                        help='Interfaz de red (default: eth0)')
    parser.add_argument('-d', '--duration', type=int, default=60,
                        help='Duración de captura (default: 60s)')
    parser.add_argument('-o', '--output', default='./captures',
                        help='Directorio de salida')
    parser.add_argument('-s', '--scan-time', type=int, default=30,
                        help='Tiempo de escaneo de IPs (default: 30s)')
    
    # Modos de operación
    parser.add_argument('--scan', action='store_true',
                        help='Solo escanear nuevas IPs')
    parser.add_argument('--scan-first', action='store_true',
                        help='Escanear IPs antes de capturar')
    parser.add_argument('--list', action='store_true',
                        help='Mostrar IPs guardadas')
    parser.add_argument('--clear', action='store_true',
                        help='Limpiar todas las IPs guardadas')
    parser.add_argument('--remove-ip', type=str,
                        help='Eliminar una IP específica')
    
    args = parser.parse_args()
    
    # Modos que no requieren root
    if args.list:
        db = IPDatabase()
        db.print_summary()
        return
    
    if args.clear:
        db = IPDatabase()
        confirm = input("[?] ¿Eliminar todas las IPs guardadas? [s/N]: ").strip().lower()
        if confirm == 's':
            db.clear()
            print("[+] Base de datos limpiada")
        return
    
    if args.remove_ip:
        db = IPDatabase()
        if db.remove_ip(args.remove_ip):
            print(f"[+] IP {args.remove_ip} eliminada")
        else:
            print(f"[!] IP {args.remove_ip} no encontrada")
        return
    
    # Banner
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║         SPOTIFY TRAFFIC CAPTURE v2                            ║
    ║         Con persistencia de IPs                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    capturer = SpotifyCaptureV2(
        interface=args.interface,
        duration=args.duration,
        output_dir=args.output,
        scan_time=args.scan_time
    )
    
    try:
        if args.scan:
            # Solo escanear
            capturer.scan_for_ips()
        elif args.scan_first:
            # Escanear y luego capturar
            capturer.scan_for_ips()
            print("\n[*] Iniciando captura en 3 segundos...")
            time.sleep(3)
            capturer.run_capture()
        else:
            # Solo capturar (usar IPs existentes)
            if capturer.ip_db.get_ip_count() == 0:
                print("[!] No hay IPs guardadas. Ejecutando escaneo primero...")
                capturer.scan_for_ips()
                if capturer.ip_db.get_ip_count() > 0:
                    print("\n[*] Iniciando captura en 3 segundos...")
                    time.sleep(3)
                    capturer.run_capture()
            else:
                capturer.run_capture()
                
    except PermissionError:
        print("\n[!] ERROR: Necesitas permisos de root")
        print("[!] Ejecuta: sudo python3 spotify_capture_v2.py ...")
    except KeyboardInterrupt:
        print("\n\n[!] Cancelado")


if __name__ == '__main__':
    main()
