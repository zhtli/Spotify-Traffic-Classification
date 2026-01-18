import os
import sys
import time
import argparse
import numpy as np
import pandas as pd
from scapy.all import sniff, wrpcap, rdpcap, IP
import pickle
from datetime import datetime
from collections import deque

# ============================================================================
# CONFIGURACIÓN
# ============================================================================
MODEL_PATH = "best_model.pkl"
WINDOW_SECONDS = 3.0
BURST_THRESHOLD = 0.03
MIN_PACKETS = 15

# ============================================================================
# CARGAR MODELO
# ============================================================================

def load_model():
    """Carga el modelo entrenado"""
    if not os.path.exists(MODEL_PATH):
        print(f"❌ No se encontró el modelo: {MODEL_PATH}")
        print("   Ejecuta primero train_model.py para entrenar el modelo")
        sys.exit(1)
    
    with open(MODEL_PATH, "rb") as f:
        data = pickle.load(f)
    
    print(f"✅ Modelo cargado: {MODEL_PATH}")
    return data["model"], data["scaler"], data["label_encoder"], data["features"]


# ============================================================================
# EXTRACCIÓN DE FEATURES
# ============================================================================

def extract_features(times, sizes):
    """Extrae features de un conjunto de paquetes"""
    if len(times) < MIN_PACKETS:
        return None
    
    duration = times[-1] - times[0]
    if duration <= 0:
        return None
    
    iat = np.diff(times)
    
    # Bursts
    bursts = []
    current = 0
    for t in iat:
        if t < BURST_THRESHOLD:
            current += 1
        else:
            if current > 0:
                bursts.append(current)
            current = 0
    if current > 0:
        bursts.append(current)
    
    bytes_total = sizes.sum()
    mean_pkt = sizes.mean()
    
    # Entropía
    size_counts = np.bincount(sizes.astype(int).clip(0, 1500))
    size_probs = size_counts[size_counts > 0] / size_counts.sum()
    entropy = -np.sum(size_probs * np.log2(size_probs + 1e-10))
    
    features = {
        "bytes_per_second": bytes_total / duration,
        "packets_per_second": len(sizes) / duration,
        "bytes_total": bytes_total,
        "mean_pkt_size": mean_pkt,
        "std_pkt_size": sizes.std(),
        "min_pkt_size": sizes.min(),
        "max_pkt_size": sizes.max(),
        "p10_pkt_size": np.percentile(sizes, 10),
        "p25_pkt_size": np.percentile(sizes, 25),
        "p50_pkt_size": np.percentile(sizes, 50),
        "p75_pkt_size": np.percentile(sizes, 75),
        "p90_pkt_size": np.percentile(sizes, 90),
        "p95_pkt_size": np.percentile(sizes, 95),
        "large_pkt_ratio": (sizes > 1000).sum() / len(sizes),
        "small_pkt_ratio": (sizes < 100).sum() / len(sizes),
        "medium_pkt_ratio": ((sizes >= 100) & (sizes <= 1000)).sum() / len(sizes),
        "pkt_size_range": sizes.max() - sizes.min(),
        "pkt_size_iqr": np.percentile(sizes, 75) - np.percentile(sizes, 25),
        "pkt_size_skew": pd.Series(sizes).skew() if len(sizes) > 2 else 0,
        "pkt_size_kurtosis": pd.Series(sizes).kurtosis() if len(sizes) > 3 else 0,
        "mean_iat": iat.mean() if len(iat) > 0 else 0,
        "std_iat": iat.std() if len(iat) > 0 else 0,
        "min_iat": iat.min() if len(iat) > 0 else 0,
        "max_iat": iat.max() if len(iat) > 0 else 0,
        "p10_iat": np.percentile(iat, 10) if len(iat) > 0 else 0,
        "p50_iat": np.percentile(iat, 50) if len(iat) > 0 else 0,
        "p90_iat": np.percentile(iat, 90) if len(iat) > 0 else 0,
        "cv_iat": (iat.std() / iat.mean()) if len(iat) > 0 and iat.mean() > 0 else 0,
        "iat_range": (iat.max() - iat.min()) if len(iat) > 0 else 0,
        "burst_count": len(bursts),
        "mean_burst_packets": np.mean(bursts) if bursts else 0,
        "max_burst_packets": max(bursts) if bursts else 0,
        "std_burst_packets": np.std(bursts) if len(bursts) > 1 else 0,
        "burst_bytes_ratio": (np.mean(bursts) * len(bursts) * mean_pkt) / bytes_total if bytes_total > 0 and bursts else 0,
        "entropy_pkt_sizes": entropy,
        "bytes_per_packet": bytes_total / len(sizes),
        "iat_per_byte": (iat.sum() / bytes_total) if bytes_total > 0 and len(iat) > 0 else 0,
    }
    
    return features


def analyze_packets(packets, model, scaler, le, feature_names):
    """Analiza paquetes y predice calidad"""
    # Filtrar paquetes IP
    filtered = [(float(pkt.time), len(pkt)) for pkt in packets if pkt.haslayer(IP) and len(pkt) > 60]
    
    if len(filtered) < MIN_PACKETS:
        return None, None, 0
    
    times = np.array([t for t, s in filtered])
    sizes = np.array([s for t, s in filtered])
    
    # Extraer features
    features = extract_features(times, sizes)
    if features is None:
        return None, None, 0
    
    # Crear DataFrame con las features en el orden correcto
    X = pd.DataFrame([features])[feature_names]
    
    # Escalar y predecir
    X_scaled = scaler.transform(X)
    pred = model.predict(X_scaled)[0]
    proba = model.predict_proba(X_scaled)[0]
    
    quality = le.inverse_transform([pred])[0]
    confidence = proba[pred] * 100
    
    return quality, proba, len(filtered)


# ============================================================================
# MODO OFFLINE - ANALIZAR PCAP
# ============================================================================

def analyze_pcap(pcap_path, model, scaler, le, feature_names):
    """Analiza un archivo PCAP offline"""
    print(f"\n📂 Analizando: {pcap_path}")
    
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"❌ Error leyendo PCAP: {e}")
        return
    
    print(f"   Paquetes totales: {len(packets)}")
    
    # Analizar por ventanas
    filtered = [(float(pkt.time), len(pkt)) for pkt in packets if pkt.haslayer(IP) and len(pkt) > 60]
    
    if len(filtered) < MIN_PACKETS:
        print(f"   ❌ Insuficientes paquetes IP ({len(filtered)})")
        return
    
    times = np.array([t for t, s in filtered])
    sizes = np.array([s for t, s in filtered])
    
    print(f"   Paquetes IP válidos: {len(filtered)}")
    print(f"   Duración: {times[-1] - times[0]:.1f}s")
    
    # Analizar todo el PCAP
    print("\n" + "=" * 50)
    print("ANÁLISIS GLOBAL")
    print("=" * 50)
    
    quality, proba, n_pkts = analyze_packets(packets, model, scaler, le, feature_names)
    
    if quality:
        print(f"\n   🎵 Calidad predicha: {quality.upper()}")
        print(f"   📊 Confianza: {proba[np.argmax(proba)] * 100:.1f}%")
        print(f"\n   Probabilidades:")
        for i, cls in enumerate(le.classes_):
            bar = "█" * int(proba[i] * 30)
            print(f"      {cls:12} {proba[i]*100:5.1f}% {bar}")
    
    # Analizar por ventanas de tiempo
    print("\n" + "=" * 50)
    print("ANÁLISIS POR VENTANAS")
    print("=" * 50)
    
    start = times[0]
    end = times[-1]
    current = start
    window_results = []
    
    while current + WINDOW_SECONDS <= end:
        w_mask = (times >= current) & (times < current + WINDOW_SECONDS)
        w_times = times[w_mask]
        w_sizes = sizes[w_mask]
        
        if len(w_times) >= MIN_PACKETS:
            features = extract_features(w_times, w_sizes)
            if features:
                X = pd.DataFrame([features])[feature_names]
                X_scaled = scaler.transform(X)
                pred = model.predict(X_scaled)[0]
                proba = model.predict_proba(X_scaled)[0]
                quality = le.inverse_transform([pred])[0]
                conf = proba[pred] * 100
                
                t_start = current - start
                t_end = t_start + WINDOW_SECONDS
                window_results.append({
                    'start': t_start,
                    'end': t_end,
                    'quality': quality,
                    'confidence': conf,
                    'packets': len(w_times)
                })
        
        current += WINDOW_SECONDS
    
    # Mostrar resultados por ventana
    print(f"\n   Ventanas analizadas: {len(window_results)}\n")
    
    for w in window_results:
        conf_bar = "█" * int(w['confidence'] / 5)
        print(f"   [{w['start']:5.1f}s - {w['end']:5.1f}s] {w['quality']:10} ({w['confidence']:4.1f}%) {conf_bar}")
    
    # Resumen
    if window_results:
        quality_counts = {}
        for w in window_results:
            q = w['quality']
            quality_counts[q] = quality_counts.get(q, 0) + 1
        
        print("\n" + "=" * 50)
        print("RESUMEN")
        print("=" * 50)
        print(f"\n   Predicciones por ventana:")
        for q, count in sorted(quality_counts.items(), key=lambda x: -x[1]):
            pct = count / len(window_results) * 100
            print(f"      {q:12}: {count:3} ventanas ({pct:.1f}%)")
        
        # Predicción final (mayoría)
        final_quality = max(quality_counts, key=quality_counts.get)
        print(f"\n   🎵 PREDICCIÓN FINAL: {final_quality.upper()}")


# ============================================================================
# MODO CAPTURA EN VIVO
# ============================================================================

def live_capture(interface, duration, model, scaler, le, feature_names):
    """Captura tráfico en vivo y analiza"""
    print(f"\n📡 Capturando en {interface} por {duration}s...")
    print("   (Reproduce algo en Spotify)")
    
    try:
        packets = sniff(iface=interface, timeout=duration, store=True)
    except PermissionError:
        print("❌ Permiso denegado. Ejecuta como administrador/sudo")
        return
    except Exception as e:
        print(f"❌ Error: {e}")
        return
    
    print(f"\n✅ Capturados {len(packets)} paquetes")
    
    # Guardar PCAP temporal
    temp_pcap = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    wrpcap(temp_pcap, packets)
    print(f"   Guardado en: {temp_pcap}")
    
    # Analizar
    analyze_pcap(temp_pcap, model, scaler, le, feature_names)


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Analizador de calidad de streaming Spotify",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python analyzer.py --pcap captura.pcap          # Analizar PCAP offline
  python analyzer.py --live -i eth0 -d 60         # Captura en vivo 60s
  python analyzer.py --dir ./pcaps                # Analizar directorio
        """
    )
    
    parser.add_argument("--pcap", "-p", help="Archivo PCAP a analizar")
    parser.add_argument("--dir", "-D", help="Directorio con PCAPs a analizar")
    parser.add_argument("--live", "-l", action="store_true", help="Modo captura en vivo")
    parser.add_argument("--interface", "-i", default="eth0", help="Interfaz de red (default: eth0)")
    parser.add_argument("--duration", "-d", type=int, default=30, help="Duración captura en segundos (default: 30)")
    
    args = parser.parse_args()
    
    # Banner
    print("=" * 50)
    print("🎵 SPOTIFY QUALITY ANALYZER")
    print("=" * 50)
    
    # Cargar modelo
    model, scaler, le, feature_names = load_model()
    print(f"   Clases: {list(le.classes_)}")
    
    # Ejecutar según modo
    if args.pcap:
        analyze_pcap(args.pcap, model, scaler, le, feature_names)
    
    elif args.dir:
        pcap_files = [f for f in os.listdir(args.dir) if f.endswith(".pcap")]
        print(f"\nEncontrados {len(pcap_files)} archivos PCAP")
        
        for f in pcap_files:
            analyze_pcap(os.path.join(args.dir, f), model, scaler, le, feature_names)
            print("\n" + "-" * 50)
    
    elif args.live:
        live_capture(args.interface, args.duration, model, scaler, le, feature_names)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
