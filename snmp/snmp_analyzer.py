"""
Analyseur de trames SNMP avancé avec intégration base de données
Développé par Louis - Étudiant 1
"""
import os 
import argparse            # Analyse des arguments en ligne de commande
import sys                 # Fonctions système (ex: exit, arguments, stdout)
import logging             # Journalisation des erreurs et informations
from collections import defaultdict  # Dictionnaire avec valeur par défaut, utile pour stats/anomalies
from datetime import datetime, timedelta  # Gestion des dates et durées
from typing import Optional, Dict, List, Any  # Annotations de type pour meilleure lisibilité/IDE
from dotenv import load_dotenv  # Chargement des variables d'environnement depuis fichier .env

import threading           # Gestion de threads (ex: nettoyage cache asynchrone)
import time                # Gestion de temporisations et délais

import json                # Sérialisation/désérialisation JSON (ex: logs ou config)
from dataclasses import dataclass, asdict  # Simplifie la définition de classes de données

import statistics          # Calculs statistiques (moyennes, médianes, etc.)

import sqlite3             # Module SQLite pour base locale fichier .db

# Import réseau et SNMP - capture et parsing paquet
from scapy.all import sniff, SNMP, IP, UDP, Packet  
from scapy.layers.snmp import *  # Protocol SNMP spécifique à scapy

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('snmp_analyzer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)
load_dotenv()

@dataclass
class SNMPPacketInfo:
    """Classe pour stocker les informations d'un paquet SNMP"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    version: str
    community_or_user: str
    request_type: str
    oids: List[Dict[str, Any]]
    enterprise_oid: Optional[str] = None
    packet_size: int = 0
    response_time: Optional[float] = None
    error_status: Optional[str] = None

logger = logging.getLogger(__name__)

import os
import sqlite3
from typing import Optional, Dict
import logging

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Gestionnaire SQLite avec création/nettoyage base locale (fichier .db)"""
    RETENTION_DAYS = 30
    def __init__(self, db_path: str = "snmp_local.db"):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.db_path = os.path.join(base_dir, db_path)
        self.conn = None
        self.init_database()

    def init_database(self):
        new_db = not os.path.exists(self.db_path)
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row

            # Sécuriser accès fichier sqlite
            os.chmod(self.db_path, 0o600)

            # pragmas  pour sécurité et intégrité
            self.conn.execute("PRAGMA foreign_keys=ON;")
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")

            if new_db:
                logger.info(f"Création d'une nouvelle base SQLite {self.db_path}")
                self._create_or_reset_tables()
            else:
                logger.info(f"Connexion à la base SQLite existante {self.db_path}")

            # ⚠️ Nettoyage automatique des données de plus de 30 jours
            self._cleanup_old_records()

        except Exception as e:
            logger.error(f"Erreur initialisation SQLite : {e}")
            raise

    def _cleanup_old_records(self):
            """Supprime les enregistrements de plus de RETENTION_DAYS jours"""
            try:
                cur = self.conn.cursor()
                cur.executescript(f"""
                    DELETE FROM snmp_metrics
                    WHERE ts < datetime('now', '-{self.RETENTION_DAYS} days');

                    DELETE FROM snmp_traps
                    WHERE ts < datetime('now', '-{self.RETENTION_DAYS} days');

                    DELETE FROM snmp_anomalies
                    WHERE ts < datetime('now', '-{self.RETENTION_DAYS} days');
                """)
                self.conn.commit()
                logger.info(f"Nettoyage des données > {self.RETENTION_DAYS} jours effectué.")
            except Exception as e:
                logger.error(f"Erreur lors du nettoyage des anciennes données : {e}")
                self.conn.rollback()

    def _create_or_reset_tables(self):
        schema_sql = """
        CREATE TABLE IF NOT EXISTS snmp_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            device_id INTEGER,
            oid TEXT NOT NULL,
            value_raw TEXT,
            value_num REAL,
            latency_ms INTEGER,
            FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS snmp_traps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            device_id INTEGER,
            version TEXT,
            community_or_user TEXT,
            enterprise_oid TEXT,
            severity TEXT,
            varbinds TEXT,
            FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS snmp_anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            description TEXT,
            severity TEXT,
            type TEXT
        );

        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip_address TEXT NOT NULL UNIQUE,
            location TEXT,
            tags TEXT,
            enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cur = self.conn.cursor()
        cur.executescript(schema_sql)
        self.conn.commit()
        logger.info("Tables SNMP SQLite créées ou vérifiées.")


    def insert_metric(self, packet_info, device_id: Optional[int] = None):
        cur = self.conn.cursor()
        if not packet_info.oids:
            logger.warning("No OIDs found in packet_info, skipping insertion.")
            return

        for oid_info in packet_info.oids:
            oid = oid_info.get("oid")
            val = oid_info.get("value")

            # 🔹 Décoder les bytes proprement
            if isinstance(val, (bytes, bytearray)):
                try:
                    val_str = val.decode("utf-8", errors="ignore")
                except Exception:
                    val_str = str(val)
            else:
                val_str = str(val)

            val_num = self._extract_numeric_value(val_str)
            latency_ms = (
                int(packet_info.response_time * 1000)
                if packet_info.response_time
                else None
            )

            logger.debug(
                f"Inserting metric: source_ip={packet_info.source_ip}, "
                f"device_id={device_id}, oid={oid}, value_raw={val_str}, value_num={val_num}"
            )

            try:
                cur.execute(
                    """
                    INSERT INTO snmp_metrics
                        (ts, source_ip, device_id, oid, value_raw, value_num, latency_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        packet_info.timestamp,
                        packet_info.source_ip,
                        device_id,
                        oid,
                        val_str,   # ⬅️ on stocke la version texte
                        val_num,
                        latency_ms,
                    ),
                )
            except Exception as e:
                logger.error(f"Erreur insertion métrique SQLite : {e}")

        self.conn.commit()




    def insert_trap(self, packet_info, device_id: Optional[int] = None):
        cur = self.conn.cursor()
        try:
            varbinds_str = ";".join([f"{o.get('oid')}:{o.get('value')}" for o in packet_info.oids])
            cur.execute(
                """
                INSERT INTO snmp_traps
                    (ts, source_ip, device_id, version, community_or_user,
                     enterprise_oid, severity, varbinds)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    packet_info.timestamp,
                    packet_info.source_ip,
                    device_id,
                    packet_info.version,
                    packet_info.community_or_user,
                    packet_info.enterprise_oid,
                    "info",
                    varbinds_str
                ),
            )
            self.conn.commit()
        except Exception as e:
            logger.error(f"Erreur insertion trap SQLite : {e}")
            self.conn.rollback()


    def insert_anomaly(self, source_ip: str, description: str, severity: str = "warning", type_: str = "generic"):
        cur = self.conn.cursor()
        try:
            cur.execute("""
                INSERT INTO snmp_anomalies (ts, source_ip, description, severity, type)
                VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?)
            """, (source_ip, description, severity, type_))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Erreur insertion anomalie SQLite : {e}")
            self.conn.rollback()

    def get_device_by_ip(self, ip_address: str) -> Optional[Dict]:
        cur = self.conn.cursor()
        try:
            cur.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_address,))
            row = cur.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Erreur recherche device SQLite : {e}")
            return None

    @staticmethod
    def _extract_numeric_value(value) -> Optional[float]:
        if value is None:
            return None
        try:
            return float(value)
        except Exception:
            return None

    def close(self):
        if self.conn:
            self.conn.close()


class SNMPAnalyzer:
    """Analyseur principal de trames SNMP avec intégration automatique en base locale"""

    def __init__(self, interface: str = None, db_manager: DatabaseManager = None):
        self.interface = interface
        self.db_manager = db_manager
        
        self.stats = {
            "total_packets": 0,
            "get_requests": 0,
            "set_requests": 0,
            "get_responses": 0,
            "traps": 0,
            "errors": 0,
            "unique_sources": set(),
            "unique_destinations": set(),
            "start_time": datetime.now()
        }

        self.request_cache = {}
        self.cleanup_thread = threading.Thread(target=self._cleanup_cache, daemon=True)
        self.cleanup_thread.start()


        self.anomaly_detector = AnomalyDetector(db_manager)

    def start_capture(self, count: int = 0, duration: int = 0, save_to_db: bool = True):
        """Démarre la capture SNMP avec enregistrement automatique en base"""
        logger.info(f"Démarrage de la capture SNMP - Count: {count}, Duration: {duration}s")

        def process_packet(packet):
            try:
                packet_info = self._parse_snmp_packet(packet)
                if packet_info:
                    self._handle_packet(packet_info, save_to_db)
                    self._update_stats(packet_info)
                    if self.anomaly_detector:
                        anomaly = self.anomaly_detector.analyze_packet(packet_info)
                        if anomaly:
                            logger.warning(f"Anomalie détectée: {anomaly}")
            except Exception as e:
                logger.error(f"Erreur dans le traitement du paquet: {e}")

        snmp_filter = "udp port 161 or udp port 162"

        try:
            if duration > 0:
                timer = threading.Timer(
                    duration,
                    lambda: logger.info("Capture arrêtée après le délai spécifié")
                )
                timer.start()

            sniff(
                filter=snmp_filter,
                prn=process_packet,
                count=count,
                iface=self.interface,
                store=0
            )
        except KeyboardInterrupt:
            logger.info("Capture interrompue par l'utilisateur.")
        except Exception as e:
            logger.error(f"Erreur durant la capture: {e}")
        finally:
            self._print_final_stats()

    def _parse_snmp_packet(self, packet: Packet) -> Optional[SNMPPacketInfo]:
        try:
            if not packet.haslayer(SNMP):
                return None
            ip_layer = packet[IP]
            udp_layer = packet[UDP]
            snmp_layer = packet[SNMP]

            version = getattr(snmp_layer, "version", "unknown")
            try:
                version_value = int(getattr(version, "val", version))
            except Exception:
                version_value = 1
            version_map = {0: "v1", 1: "v2c", 3: "v3"}
            version_str = version_map.get(version_value, f"unknown({version_value})")

            community_or_user = ""
            if hasattr(snmp_layer, "community"):
                try:
                    community_or_user = snmp_layer.community.decode("utf-8", errors="ignore")
                except Exception:
                    community_or_user = str(snmp_layer.community)
            elif version_value == 3 and hasattr(snmp_layer, "msgUserName"):
                community_or_user = str(snmp_layer.msgUserName)

            request_type, oids, enterprise_oid, error_status = self._parse_pdu(snmp_layer)

            return SNMPPacketInfo(
                timestamp=datetime.now(),
                source_ip=str(ip_layer.src),
                dest_ip=str(ip_layer.dst),
                source_port=udp_layer.sport,
                dest_port=udp_layer.dport,
                version=version_str,
                community_or_user=community_or_user,
                request_type=request_type,
                oids=oids,
                enterprise_oid=enterprise_oid,
                packet_size=len(packet),
                error_status=error_status
            )
        except Exception as e:
            logger.error(f"Erreur parsing SNMP: {e}")
            return None

    def _parse_pdu(self, snmp_layer):
        """Analyse le PDU SNMP"""
        request_type = "unknown"
        oids, enterprise_oid, error_status = [], None, None

        if not hasattr(snmp_layer, "PDU") or not snmp_layer.PDU:
            return request_type, oids, enterprise_oid, error_status

        pdu = snmp_layer.PDU
        pdu_type = pdu.__class__.__name__
        mapping = {
            "SNMPget": "GET",
            "SNMPset": "SET",
            "SNMPresponse": "RESPONSE",
            "SNMPnext": "GETNEXT",
            "SNMPbulk": "GETBULK",
            "SNMPtrapv1": "TRAPv1",
            "SNMPtrapv2": "TRAPv2"
        }
        request_type = mapping.get(pdu_type, pdu_type)

        if request_type == "TRAPv1" and hasattr(pdu, "enterprise"):
            enterprise_oid = str(pdu.enterprise)

        if hasattr(pdu, "error_status"):
            error_status = str(pdu.error_status)

        if hasattr(pdu, "varbindlist") and pdu.varbindlist:
            for vb in pdu.varbindlist:
                oid_obj = getattr(vb, "oid", None)
                val_obj = getattr(vb, "value", None)

                # OID lisible
                oid_str = str(getattr(oid_obj, "val", oid_obj))

                # 🔹 On NE convertit PAS en str ici
                # On essaie de prendre .val si présent
                if hasattr(val_obj, "val"):
                    real_val = val_obj.val
                else:
                    real_val = val_obj

                oids.append({"oid": oid_str, "value": real_val})

        return request_type, oids, enterprise_oid, error_status



    def _make_key(self, ip1, ip2):
        return (str(ip1), str(ip2))

    def _handle_packet(self, packet_info: SNMPPacketInfo, save_to_db: bool):
        """Traite le paquet SNMP et l’enregistre si demandé"""
        self._print_packet_info(packet_info)
        if not save_to_db or not self.db_manager:
            return

        device = self.db_manager.get_device_by_ip(packet_info.source_ip)
        device_id = device["id"] if device else None

        if packet_info.request_type == "RESPONSE":
            req_key = self._make_key(packet_info.dest_ip, packet_info.source_ip)
            if req_key in self.request_cache:
                req_time = self.request_cache[req_key]
                packet_info.response_time = (packet_info.timestamp - req_time).total_seconds()
                del self.request_cache[req_key]
        elif packet_info.request_type in ["GET", "SET", "GETNEXT", "GETBULK"]:
            self.request_cache[self._make_key(packet_info.source_ip, packet_info.dest_ip)] = packet_info.timestamp

        try:
            if "TRAP" in packet_info.request_type:
                # On stocke les traps dans la table snmp_traps
                self.db_manager.insert_trap(packet_info, device_id)

            elif packet_info.request_type == "RESPONSE":
                # On NE stocke que les réponses, car ce sont elles qui ont les valeurs
                self.db_manager.insert_metric(packet_info, device_id)

            else:
                # GET / GETNEXT / SET : on ne les stocke pas en métriques
                pass
        except Exception as e:
            logger.error(f"Erreur d’écriture en base : {e}")


    def _print_packet_info(self, packet_info: SNMPPacketInfo):
        print(f"\n{'='*60}")
        print(f"[{packet_info.timestamp.strftime('%H:%M:%S.%f')[:-3]}] SNMP {packet_info.request_type}")
        print(f"{packet_info.source_ip}:{packet_info.source_port} → {packet_info.dest_ip}:{packet_info.dest_port}")
        print(f"Version: {packet_info.version} | Community/User: {packet_info.community_or_user}")
        if packet_info.response_time:
            print(f"Temps de réponse: {packet_info.response_time*1000:.1f}ms")
        if packet_info.error_status:
            print(f"Erreur: {packet_info.error_status}")
        if packet_info.oids:
            print("OIDs:")
            for oid_info in packet_info.oids[:5]:
                print(f"  {oid_info['oid']} = {oid_info['value']}")
        print(f"Taille: {packet_info.packet_size} bytes")

    def _update_stats(self, packet_info: SNMPPacketInfo):
        stats = self.stats
        stats["total_packets"] += 1
        stats["unique_sources"].add(packet_info.source_ip)
        stats["unique_destinations"].add(packet_info.dest_ip)
        typ = packet_info.request_type
        if typ == "GET":
            stats["get_requests"] += 1
        elif typ == "SET":
            stats["set_requests"] += 1
        elif typ == "RESPONSE":
            stats["get_responses"] += 1
        elif "TRAP" in typ:
            stats["traps"] += 1
        if packet_info.error_status:
            stats["errors"] += 1
        if stats["total_packets"] % 10 == 0:
            self._print_live_stats()

    def _print_live_stats(self):
        uptime = datetime.now() - self.stats["start_time"]
        rate = self.stats["total_packets"] / uptime.total_seconds() if uptime.total_seconds() > 0 else 0
        print(f"\n--- Statistiques ({uptime}) ---")
        print(f"Total: {self.stats['total_packets']} ({rate:.1f} pkt/s)")
        print(f"GET: {self.stats['get_requests']} | SET: {self.stats['set_requests']} | "
              f"Réponses: {self.stats['get_responses']} | TRAPs: {self.stats['traps']} | "
              f"Erreurs: {self.stats['errors']}")

    def _print_final_stats(self):
        print(f"\n{'='*60}")
        print("STATISTIQUES FINALES")
        print(f"{'='*60}")
        self._print_live_stats()
        print(f"Sources uniques: {len(self.stats['unique_sources'])}, "
              f"Destinations uniques: {len(self.stats['unique_destinations'])}")

    def _cleanup_cache(self):
        """Nettoyage des requêtes expirées"""
        while True:
            time.sleep(60)
            cutoff = datetime.now() - timedelta(seconds=30)
            self.request_cache = {k: v for k, v in self.request_cache.items() if v > cutoff}

class AnomalyDetector:
    """Détecteur d'anomalies SNMP simple"""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.request_counts = defaultdict(int)
        self.last_reset = datetime.now()

    def analyze_packet(self, packet_info: SNMPPacketInfo) -> Optional[str]:
        """Analyse un paquet pour détecter des anomalies"""

        anomalies = []

        # Reset des compteurs toutes les minutes
        if datetime.now() - self.last_reset > timedelta(minutes=1):
            self.request_counts.clear()
            self.last_reset = datetime.now()

        # Détection de flood : plus de 100 requêtes par minute depuis une source
        source_key = str(packet_info.source_ip)
        self.request_counts[source_key] += 1

        if self.request_counts[source_key] > 100:
            anomalies.append(f"Flood potentiel depuis {source_key}")

        # Detection community string par défaut trop simple
        if packet_info.community_or_user.lower() in ['public', 'private', 'community']:
            anomalies.append("Community string par défaut détectée")

        # Trap potentiellement suspect (exclut localhost)
        if 'TRAP' in packet_info.request_type and packet_info.source_ip not in ['127.0.0.1', '::1']:
            anomalies.append("Trap depuis source externe")

        if anomalies:
            # Optionnel : tu peux ici enregistrer en base les anomalies détectées via self.db_manager
            return " | ".join(anomalies)
        else:
            return None

def main():

    logger = logging.getLogger(__name__)

    load_dotenv()

    parser = argparse.ArgumentParser(description="Analyseur de trames SNMP")
    parser.add_argument('-i', '--interface', help="Interface réseau à monitorer")
    parser.add_argument('-c', '--count', type=int, default=0, help="Nombre de paquets à capturer (0=illimité)")
    parser.add_argument('-d', '--duration', type=int, default=0, help="Durée en secondes (0=illimité)")
    parser.add_argument('--no-db', action='store_true', help="Ne pas sauvegarder en base")
    parser.add_argument('--db-path', default="snmp_local.db", help="Chemin vers le fichier SQLite")

    args = parser.parse_args()

    try:
        db_manager = None
        if not args.no_db:
            db_manager = DatabaseManager(db_path=args.db_path)

        analyzer = SNMPAnalyzer(
            interface=args.interface,
            db_manager=db_manager
        )

        analyzer.start_capture(
            count=args.count,
            duration=args.duration,
            save_to_db=not args.no_db
        )

    except Exception as e:
        logger.error(f"Erreur fatale: {e}")
        sys.exit(1)
    finally:
        if db_manager:
            db_manager.close()

if __name__ == "__main__":
    main()
