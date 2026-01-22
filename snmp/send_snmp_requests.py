#!/usr/bin/env python3
# snmp/snmp_sender.py
"""
Générateur et envoyeur de requêtes SNMP pour tests
Développé par Louis - Étudiant 1
"""
import os
from dotenv import load_dotenv
import argparse
import sys
import time
import logging
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import concurrent.futures
import re
import threading
import ipaddress
import json
from scapy.all import *
from scapy.layers.snmp import *

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SNMPSender:
    """Générateur et envoyeur de requêtes SNMP"""
    
    # OIDs couramment utilisés
    COMMON_OIDS = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysUpTime': '1.3.6.1.2.1.1.3.0',
        'sysContact': '1.3.6.1.2.1.1.4.0',
        'sysName': '1.3.6.1.2.1.1.5.0',
        'sysLocation': '1.3.6.1.2.1.1.6.0',
        'ifNumber': '1.3.6.1.2.1.2.1.0',
        'ifDescr': '1.3.6.1.2.1.2.2.1.2',
        'ifType': '1.3.6.1.2.1.2.2.1.3',
        'ifMtu': '1.3.6.1.2.1.2.2.1.4',
        'ifSpeed': '1.3.6.1.2.1.2.2.1.5',
        'ifOperStatus': '1.3.6.1.2.1.2.2.1.8',
        'ipAddrTable': '1.3.6.1.2.1.4.20',
        'hrSystemUptime': '1.3.6.1.2.1.25.1.1.0',
        'hrSystemDate': '1.3.6.1.2.1.25.1.2.0',
        'hrProcessorLoad': '1.3.6.1.2.1.25.3.3.1.2',
        'hrStorageUsed': '1.3.6.1.2.1.25.2.3.1.6',
        'hrStorageSize': '1.3.6.1.2.1.25.2.3.1.5'
    }
    
    PRESET_OIDS = {
        "sysinfo": [
            COMMON_OIDS['sysDescr'],
            COMMON_OIDS['sysUpTime'],
            COMMON_OIDS['sysContact'],
            COMMON_OIDS['sysName'],
            COMMON_OIDS['sysLocation'],
        ],
        "interfaces": [
            COMMON_OIDS['ifNumber'],
            COMMON_OIDS['ifDescr'],
            COMMON_OIDS['ifSpeed'],
            COMMON_OIDS['ifOperStatus'],
        ],
        "host_resources": [
            COMMON_OIDS['hrSystemUptime'],
            COMMON_OIDS['hrSystemDate'],
            COMMON_OIDS['hrProcessorLoad'],
        ],
    }
    
    def __init__(self, db_config: Optional[Dict] = None):
        self.db_config = db_config
        self.results = []
        self.stats = {
            'sent': 0,
            'received': 0,
            'timeout': 0,
            'errors': 0
        }
    
    def resolve_oids(self, oids: Optional[List[str]] = None,
                     preset: Optional[str] = None) -> List[str]:
        """
        Résout une liste d'OID en combinant :
        - noms connus (sysDescr, sysName, etc.)
        - OIDs bruts "1.3.6..."
        - presets prédéfinis (sysinfo, interfaces, ...)
        """
        resolved: List[str] = []

        # Preset éventuel
        if preset:
            preset = preset.lower()
            if preset in self.PRESET_OIDS:
                resolved.extend(self.PRESET_OIDS[preset])
            else:
                logger.warning(f"Preset inconnu: {preset}")

        # OIDs passés directement
        if oids:
            for oid in oids:
                if oid in self.COMMON_OIDS:
                    resolved.append(self.COMMON_OIDS[oid])
                else:
                    resolved.append(oid)

        # Évite les doublons
        return list(dict.fromkeys(resolved))

    
    def send_get_request(self, target_ip: str, oids: List[str], 
                        community: str = "public", timeout: float = 2.0,
                        retries: int = 1) -> Dict:
        """
        Envoie une requête SNMP GET
        """
        logger.info(f"Envoi GET vers {target_ip} - OIDs: {len(oids)}")
        
        # Construction des varbinds
        varbindlist = [SNMPvarbind(oid=oid) for oid in oids]
        
        # Construction du paquet
        packet = (
            IP(dst=target_ip) /
            UDP(sport=RandShort(), dport=161) /
            SNMP(
                community=community,
                PDU=SNMPget(varbindlist=varbindlist)
            )
        )
        
        result = {
            'timestamp': datetime.now(),
            'target': target_ip,
            'type': 'GET',
            'oids': oids,
            'community': community,
            'success': False,
            'response_time': None,
            'values': {},
            'error': None
        }
        
        try:
            start_time = time.time()
            
            # Envoi avec retry
            response = None
            for attempt in range(retries + 1):
                self.stats['sent'] += 1
                response = sr1(packet, timeout=timeout, verbose=False)
                if response:
                    break
                
                if attempt < retries:
                    logger.debug(f"Retry {attempt + 1}/{retries} pour {target_ip}")
                    time.sleep(0.5)
            
            response_time = time.time() - start_time
            result['response_time'] = response_time
            
            if response and response.haslayer(SNMP):
                self.stats['received'] += 1
                result['success'] = True
                
                # Parse de la réponse
                snmp_layer = response[SNMP]
                if hasattr(snmp_layer, 'PDU') and hasattr(snmp_layer.PDU, 'varbindlist'):
                    for vb in snmp_layer.PDU.varbindlist:
                        oid = str(vb.oid)
                        value = vb.value
                        result['values'][oid] = value
                
                logger.info(f"✓ Réponse reçue en {response_time*1000:.1f}ms - {len(result['values'])} valeurs")
                
                # Vérification des erreurs SNMP
                if hasattr(snmp_layer.PDU, 'error_status') and snmp_layer.PDU.error_status != 0:
                    result['error'] = f"SNMP Error Status: {snmp_layer.PDU.error_status}"
                    self.stats['errors'] += 1
            else:
                self.stats['timeout'] += 1
                result['error'] = "Timeout ou réponse invalide"
                logger.warning(f"✗ Pas de réponse de {target_ip}")
                
        except Exception as e:
            self.stats['errors'] += 1
            result['error'] = str(e)
            logger.error(f"✗ Erreur lors de l'envoi vers {target_ip}: {e}")
        
        self.results.append(result)
        return result
    
    def send_set_request(self, target_ip: str, oid_values: Dict[str, any],
                        community: str = "private", timeout: float = 2.0) -> Dict:
        """
        Envoie une requête SNMP SET
        """
        logger.info(f"Envoi SET vers {target_ip} - {len(oid_values)} OIDs")
        
        # Construction des varbinds avec valeurs
        varbindlist = []
        for oid, value in oid_values.items():
            # Détection automatique du type de valeur
            if isinstance(value, int):
                snmp_value = value
            elif isinstance(value, str):
                snmp_value = value
            else:
                snmp_value = str(value)
            
            varbindlist.append(SNMPvarbind(oid=oid, value=snmp_value))
        
        # Construction du paquet
        packet = (
            IP(dst=target_ip) /
            UDP(sport=RandShort(), dport=161) /
            SNMP(
                community=community,
                PDU=SNMPset(varbindlist=varbindlist)
            )
        )
        
        result = {
            'timestamp': datetime.now(),
            'target': target_ip,
            'type': 'SET',
            'oid_values': oid_values,
            'community': community,
            'success': False,
            'response_time': None,
            'error': None
        }
        
        try:
            start_time = time.time()
            self.stats['sent'] += 1
            response = sr1(packet, timeout=timeout, verbose=False)
            response_time = time.time() - start_time
            result['response_time'] = response_time
            
            if response and response.haslayer(SNMP):
                self.stats['received'] += 1
                snmp_layer = response[SNMP]
                
                # Vérification du statut de réponse
                if hasattr(snmp_layer.PDU, 'error_status'):
                    if snmp_layer.PDU.error_status == 0:
                        result['success'] = True
                        logger.info(f"✓ SET réussi sur {target_ip} en {response_time*1000:.1f}ms")
                    else:
                        result['error'] = f"SNMP Error Status: {snmp_layer.PDU.error_status}"
                        self.stats['errors'] += 1
                        logger.error(f"✗ Erreur SET sur {target_ip}: {result['error']}")
            else:
                self.stats['timeout'] += 1
                result['error'] = "Timeout ou réponse invalide"
                logger.warning(f"✗ Pas de réponse SET de {target_ip}")
                
        except Exception as e:
            self.stats['errors'] += 1
            result['error'] = str(e)
            logger.error(f"✗ Erreur lors du SET vers {target_ip}: {e}")
        
        self.results.append(result)
        return result
    
    def send_getnext_request(self, target_ip: str, start_oid: str,
                            community: str = "public", max_repetitions: int = 10,
                            timeout: float = 2.0) -> Dict:
        """
        Envoie une série de requêtes GETNEXT pour parcourir une table
        """
        logger.info(f"Envoi GETNEXT vers {target_ip} depuis {start_oid}")
        
        result = {
            'timestamp': datetime.now(),
            'target': target_ip,
            'type': 'GETNEXT',
            'start_oid': start_oid,
            'community': community,
            'success': False,
            'response_time': None,
            'values': {},
            'total_oids': 0,
            'error': None
        }
        
        current_oid = start_oid
        start_time = time.time()
        
        try:
            for i in range(max_repetitions):
                # Construction du paquet GETNEXT
                packet = (
                    IP(dst=target_ip) /
                    UDP(sport=RandShort(), dport=161) /
                    SNMP(
                        community=community,
                        PDU=SNMPnext(varbindlist=[SNMPvarbind(oid=current_oid)])
                    )
                )
                
                self.stats['sent'] += 1
                response = sr1(packet, timeout=timeout, verbose=False)
                
                if not response or not response.haslayer(SNMP):
                    break
                
                self.stats['received'] += 1
                snmp_layer = response[SNMP]
                
                if not hasattr(snmp_layer.PDU, 'varbindlist') or not snmp_layer.PDU.varbindlist:
                    break
                
                vb = snmp_layer.PDU.varbindlist[0]
                next_oid = str(vb.oid)
                value = vb.value
                
                # Vérification si on a dépassé la table
                if not next_oid.startswith(start_oid.rsplit('.', 1)[0]):
                    break
                
                result['values'][next_oid] = value
                current_oid = next_oid
                result['total_oids'] += 1
                
                # Petite pause pour éviter le flood
                time.sleep(0.01)
            
            result['response_time'] = time.time() - start_time
            result['success'] = result['total_oids'] > 0
            
            logger.info(f"✓ GETNEXT terminé sur {target_ip} - {result['total_oids']} OIDs en {result['response_time']*1000:.1f}ms")
            
        except Exception as e:
            result['error'] = str(e)
            result['response_time'] = time.time() - start_time
            self.stats['errors'] += 1
            logger.error(f"✗ Erreur GETNEXT vers {target_ip}: {e}")
        
        self.results.append(result)
        return result
    
    def send_trap(self, target_ip: str,
                  community: str = "public",
                  enterprise_oid: str = "1.3.6.1.4.1.8072.2.3.0.1",
                  varbinds: Optional[Dict[str, any]] = None) -> Dict:
        """
        Envoie un trap SNMPv2c simple
        - target_ip : IP du serveur de trap
        - enterprise_oid : OID du trap
        - varbinds : dict {oid: value}
        """
        logger.info(f"Envoi TRAP vers {target_ip}")

        if varbinds is None:
            varbinds = {}

        # Construction des varbinds
        vb_list = []
        for oid, value in varbinds.items():
            if oid in self.COMMON_OIDS:
                oid = self.COMMON_OIDS[oid]
            vb_list.append(SNMPvarbind(oid=oid, value=value))

        # PDU Trap v2
        pdu = SNMPtrapv2(
            varbindlist=vb_list
        )

        packet = (
            IP(dst=target_ip) /
            UDP(sport=RandShort(), dport=162) /
            SNMP(
                community=community,
                PDU=pdu
            )
        )

        result = {
            "timestamp": datetime.now(),
            "target": target_ip,
            "type": "TRAP",
            "community": community,
            "enterprise_oid": enterprise_oid,
            "varbinds": varbinds,
            "success": False,
            "error": None,
        }

        try:
            send(packet, verbose=False)
            self.stats["sent"] += 1
            result["success"] = True
            logger.info("✓ TRAP envoyé")
        except Exception as e:
            self.stats["errors"] += 1
            result["error"] = str(e)
            logger.error(f"✗ Erreur lors de l'envoi du TRAP: {e}")

        self.results.append(result)
        return result

    def send_snmp(self, params: Dict) -> Dict:
        """
        Point d'entrée générique pour une API.
        params attendu, par ex :
        {
          "type": "GET" | "SET" | "GETNEXT" | "GETBULK" | "TRAP",
          "target": "10.0.0.1",
          "community": "public",
          "oids": ["sysDescr", "1.3.6.1.2.1.1.5.0"],
          "preset": "sysinfo",
          "values": {"sysLocation": "IUT Béziers"},
          "start_oid": "1.3.6.1.2.1.1",
          "non_repeaters": 0,
          "max_repetitions": 10,
        }
        """
        req_type = params.get("type", "GET").upper()
        target = params["target"]
        community = params.get("community", "public")

        # Résolution des OIDs (noms + presets)
        oids = self.resolve_oids(
            oids=params.get("oids"),
            preset=params.get("preset"),
        )

        if req_type == "GET":
            if not oids:
                raise ValueError("GET nécessite au moins un OID ou un preset")
            return self.send_get_request(
                target_ip=target,
                oids=oids,
                community=community,
                timeout=params.get("timeout", 2.0),
                retries=params.get("retries", 1),
            )

        elif req_type == "SET":
            values = params.get("values") or {}
            # On mappe les éventuels noms vers leurs vrais OIDs
            oid_values = {}
            for key, val in values.items():
                if key in self.COMMON_OIDS:
                    oid_values[self.COMMON_OIDS[key]] = val
                else:
                    oid_values[key] = val
            return self.send_set_request(
                target_ip=target,
                oid_values=oid_values,
                community=community,
                timeout=params.get("timeout", 2.0),
            )

        elif req_type == "GETNEXT":
            start_oid = params.get("start_oid")
            if not start_oid and oids:
                start_oid = oids[0]
            if not start_oid:
                raise ValueError("GETNEXT nécessite start_oid ou un OID")
            return self.send_getnext_request(
                target_ip=target,
                start_oid=start_oid,
                community=community,
                max_repetitions=params.get("max_repetitions", 10),
                timeout=params.get("timeout", 2.0),
            )

        elif req_type == "GETBULK":
            if not oids:
                raise ValueError("GETBULK nécessite des OIDs ou un preset")
            return self.send_getbulk_request(
                target_ip=target,
                oids=oids,
                community=community,
                non_repeaters=params.get("non_repeaters", 0),
                max_repetitions=params.get("max_repetitions", 10),
                timeout=params.get("timeout", 2.0),
            )

        elif req_type == "TRAP":
            return self.send_trap(
                target_ip=target,
                community=community,
                enterprise_oid=params.get("enterprise_oid", "1.3.6.1.4.1.8072.2.3.0.1"),
                varbinds=params.get("varbinds") or {},
            )

        else:
            raise ValueError(f"Type de requête SNMP non supporté: {req_type}")

    
    def send_getbulk_request(self, target_ip: str, oids: List[str],
                            community: str = "public", non_repeaters: int = 0,
                            max_repetitions: int = 10, timeout: float = 2.0) -> Dict:
        """
        Envoie une requête SNMP GETBULK (SNMPv2c uniquement)
        """
        logger.info(f"Envoi GETBULK vers {target_ip} - {len(oids)} OIDs")
        
        # Construction des varbinds
        varbindlist = [SNMPvarbind(oid=oid) for oid in oids]
        
        # Construction du paquet GETBULK
        packet = (
            IP(dst=target_ip) /
            UDP(sport=RandShort(), dport=161) /
            SNMP(
                version=1,  # SNMPv2c
                community=community,
                PDU=SNMPbulk(
                    non_repeaters=non_repeaters,
                    max_repetitions=max_repetitions,
                    varbindlist=varbindlist
                )
            )
        )
        
        result = {
            'timestamp': datetime.now(),
            'target': target_ip,
            'type': 'GETBULK',
            'oids': oids,
            'community': community,
            'non_repeaters': non_repeaters,
            'max_repetitions': max_repetitions,
            'success': False,
            'response_time': None,
            'values': {},
            'error': None
        }
        
        try:
            start_time = time.time()
            self.stats['sent'] += 1
            response = sr1(packet, timeout=timeout, verbose=False)
            response_time = time.time() - start_time
            result['response_time'] = response_time
            
            if response and response.haslayer(SNMP):
                self.stats['received'] += 1
                result['success'] = True
                
                # Parse de la réponse
                snmp_layer = response[SNMP]
                if hasattr(snmp_layer, 'PDU') and hasattr(snmp_layer.PDU, 'varbindlist'):
                    for vb in snmp_layer.PDU.varbindlist:
                        oid = str(vb.oid)
                        value = vb.value
                        result['values'][oid] = value
                
                logger.info(f"✓ GETBULK réussi sur {target_ip} en {response_time*1000:.1f}ms - {len(result['values'])} valeurs")
            else:
                self.stats['timeout'] += 1
                result['error'] = "Timeout ou réponse invalide"
                logger.warning(f"✗ Pas de réponse GETBULK de {target_ip}")
                
        except Exception as e:
            self.stats['errors'] += 1
            result['error'] = str(e)
            logger.error(f"✗ Erreur GETBULK vers {target_ip}: {e}")
        
        self.results.append(result)
        return result
    
    def discovery_scan(self, target_network: str, community: str = "public",
                      timeout: float = 1.0, threads: int = 10) -> List[str]:
        """
        Scan de découverte SNMP sur un réseau
        """
        
        logger.info(f"Découverte SNMP sur {target_network}")
        
        try:
            network = ipaddress.IPv4Network(target_network, strict=False)
        except ValueError as e:
            logger.error(f"Réseau invalide {target_network}: {e}")
            return []
        
        active_hosts = []
        lock = threading.Lock()
        
        def scan_host(ip_str):
            try:
                result = self.send_get_request(
                    ip_str, 
                    [self.COMMON_OIDS['sysDescr']], 
                    community, 
                    timeout,
                    retries=0
                )
                if result['success']:
                    with lock:
                        active_hosts.append(ip_str)
                        logger.info(f"✓ Host SNMP trouvé: {ip_str}")
            except Exception as e:
                logger.debug(f"Erreur scan {ip_str}: {e}")
        
        # Scan multi-threadé
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for ip in network.hosts():
                futures.append(executor.submit(scan_host, str(ip)))
            
            # Attendre completion avec progress
            completed = 0
            total = len(futures)
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                if completed % 10 == 0:
                    logger.info(f"Progress: {completed}/{total} hosts scannés")
        
        logger.info(f"Découverte terminée: {len(active_hosts)} hosts SNMP actifs")
        return sorted(active_hosts)
    
    def automated_polling(self, target_ip: str, oids: List[str],
                         community: str = "public", interval: int = 60,
                         duration: int = 3600) -> None:
        """
        Polling automatique d'un équipement
        """
        logger.info(f"Démarrage polling automatique {target_ip} - Intervalle: {interval}s, Durée: {duration}s")
        
        start_time = time.time()
        poll_count = 0
        
        try:
            while (time.time() - start_time) < duration:
                poll_start = time.time()
                
                result = self.send_get_request(target_ip, oids, community)
                poll_count += 1
                
                if result['success']:
                    logger.info(f"Poll #{poll_count} réussi - {len(result['values'])} métriques")
                    
                    # Sauvegarde en base si configuré
                    if self.db_config:
                        self._save_metrics_to_db(target_ip, result)
                else:
                    logger.warning(f"Poll #{poll_count} échoué: {result.get('error', 'Unknown')}")
                
                # Attente avant prochain poll
                poll_duration = time.time() - poll_start
                sleep_time = max(0, interval - poll_duration)
                if sleep_time > 0:
                    time.sleep(sleep_time)
                
        except KeyboardInterrupt:
            logger.info("Polling interrompu par l'utilisateur")
        
        logger.info(f"Polling terminé - {poll_count} polls effectués")
    
    def _save_metrics_to_db(self, target_ip: str, result: Dict) -> None:
        """Sauvegarde les métriques en base SQLite"""
        if not self.db_config:
            return

        try:
            conn = self.db_config.get('conn')  
            if conn is None:
                logger.error("Connexion SQLite manquante pour sauvegarde")
                return

            cur = conn.cursor()

            # Récupération de l'id device
            cur.execute("SELECT id FROM devices WHERE ip_address = ?", (target_ip,))
            device_row = cur.fetchone()
            device_id = device_row[0] if device_row else None

            for oid, value in result['values'].items():
                value_num = None
                try:
                    if isinstance(value, (int, float)):
                        value_num = float(value)
                    elif isinstance(value, str):
                        numbers = re.findall(r'-?\d+\.?\d*', str(value))
                        if numbers:
                            value_num = float(numbers[0])
                except:
                    pass

                cur.execute("""
                    INSERT INTO metrics (device_id, ts, oid, value_raw, value_num, latency_ms)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    device_id,
                    result['timestamp'],
                    oid,
                    str(value),
                    value_num,
                    int(result['response_time'] * 1000) if result['response_time'] else None
                ))
            conn.commit()
        except Exception as e:
            logger.error(f"Erreur sauvegarde métriques SQLite: {e}")

    
    def print_statistics(self):
        """Affiche les statistiques globales"""
        print(f"\n{'='*50}")
        print("STATISTIQUES ENVOYEUR SNMP")
        print(f"{'='*50}")
        print(f"Paquets envoyés: {self.stats['sent']}")
        print(f"Réponses reçues: {self.stats['received']}")
        print(f"Timeouts: {self.stats['timeout']}")
        print(f"Erreurs: {self.stats['errors']}")
        
        if self.stats['sent'] > 0:
            success_rate = (self.stats['received'] / self.stats['sent']) * 100
            print(f"Taux de succès: {success_rate:.1f}%")
        
        if self.results:
            response_times = [
                r.get('response_time')
                for r in self.results
                if r.get('response_time') is not None
            ]
            if response_times:
                avg_time = sum(response_times) / len(response_times)
                min_time = min(response_times)
                max_time = max(response_times)
                print(f"Temps de réponse moyen: {avg_time*1000:.1f}ms")
                print(f"Temps de réponse min/max: {min_time*1000:.1f}ms / {max_time*1000:.1f}ms")
    
    def export_results(self, filename: str = None):
        """Exporte les résultats en JSON"""
        if not filename:
            filename = f"snmp_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        
        # Préparation des données pour JSON
        export_data = {
            'statistics': self.stats,
            'results': []
        }
        
        for result in self.results:
            # Conversion datetime en string
            result_copy = result.copy()
            if 'timestamp' in result_copy:
                result_copy['timestamp'] = result_copy['timestamp'].isoformat()
            export_data['results'].append(result_copy)
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            logger.info(f"Résultats exportés vers {filename}")
        except Exception as e:
            logger.error(f"Erreur lors de l'export: {e}")

logger = logging.getLogger(__name__)

logger = logging.getLogger(__name__)

def main():
    """Fonction principale avec interface CLI (compatible API-style)"""

    load_dotenv('variables.env')  # charge les variables d'environnement

    parser = argparse.ArgumentParser(description="Générateur de requêtes SNMP")
    parser.add_argument('target', help="IP cible ou réseau (ex: 192.168.1.1 ou 192.168.1.0/24)")
    parser.add_argument('-c', '--community', default='public', help="Community string SNMP")
    parser.add_argument('-t', '--timeout', type=float, default=2.0, help="Timeout en secondes")
    parser.add_argument('-r', '--retries', type=int, default=1, help="Nombre de retries")
    parser.add_argument('--db-path', default='snmp_local.db', help="Chemin vers fichier SQLite")
    parser.add_argument('--no-db', action='store_true', help="Désactive la sauvegarde en base de données")

    # Modes exclusifs : soit une requête SNMP standard, soit discovery/poll/sysinfo
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '--type',
        choices=['GET', 'SET', 'GETNEXT', 'GETBULK', 'TRAP'],
        help="Type de requête SNMP standard"
    )
    group.add_argument('--discovery', action='store_true', help="Scan de découverte SNMP sur un réseau")
    group.add_argument('--poll', action='store_true', help="Polling automatique sur la cible")
    group.add_argument('--sysinfo', action='store_true', help="Preset infos système (GET sysinfo)")

    # Options communes pour les OIDs
    parser.add_argument(
        '--oid',
        action='append',
        help="OID ou nom (sysName, sysDescr, ...) ; peut être répété"
    )
    parser.add_argument(
        '--preset',
        help="Preset d'OIDs prédéfinis (ex: sysinfo, interfaces, host_resources)"
    )

    # SET : OID=valeur
    parser.add_argument(
        '--value',
        action='append',
        help="Pour SET : OID=valeur (peut être répété)"
    )

    # TRAP : OID=valeur
    parser.add_argument(
        '--varbind',
        action='append',
        help="Pour TRAP : OID=valeur (peut être répété)"
    )

    # GETNEXT / GETBULK
    parser.add_argument('--start-oid', help="OID de départ pour GETNEXT")
    parser.add_argument('--non-repeaters', type=int, default=0, help="non-repeaters pour GETBULK")
    parser.add_argument('--max-repetitions', type=int, default=10, help="max-repetitions pour GETNEXT/GETBULK")

    # Discovery / polling
    parser.add_argument('--interval', type=int, default=60, help="Intervalle de polling (secondes)")
    parser.add_argument('--duration', type=int, default=3600, help="Durée de polling (secondes)")
    parser.add_argument('--threads', type=int, default=10, help="Threads pour discovery")

    # Export
    parser.add_argument('--export', help="Fichier d'export des résultats (JSON)")

    args = parser.parse_args()

    # Config DB (pour le polling éventuel)
    if not args.no_db:
        db_config = {'db_path': args.db_path}
    else:
        db_config = None

    sender = SNMPSender(db_config)

    try:
        # ─────────────────────────────
        # MODE 1 : Requête SNMP standard via --type
        # ─────────────────────────────
        if args.type:
            params = {
                "type": args.type,
                "target": args.target,
                "community": args.community,
                "timeout": args.timeout,
                "retries": args.retries,
                "preset": args.preset,
                "oids": args.oid,
                "non_repeaters": args.non_repeaters,
                "max_repetitions": args.max_repetitions,
            }

            # SET : parsing des --value  => values: {oid: value}
            if args.value:
                values = {}
                for item in args.value:
                    if "=" not in item:
                        logger.error(f"Format invalide pour --value : {item} (attendu: OID=valeur)")
                        continue
                    k, v = item.split("=", 1)
                    values[k] = v
                if values:
                    params["values"] = values

            # TRAP : parsing des --varbind => varbinds: {oid: value}
            if args.varbind:
                vb = {}
                for item in args.varbind:
                    if "=" not in item:
                        logger.error(f"Format invalide pour --varbind : {item} (attendu: OID=valeur)")
                        continue
                    k, v = item.split("=", 1)
                    vb[k] = v
                if vb:
                    params["varbinds"] = vb

            # GETNEXT : OID de départ
            if args.start_oid:
                params["start_oid"] = args.start_oid

            # Appel générique
            result = sender.send_snmp(params)

            # Affichage simple
            print("\n=== RÉSULTAT SNMP ===")
            print(f"Type      : {result.get('type')}")
            print(f"Cible     : {result.get('target')}")
            print(f"Succès    : {result.get('success')}")
            if result.get("response_time") is not None:
                print(f"Temps     : {result['response_time']*1000:.1f} ms")
            if result.get("error"):
                print(f"Erreur    : {result['error']}")
            if result.get("values"):
                print("Valeurs   :")
                for oid, value in result["values"].items():
                    print(f"  {oid} = {value}")

        # ─────────────────────────────
        # MODE 2 : Discovery
        # ─────────────────────────────
        elif args.discovery:
            active_hosts = sender.discovery_scan(
                args.target,
                args.community,
                args.timeout,
                args.threads
            )

            print(f"\nHosts SNMP actifs trouvés ({len(active_hosts)}) :")
            for host in active_hosts:
                print(f"  {host}")

        # ─────────────────────────────
        # MODE 3 : Polling
        # ─────────────────────────────
        elif args.poll:
            # On réutilise les mêmes options que pour --type :
            # --oid / --preset
            if not args.oid and not args.preset:
                logger.error("Le mode --poll nécessite au moins un --oid ou un --preset")
            else:
                # nécessite que resolve_oids soit présent dans SNMPSender
                oids = sender.resolve_oids(oids=args.oid, preset=args.preset)
                if not oids:
                    logger.error("Aucun OID résolu pour le polling")
                else:
                    sender.automated_polling(
                        target_ip=args.target,
                        oids=oids,
                        community=args.community,
                        interval=args.interval,
                        duration=args.duration
                    )

        # ─────────────────────────────
        # MODE 4 : Sysinfo (preset)
        # ─────────────────────────────
        elif args.sysinfo:
            params = {
                "type": "GET",
                "target": args.target,
                "community": args.community,
                "preset": "sysinfo",
                "timeout": args.timeout,
                "retries": args.retries,
            }
            result = sender.send_snmp(params)

            if result.get("values"):
                print(f"\nInformations système de {args.target} :")
                # mapping inverse OID -> nom si possible
                oid_names = {v: k for k, v in sender.COMMON_OIDS.items()}
                for oid, value in result["values"].items():
                    name = oid_names.get(oid, oid)
                    print(f"  {name}: {value}")
            else:
                print("\nAucune donnée reçue pour sysinfo.")

        # Export des résultats si demandé
        if args.export:
            sender.export_results(args.export)

    except KeyboardInterrupt:
        logger.info("Opération interrompue par l'utilisateur")
    except Exception as e:
        logger.error(f"Erreur: {e}")
    finally:
        sender.print_statistics()


if __name__ == "__main__":
    main()
