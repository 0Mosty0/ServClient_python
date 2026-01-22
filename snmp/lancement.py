#!/usr/bin/env python3
"""
Script de lancement pour l'analyseur SNMP
Usage: python launch.py [mode] [options]
"""

import sys
import os
import argparse
import subprocess
from pathlib import Path
from config import validate_config, config
from scapy.all import get_if_list

# Ajout du répertoire parent au path pour les imports
sys.path.append(str(Path(__file__).parent))


def check_requirements():
    """Vérifie que les dépendances sont installées"""
    required_modules = ['scapy', 'psycopg2', 'dotenv']
    missing = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        print(f"Modules manquants: {', '.join(missing)}")
        print("Installez-les avec: pip install " + ' '.join(missing))
        return False
    
    return True

def check_permissions():
    """Vérifie les permissions pour la capture réseau"""
    if os.name == 'nt':  # Windows
        return True  # Supposer que l'utilisateur a les droits
    else:  # Unix/Linux
        return os.geteuid() == 0

def list_interfaces():
    interfaces = get_if_list()
    print("Interfaces réseau disponibles :")
    for iface in interfaces:
        print(f" - {iface}")

def launch_analyzer(args):
    """Lance l'analyseur de trames"""
    
    if getattr(args, 'list_interfaces', False):
        list_interfaces()
        return
    
    if not check_permissions() and not getattr(args, 'no_capture', False):
        print("Attention: Droits administrateur requis pour la capture réseau")
        print("Utilisez 'sudo python launch.py analyzer' ou ajoutez --no-capture")
        return False
    
    cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "snmp_analyzer.py")]
    
    if args.interface:
        cmd.extend(["-i", args.interface])
    if args.count:
        cmd.extend(["-c", str(args.count)])
    if args.duration:
        cmd.extend(["-d", str(args.duration)])
    if getattr(args, 'no_db', False):
        cmd.append("--no-db")
    
    print(f"Lancement de l'analyseur: {' '.join(cmd)}")
    subprocess.run(cmd)

def launch_sender(args):
    """Lance l'envoyeur de requêtes"""
    if not args.target:
        print("Erreur: IP cible requise pour l'envoyeur")
        return False
    
    cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "send_snmp_requests.py"), args.target]
    
    if args.community:
        cmd.extend(["-c", args.community])
    if args.timeout:
        cmd.extend(["-t", str(args.timeout)])
    
    # Type de requête
    if args.sysinfo:
        cmd.append("--sysinfo")
    elif args.discovery:
        cmd.append("--discovery")
    elif args.get:
        cmd.extend(["--get"] + args.get)
    elif args.poll:
        cmd.extend(["--poll"] + args.poll)
        if args.interval:
            cmd.extend(["--interval", str(args.interval)])
        if args.poll_duration:
            cmd.extend(["--duration", str(args.poll_duration)])
    
    print(f"Lancement de l'envoyeur: {' '.join(cmd)}")
    subprocess.run(cmd)

def run_tests():
    """Exécute les tests basiques"""
    print("=== Tests de base ===")
    
    # Test configuration
    print("1. Test de configuration...")
    try:
        if validate_config():
            print("   ✓ Configuration valide")
        else:
            print("   ✗ Configuration invalide")
    except Exception as e:
        print(f"   ✗ Erreur configuration: {e}")
    
    # Test capture simple
    print("3. Test du module de capture...")
    try:
        subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "test_capture.py")], timeout=10, capture_output=True)
        print("   ✓ Module de capture OK")
    except Exception as e:
        print(f"   ✗ Test capture échoué: {e}")

def monitor_mode():
    """Mode monitoring complet"""
    print("=== Mode Monitoring Complet ===")
    print("Lancement de l'analyseur en arrière-plan...")
    
    # Lancement analyseur
    analyzer_cmd = [sys.executable, "snmp_analyzer.py", "-d", "0"]
    analyzer_proc = subprocess.Popen(analyzer_cmd)
    
    try:
        print("Analyseur démarré (PID: {})".format(analyzer_proc.pid))
        print("Appuyez sur Ctrl+C pour arrêter...")
        analyzer_proc.wait()
    except KeyboardInterrupt:
        print("\nArrêt du monitoring...")
        analyzer_proc.terminate()
        analyzer_proc.wait()

def main():
    parser = argparse.ArgumentParser(description="Lanceur pour l'analyseur SNMP")
    subparsers = parser.add_subparsers(dest='mode', help='Mode de fonctionnement')
    
    # Mode analyseur
    analyzer_parser = subparsers.add_parser('analyzer', help='Lance l\'analyseur de trames')
    analyzer_parser.add_argument('-i', '--interface', help='Interface réseau')
    analyzer_parser.add_argument('-c', '--count', type=int, help='Nombre de paquets')
    analyzer_parser.add_argument('-d', '--duration', type=int, help='Durée en secondes')
    analyzer_parser.add_argument('--no-db', action='store_true', help='Pas de sauvegarde BDD')
    analyzer_parser.add_argument('--no-capture', action='store_true', help='Mode sans capture')
    parser.add_argument('--no-db', action='store_true', help="Désactive la sauvegarde en base de données")
    analyzer_parser.add_argument('--list-interfaces', action='store_true', help='Afficher la liste des interfaces réseau')

    # Mode envoyeur
    sender_parser = subparsers.add_parser('sender', help='Lance l\'envoyeur de requêtes')
    sender_parser.add_argument('target', nargs='?', help='IP cible')
    sender_parser.add_argument('-c', '--community', default='public', help='Community SNMP')
    sender_parser.add_argument('-t', '--timeout', type=float, default=2.0, help='Timeout')
    
    # Types de requêtes pour l'envoyeur
    sender_group = sender_parser.add_mutually_exclusive_group()
    sender_group.add_argument('--sysinfo', action='store_true', help='Infos système')
    sender_group.add_argument('--discovery', action='store_true', help='Découverte réseau')
    sender_group.add_argument('--get', nargs='+', help='Requête GET')
    sender_group.add_argument('--poll', nargs='+', help='Polling automatique')
    
    sender_parser.add_argument('--interval', type=int, default=60, help='Intervalle polling')
    sender_parser.add_argument('--poll-duration', type=int, default=3600, help='Durée polling')
    
    # Mode test
    subparsers.add_parser('test', help='Exécute les tests')
    
    # Mode monitoring
    subparsers.add_parser('monitor', help='Mode monitoring complet')
    
    args = parser.parse_args()
    
    # Vérifications préalables
    if not check_requirements():
        return 1
    
    # Routage selon le mode
    if args.mode == 'analyzer':
        launch_analyzer(args)
    elif args.mode == 'sender':
        launch_sender(args)
    elif args.mode == 'test':
        run_tests()
    elif args.mode == 'monitor':
        monitor_mode()
    else:
        # Mode interactif si pas d'arguments
        print("=== Analyseur SNMP ===")
        print("Modes disponibles:")
        print("1. analyzer  - Capture et analyse du trafic")
        print("2. sender    - Envoi de requêtes SNMP")
        print("3. test      - Tests de fonctionnement")
        print("4. monitor   - Monitoring complet")
        print("\nExemples:")
        print("  python launch.py analyzer -i eth0 -d 300")
        print("  python launch.py sender 192.168.1.1 --sysinfo")
        print("  python launch.py test")
        
        choice = input("\nChoisissez un mode (1-4): ").strip()
        
        if choice == '1':
            interface = input("Interface (défaut: auto, tape 'list' pour voir): ").strip()

            if interface.lower() == "list":
                interfaces = get_if_list()
                print("Interfaces réseau disponibles :")
                for i, iface in enumerate(interfaces, 1):
                    print(f"  {i}. {iface}")
                choix = input("Choisissez une interface par numéro : ").strip()
                try:
                    index = int(choix) - 1
                    if 0 <= index < len(interfaces):
                        interface = interfaces[index]
                    else:
                        print("Choix invalide, utilisation interface par défaut")
                        interface = None
                except ValueError:
                    print("Choix invalide, utilisation interface par défaut")
                    interface = None

            if interface == "":
                interface = None

            duration = input("Durée en secondes (défaut: illimité): ").strip()
            duration = int(duration) if duration else 0

            args.interface = interface  # <- Ajout important ici
            args.duration = duration
            args.count = None
            args.no_db = False
            args.no_capture = False
            launch_analyzer(args)

            
        elif choice == '2':
            target = input("IP cible: ").strip()
            if target:
                args.target = target
                args.community = 'public'
                args.timeout = 2.0
                args.sysinfo = True
                args.discovery = False
                args.get = None
                args.poll = None
                launch_sender(args)
        
        elif choice == '3':
            run_tests()
        
        elif choice == '4':
            monitor_mode()

if __name__ == "__main__":
    sys.exit(main() or 0)
