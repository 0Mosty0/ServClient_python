# snmp/config.py
"""
Configuration centralisée pour l'analyseur SNMP
Développé par Louis - Étudiant 1
"""

import os
from dataclasses import dataclass
from typing import Optional, Dict, List
from dotenv import load_dotenv
import json
from dataclasses import asdict
import logging

# Chargement des variables d'environnement
load_dotenv()

@dataclass
class DatabaseConfig:
    """Configuration base de données SQLite locale"""
    db_path: str = "snmp_local.db"  # chemin vers fichier .db local

    @classmethod
    def from_env(cls):
        """Création depuis variables d'environnement ou valeur par défaut"""
        return cls(
            db_path=os.getenv("DB_PATH", "snmp_local.db")
        )

    def to_dict(self) -> Dict[str, str]:
        """Conversion en dict simple"""
        return {
            'db_path': self.db_path
        }

@dataclass
class SNMPConfig:
    """Configuration SNMP par défaut"""
    default_community: str = "public"
    default_timeout: float = 2.0
    default_retries: int = 1
    default_port: int = 161
    trap_port: int = 162
    
    # Versions SNMP supportées
    supported_versions: List[str] = None
    
    # OIDs système couramment utilisés
    system_oids: Dict[str, str] = None
    
    def __post_init__(self):
        if self.supported_versions is None:
            self.supported_versions = ['v1', 'v2c', 'v3']
        
        if self.system_oids is None:
            self.system_oids = {
                'sysDescr': '1.3.6.1.2.1.1.1.0',
                'sysObjectID': '1.3.6.1.2.1.1.2.0',
                'sysUpTime': '1.3.6.1.2.1.1.3.0',
                'sysContact': '1.3.6.1.2.1.1.4.0',
                'sysName': '1.3.6.1.2.1.1.5.0',
                'sysLocation': '1.3.6.1.2.1.1.6.0',
                'sysServices': '1.3.6.1.2.1.1.7.0',
                
                # Interface MIB
                'ifNumber': '1.3.6.1.2.1.2.1.0',
                'ifIndex': '1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '1.3.6.1.2.1.2.2.1.2',
                'ifType': '1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '1.3.6.1.2.1.2.2.1.5',
                'ifPhysAddress': '1.3.6.1.2.1.2.2.1.6',
                'ifAdminStatus': '1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '1.3.6.1.2.1.2.2.1.8',
                'ifLastChange': '1.3.6.1.2.1.2.2.1.9',
                'ifInOctets': '1.3.6.1.2.1.2.2.1.10',
                'ifInUcastPkts': '1.3.6.1.2.1.2.2.1.11',
                'ifInErrors': '1.3.6.1.2.1.2.2.1.14',
                'ifOutOctets': '1.3.6.1.2.1.2.2.1.16',
                'ifOutUcastPkts': '1.3.6.1.2.1.2.2.1.17',
                'ifOutErrors': '1.3.6.1.2.1.2.2.1.20',
                
                # IP MIB
                'ipForwarding': '1.3.6.1.2.1.4.1.0',
                'ipDefaultTTL': '1.3.6.1.2.1.4.2.0',
                'ipInReceives': '1.3.6.1.2.1.4.3.0',
                'ipAddrTable': '1.3.6.1.2.1.4.20',
                'ipRouteTable': '1.3.6.1.2.1.4.21',
                
                # Host Resources MIB
                'hrSystemUptime': '1.3.6.1.2.1.25.1.1.0',
                'hrSystemDate': '1.3.6.1.2.1.25.1.2.0',
                'hrSystemInitialLoadDevice': '1.3.6.1.2.1.25.1.3.0',
                'hrSystemInitialLoadParameters': '1.3.6.1.2.1.25.1.4.0',
                'hrSystemNumUsers': '1.3.6.1.2.1.25.1.5.0',
                'hrSystemProcesses': '1.3.6.1.2.1.25.1.6.0',
                'hrSystemMaxProcesses': '1.3.6.1.2.1.25.1.7.0',
                'hrMemorySize': '1.3.6.1.2.1.25.2.2.0',
                'hrStorageTable': '1.3.6.1.2.1.25.2.3',
                'hrStorageUsed': '1.3.6.1.2.1.25.2.3.1.6',
                'hrStorageSize': '1.3.6.1.2.1.25.2.3.1.5',
                'hrProcessorTable': '1.3.6.1.2.1.25.3.3',
                'hrProcessorLoad': '1.3.6.1.2.1.25.3.3.1.2',
                
                # TCP MIB
                'tcpRtoAlgorithm': '1.3.6.1.2.1.6.1.0',
                'tcpRtoMin': '1.3.6.1.2.1.6.2.0',
                'tcpRtoMax': '1.3.6.1.2.1.6.3.0',
                'tcpMaxConn': '1.3.6.1.2.1.6.4.0',
                'tcpActiveOpens': '1.3.6.1.2.1.6.5.0',
                'tcpPassiveOpens': '1.3.6.1.2.1.6.6.0',
                'tcpAttemptFails': '1.3.6.1.2.1.6.7.0',
                'tcpEstabResets': '1.3.6.1.2.1.6.8.0',
                'tcpCurrEstab': '1.3.6.1.2.1.6.9.0',
                
                # UDP MIB
                'udpInDatagrams': '1.3.6.1.2.1.7.1.0',
                'udpNoPorts': '1.3.6.1.2.1.7.2.0',
                'udpInErrors': '1.3.6.1.2.1.7.3.0',
                'udpOutDatagrams': '1.3.6.1.2.1.7.4.0'
            }
    
    @classmethod
    def from_env(cls):
        """Création depuis variables d'environnement"""
        return cls(
            default_community=os.getenv("SNMP_COMMUNITY", cls.default_community),
            default_timeout=float(os.getenv("SNMP_TIMEOUT", cls.default_timeout)),
            default_retries=int(os.getenv("SNMP_RETRIES", cls.default_retries)),
            default_port=int(os.getenv("SNMP_PORT", cls.default_port)),
            trap_port=int(os.getenv("SNMP_TRAP_PORT", cls.trap_port))
        )

@dataclass
class CaptureConfig:
    """Configuration pour la capture de paquets"""
    default_interface: Optional[str] = None
    buffer_size: int = 65536
    promiscuous_mode: bool = False
    capture_timeout: int = 1000  # millisecondes
    max_packets_in_memory: int = 10000
    
    # Filtres BPF pour différents types de capture
    snmp_filter: str = "udp port 161 or udp port 162"
    snmp_requests_only: str = "udp port 161 and dst port 161"
    snmp_responses_only: str = "udp port 161 and src port 161"
    snmp_traps_only: str = "udp port 162"
    
    @classmethod
    def from_env(cls):
        """Création depuis variables d'environnement"""
        return cls(
            default_interface=os.getenv("CAPTURE_INTERFACE"),
            buffer_size=int(os.getenv("CAPTURE_BUFFER_SIZE", cls.buffer_size)),
            promiscuous_mode=os.getenv("CAPTURE_PROMISCUOUS", "false").lower() == "true",
            capture_timeout=int(os.getenv("CAPTURE_TIMEOUT", cls.capture_timeout)),
            max_packets_in_memory=int(os.getenv("MAX_PACKETS_MEMORY", cls.max_packets_in_memory))
        )

@dataclass
class AnalysisConfig:
    """Configuration pour l'analyse des paquets"""
    # Détection d'anomalies
    max_requests_per_minute: int = 100
    suspicious_communities: List[str] = None
    alert_response_time_threshold: float = 5.0  # secondes
    
    # Cache et nettoyage
    request_cache_ttl: int = 30  # secondes
    cache_cleanup_interval: int = 60  # secondes
    
    # Statistiques
    stats_update_interval: int = 10  # paquets
    stats_export_interval: int = 300  # secondes
    
    def __post_init__(self):
        if self.suspicious_communities is None:
            self.suspicious_communities = [
                'public', 'private', 'community', 'admin', 
                'root', 'test', 'guest', 'default'
            ]
    
    @classmethod
    def from_env(cls):
        """Création depuis variables d'environnement"""
        return cls(
            max_requests_per_minute=int(os.getenv("MAX_REQUESTS_PER_MIN", cls.max_requests_per_minute)),
            alert_response_time_threshold=float(os.getenv("ALERT_RESPONSE_TIME", cls.alert_response_time_threshold)),
            request_cache_ttl=int(os.getenv("CACHE_TTL", cls.request_cache_ttl)),
            cache_cleanup_interval=int(os.getenv("CACHE_CLEANUP", cls.cache_cleanup_interval))
        )

@dataclass
class LoggingConfig:
    """Configuration des logs"""
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    log_file: str = "snmp_analyzer.log"
    log_rotation: bool = True
    log_max_size: int = 10 * 1024 * 1024  # 10 MB
    log_backup_count: int = 5
    console_output: bool = True
    
    @classmethod
    def from_env(cls):
        """Création depuis variables d'environnement"""
        return cls(
            log_level=os.getenv("LOG_LEVEL", cls.log_level),
            log_file=os.getenv("LOG_FILE", cls.log_file),
            log_rotation=os.getenv("LOG_ROTATION", "true").lower() == "true",
            log_max_size=int(os.getenv("LOG_MAX_SIZE", cls.log_max_size)),
            log_backup_count=int(os.getenv("LOG_BACKUP_COUNT", cls.log_backup_count)),
            console_output=os.getenv("CONSOLE_OUTPUT", "true").lower() == "true"
        )

@dataclass
class ExportConfig:
    """Configuration pour l'export des données"""
    default_export_format: str = "json"
    export_directory: str = "exports"
    include_raw_packets: bool = False
    compress_exports: bool = True
    max_export_size: int = 100 * 1024 * 1024  # 100 MB
    
    # Formats supportés
    supported_formats: List[str] = None
    
    def __post_init__(self):
        if self.supported_formats is None:
            self.supported_formats = ['json', 'csv', 'xml', 'pcap']
    
    @classmethod
    def from_env(cls):
        """Création depuis variables d'environnement"""
        return cls(
            default_export_format=os.getenv("EXPORT_FORMAT", cls.default_export_format),
            export_directory=os.getenv("EXPORT_DIR", cls.export_directory),
            include_raw_packets=os.getenv("EXPORT_RAW", "false").lower() == "true",
            compress_exports=os.getenv("EXPORT_COMPRESS", "true").lower() == "true",
            max_export_size=int(os.getenv("MAX_EXPORT_SIZE", cls.max_export_size))
        )

@dataclass
class SecurityConfig:
    """Configuration sécurité"""
    # Authentification SNMP v3
    auth_protocols: List[str] = None
    priv_protocols: List[str] = None
    
    # Filtrage IP
    allowed_sources: Optional[List[str]] = None
    blocked_sources: Optional[List[str]] = None
    
    # Limitations
    max_oids_per_request: int = 100
    max_community_length: int = 64
    
    def __post_init__(self):
        if self.auth_protocols is None:
            self.auth_protocols = ['MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512']
        
        if self.priv_protocols is None:
            self.priv_protocols = ['DES', '3DES', 'AES128', 'AES192', 'AES256']
    
    @classmethod
    def from_env(cls):
        """Création depuis variables d'environnement"""
        allowed_sources = os.getenv("ALLOWED_SOURCES")
        blocked_sources = os.getenv("BLOCKED_SOURCES")
        
        return cls(
            allowed_sources=allowed_sources.split(',') if allowed_sources else None,
            blocked_sources=blocked_sources.split(',') if blocked_sources else None,
            max_oids_per_request=int(os.getenv("MAX_OIDS_PER_REQUEST", cls.max_oids_per_request)),
            max_community_length=int(os.getenv("MAX_COMMUNITY_LENGTH", cls.max_community_length))
        )

class AppConfig:
    """Configuration principale de l'application"""
    
    def __init__(self, use_env: bool = True):
        """
        Initialise la configuration
        :param use_env: Utiliser les variables d'environnement si disponibles
        """
        if use_env:
            self.database = DatabaseConfig.from_env()
            self.snmp = SNMPConfig.from_env()
            self.capture = CaptureConfig.from_env()
            self.analysis = AnalysisConfig.from_env()
            self.logging = LoggingConfig.from_env()
            self.export = ExportConfig.from_env()
            self.security = SecurityConfig.from_env()
        else:
            self.database = DatabaseConfig()
            self.snmp = SNMPConfig()
            self.capture = CaptureConfig()
            self.analysis = AnalysisConfig()
            self.logging = LoggingConfig()
            self.export = ExportConfig()
            self.security = SecurityConfig()
    
    def validate(self) -> List[str]:
        """
        Valide la configuration et retourne les erreurs trouvées
        :return: Liste des erreurs de validation
        """
        errors = []
        
        # Validation base de données
        if not self.database.host:
            errors.append("Host de base de données manquant")
        if not self.database.database:
            errors.append("Nom de base de données manquant")
        if not self.database.user:
            errors.append("Utilisateur de base de données manquant")
        
        # Validation SNMP
        if self.snmp.default_timeout <= 0:
            errors.append("Timeout SNMP doit être positif")
        if self.snmp.default_retries < 0:
            errors.append("Nombre de retries SNMP ne peut être négatif")
        
        # Validation capture
        if self.capture.buffer_size <= 0:
            errors.append("Taille de buffer de capture doit être positive")
        
        # Validation export
        if self.export.default_export_format not in self.export.supported_formats:
            errors.append(f"Format d'export '{self.export.default_export_format}' non supporté")
        
        return errors
    
    def save_to_file(self, filename: str):
        """
        Sauvegarde la configuration dans un fichier JSON
        :param filename: Nom du fichier
        """

        
        config_dict = {
            'database': asdict(self.database),
            'snmp': asdict(self.snmp),
            'capture': asdict(self.capture),
            'analysis': asdict(self.analysis),
            'logging': asdict(self.logging),
            'export': asdict(self.export),
            'security': asdict(self.security)
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(config_dict, f, indent=2, ensure_ascii=False)
    
    @classmethod
    def load_from_file(cls, filename: str):
        """
        Charge la configuration depuis un fichier JSON
        :param filename: Nom du fichier
        :return: Instance d'AppConfig
        """
        
        with open(filename, 'r', encoding='utf-8') as f:
            config_dict = json.load(f)
        
        config = cls(use_env=False)
        
        # Reconstruction des objets de configuration
        if 'database' in config_dict:
            config.database = DatabaseConfig(**config_dict['database'])
        if 'snmp' in config_dict:
            config.snmp = SNMPConfig(**config_dict['snmp'])
        if 'capture' in config_dict:
            config.capture = CaptureConfig(**config_dict['capture'])
        if 'analysis' in config_dict:
            config.analysis = AnalysisConfig(**config_dict['analysis'])
        if 'logging' in config_dict:
            config.logging = LoggingConfig(**config_dict['logging'])
        if 'export' in config_dict:
            config.export = ExportConfig(**config_dict['export'])
        if 'security' in config_dict:
            config.security = SecurityConfig(**config_dict['security'])
        
        return config

# Instance globale de configuration (utilisée par défaut)
config = AppConfig()

# Fonctions utilitaires pour accéder à la configuration
def get_db_config() -> DatabaseConfig:
    """Récupère la configuration base de données"""
    return config.database

def get_snmp_config() -> SNMPConfig:
    """Récupère la configuration SNMP"""
    return config.snmp

def get_capture_config() -> CaptureConfig:
    """Récupère la configuration capture"""
    return config.capture

def get_analysis_config() -> AnalysisConfig:
    """Récupère la configuration analyse"""
    return config.analysis

def get_logging_config() -> LoggingConfig:
    """Récupère la configuration logging"""
    return config.logging

def get_export_config() -> ExportConfig:
    """Récupère la configuration export"""
    return config.export

def get_security_config() -> SecurityConfig:
    """Récupère la configuration sécurité"""
    return config.security

def validate_config() -> bool:
    """
    Valide la configuration globale
    :return: True si valide, False sinon
    """
    errors = config.validate()
    if errors:
        logger = logging.getLogger(__name__)
        logger.error("Erreurs de configuration détectées:")
        for error in errors:
            logger.error(f"  - {error}")
        return False
    return True

if __name__ == "__main__":
    # Test de la configuration
    print("=== Test de configuration SNMP ===")
    
    # Validation
    if validate_config():
        print("✓ Configuration valide")
    else:
        print("✗ Configuration invalide")
    
    # Affichage des configurations principales
    print(f"\nBase de données: {config.database.host}:{config.database.port}/{config.database.database}")
    print(f"SNMP Community: {config.snmp.default_community}")
    print(f"SNMP Timeout: {config.snmp.default_timeout}s")
    print(f"Nombre d'OIDs système: {len(config.snmp.system_oids)}")
    print(f"Interface capture: {config.capture.default_interface or 'Auto-détection'}")
    print(f"Format export: {config.export.default_export_format}")
    
    # Test de sauvegarde/chargement
    try:
        config.save_to_file("config_test.json")
        loaded_config = AppConfig.load_from_file("config_test.json")
        print("✓ Sauvegarde/Chargement OK")
        os.remove("config_test.json")  # Nettoyage
    except Exception as e:
        print(f"✗ Erreur sauvegarde/chargement: {e}")