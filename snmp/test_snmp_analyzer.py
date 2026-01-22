import unittest
import logging
from datetime import datetime, timedelta

from snmp_analyzer import SNMPAnalyzer, DatabaseManager, AnomalyDetector, SNMPPacketInfo

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
"""
- Vérifie la création correcte des tables SQLite.
- Teste insertion des métriques SNMP dans la base.
- Teste insertion des traps SNMP dans la base.
- Analyse la détection des floods de requêtes SNMP.
- Valide la détection des community strings par défaut.
- Contrôle la détection des traps venant de sources externes.
- Vérifie la conversion sécurisée des valeurs numériques.
"""
class TestSNMPModule(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger('TestSNMPModule')
        self.db_manager = DatabaseManager(":memory:")
        self.detector = AnomalyDetector(self.db_manager)
        self.analyzer = SNMPAnalyzer(interface=None, db_manager=self.db_manager)

    def test_database_tables_created(self):
        cur = self.db_manager.conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}
        self.logger.debug(f"Tables in DB: {tables}")
        self.assertIn('snmp_metrics', tables)
        self.assertIn('snmp_traps', tables)

    def test_insert_metric_and_count(self):
        packet_info = SNMPPacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.0.10",
            oid="1.3.6.1.2",
            oids=[{"oid": "1.3.6.1.2", "value": "100"}],
            response_time=0.05
        )
        self.db_manager.insert_metric(packet_info)
        cur = self.db_manager.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM snmp_metrics")
        count = cur.fetchone()[0]
        self.logger.debug(f"Count metrics: {count}")
        self.assertEqual(count, 1)

    def test_insert_trap_and_count(self):
        packet_info = SNMPPacketInfo(
            timestamp=datetime.now(),
            source_ip="10.0.0.1",
            version="v2c",
            community_or_user="public",
            enterprise_oid="1.3.6.1.4.1",
            severity="info",
            oids=[{"oid": "1.3.6.1.4.1", "value": "trap"}]
        )
        self.db_manager.insert_trap(packet_info)
        cur = self.db_manager.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM snmp_traps")
        count = cur.fetchone()[0]
        self.logger.debug(f"Count traps: {count}")
        self.assertEqual(count, 1)

    def test_anomaly_detection_flood(self):
        anomaly = None
        for i in range(101):
            packet_info = SNMPPacketInfo(source_ip="10.0.0.2", community_or_user="test", oids=[])
            anomaly = self.detector.analyze_packet(packet_info)
        self.logger.debug(f"Flood anomaly: {anomaly}")
        self.assertIsNotNone(anomaly)
        self.assertIn("Flood potentiel", anomaly)

    def test_anomaly_detection_default_community(self):
        packet_info = SNMPPacketInfo(source_ip="10.0.0.3", community_or_user="public", oids=[])
        anomaly = self.detector.analyze_packet(packet_info)
        self.logger.debug(f"Community anomaly: {anomaly}")
        self.assertIsNotNone(anomaly)
        self.assertIn("Community string par défaut", anomaly)

    def test_anomaly_detection_trap_external(self):
        packet_info = SNMPPacketInfo(source_ip="10.0.0.4", request_type="TRAP", community_or_user="private", oids=[])
        anomaly = self.detector.analyze_packet(packet_info)
        self.logger.debug(f"Trap anomaly: {anomaly}")
        self.assertIsNotNone(anomaly)
        self.assertIn("Trap depuis source externe", anomaly)

    def test_extract_numeric_value(self):
        self.assertEqual(self.db_manager._extract_numeric_value("123"), 123.0)
        self.assertEqual(self.db_manager._extract_numeric_value(123), 123.0)
        self.assertIsNone(self.db_manager._extract_numeric_value("abc"))
        self.assertIsNone(self.db_manager._extract_numeric_value(None))

if __name__ == '__main__':
    unittest.main()
