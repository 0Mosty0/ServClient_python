import sys
import json
import requests

from PySide6.QtCore import Qt, QSettings
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget,
    QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QComboBox, QPushButton, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QLabel, QSpinBox, QMessageBox
)


API_BASE_URL = "http://localhost:5000/api"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Gestionnaire SNMP v2c")
        self.resize(900, 600)

        # QSettings pour sauvegarder la config (équivalent localStorage)
        self.settings = QSettings("IUT-SAE", "Gestionnaire-SNMP")

        # Widget central avec onglets
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Création des onglets
        self._create_trames_tab()
        self._create_config_tab()
        self._create_history_tab()

        # Barre de statut
        self.statusBar().showMessage("Prêt")

        # Charger la configuration enregistrée
        self.load_config_into_forms()

    # ---------- Onglet 1 : Trames ----------

    def _create_trames_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        form_layout = QFormLayout()

        self.type_combo = QComboBox()
        self.type_combo.addItems(["GET", "SET", "TRAP"])

        self.community_edit = QLineEdit()
        self.target_edit = QLineEdit()
        self.oid_edit = QLineEdit()
        self.value_edit = QLineEdit()

        form_layout.addRow("Type de trame :", self.type_combo)
        form_layout.addRow("Communauté :", self.community_edit)
        form_layout.addRow("Adresse IP cible :", self.target_edit)
        form_layout.addRow("OID :", self.oid_edit)
        form_layout.addRow("Valeur (SET uniquement) :", self.value_edit)

        layout.addLayout(form_layout)

        # Bouton Envoyer
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        self.send_button = QPushButton("Envoyer la trame")
        self.send_button.clicked.connect(self.send_snmp_frame)
        button_layout.addWidget(self.send_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        # Zone de réponse
        response_label = QLabel("Réponse du serveur :")
        self.response_text = QTextEdit()
        self.response_text.setReadOnly(True)
        layout.addWidget(response_label)
        layout.addWidget(self.response_text)

        self.tabs.addTab(tab, "Trames")

    def send_snmp_frame(self):
        data = {
            "type": self.type_combo.currentText(),
            "community": self.community_edit.text().strip(),
            "target": self.target_edit.text().strip(),
            "oid": self.oid_edit.text().strip(),
            "value": self.value_edit.text().strip() or None
        }

        # Validation très basique
        if not data["community"] or not data["target"] or not data["oid"]:
            QMessageBox.warning(self, "Champs manquants",
                                "Communauté, IP cible et OID sont obligatoires.")
            return

        self.response_text.setPlainText("Envoi en cours...")
        self.statusBar().showMessage("Envoi de la trame SNMP...")

        try:
            res = requests.post(f"{API_BASE_URL}/snmp", json=data, timeout=5)
            res.raise_for_status()
            result_json = res.json()
            self.response_text.setPlainText(json.dumps(result_json, indent=2, ensure_ascii=False))
            self.statusBar().showMessage("Trame envoyée avec succès", 5000)
        except requests.exceptions.RequestException as e:
            self.response_text.setPlainText("Erreur de communication avec le serveur SNMP.")
            self.statusBar().showMessage("Erreur réseau", 5000)
            QMessageBox.critical(self, "Erreur réseau", str(e))
        except ValueError:
            self.response_text.setPlainText("Réponse non valide (JSON invalide).")
            self.statusBar().showMessage("Erreur de format de réponse", 5000)

    # ---------- Onglet 2 : Configuration ----------

    def _create_config_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        form_layout = QFormLayout()

        self.config_ip_edit = QLineEdit()
        self.config_port_spin = QSpinBox()
        self.config_port_spin.setRange(1, 65535)
        self.config_community_edit = QLineEdit()

        form_layout.addRow("Adresse IP par défaut :", self.config_ip_edit)
        form_layout.addRow("Port SNMP :", self.config_port_spin)
        form_layout.addRow("Communauté :", self.config_community_edit)

        layout.addLayout(form_layout)

        # Bouton sauvegarder
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        save_button = QPushButton("Sauvegarder")
        save_button.clicked.connect(self.save_config)
        button_layout.addWidget(save_button)
        button_layout.addStretch()

        layout.addLayout(button_layout)

        self.tabs.addTab(tab, "Configuration")

    def save_config(self):
        self.settings.setValue("ip_default", self.config_ip_edit.text().strip())
        self.settings.setValue("port", self.config_port_spin.value())
        self.settings.setValue("community_default", self.config_community_edit.text().strip())

        # On applique directement aux champs de l’onglet Trames
        if self.config_ip_edit.text().strip():
            self.target_edit.setText(self.config_ip_edit.text().strip())
        if self.config_community_edit.text().strip():
            self.community_edit.setText(self.config_community_edit.text().strip())

        self.statusBar().showMessage("Configuration sauvegardée", 5000)
        QMessageBox.information(self, "Configuration",
                                "Configuration sauvegardée avec succès !")

    def load_config_into_forms(self):
        ip_default = self.settings.value("ip_default", "192.168.0.10")
        port = int(self.settings.value("port", 161))
        community_default = self.settings.value("community_default", "public")

        # Onglet Config
        self.config_ip_edit.setText(ip_default)
        self.config_port_spin.setValue(port)
        self.config_community_edit.setText(community_default)

        # Onglet Trames
        self.target_edit.setText(ip_default)
        self.community_edit.setText(community_default)

    # ---------- Onglet 3 : Historique ----------

    def _create_history_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Bouton Actualiser
        button_layout = QHBoxLayout()
        self.refresh_button = QPushButton("Actualiser")
        self.refresh_button.clicked.connect(self.load_history)
        button_layout.addStretch()
        button_layout.addWidget(self.refresh_button)
        button_layout.addStretch()

        layout.addLayout(button_layout)

        # Tableau
        self.history_table = QTableWidget(0, 6)
        self.history_table.setHorizontalHeaderLabels(
            ["Date", "Type", "OID", "Cible", "Valeur", "Statut"]
        )
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)

        layout.addWidget(self.history_table)

        self.tabs.addTab(tab, "Historique")

    def load_history(self):
        self.statusBar().showMessage("Chargement de l'historique...")
        self.history_table.setRowCount(0)

        try:
            res = requests.get(f"{API_BASE_URL}/history", timeout=5)
            res.raise_for_status()
            data = res.json()

            if not data:
                self.history_table.setRowCount(1)
                self.history_table.setSpan(0, 0, 1, 6)
                empty_item = QTableWidgetItem("Aucune trame enregistrée.")
                empty_item.setTextAlignment(Qt.AlignCenter)
                self.history_table.setItem(0, 0, empty_item)
                self.statusBar().showMessage("Aucune trame", 5000)
                return

            self.history_table.setRowCount(len(data))
            for row, trame in enumerate(data):
                # On suppose des clés: date, type, oid, cible, valeur, statut
                self.history_table.setItem(row, 0, QTableWidgetItem(str(trame.get("date", ""))))
                self.history_table.setItem(row, 1, QTableWidgetItem(str(trame.get("type", ""))))
                self.history_table.setItem(row, 2, QTableWidgetItem(str(trame.get("oid", ""))))
                self.history_table.setItem(row, 3, QTableWidgetItem(str(trame.get("cible", ""))))
                self.history_table.setItem(row, 4, QTableWidgetItem(str(trame.get("valeur", ""))))
                self.history_table.setItem(row, 5, QTableWidgetItem(str(trame.get("statut", ""))))

            self.statusBar().showMessage("Historique chargé", 5000)

        except requests.exceptions.RequestException as e:
            self.statusBar().showMessage("Erreur lors du chargement de l'historique", 5000)
            QMessageBox.critical(self, "Erreur réseau", str(e))
        except ValueError:
            self.statusBar().showMessage("Réponse JSON invalide", 5000)
            QMessageBox.critical(self, "Erreur", "Réponse JSON invalide reçue depuis l'API.")


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
