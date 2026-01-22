import sys
# Les dépendances pour l'API et la communication réseau sont désactivées (mode autonome)
# import requests
# import json
# import threading
# import import socket

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStackedWidget, QListWidget, QLineEdit,
    QGridLayout, QFrame, QSizePolicy, QScrollArea, QListWidgetItem,
    QComboBox 
)
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt, QEvent, QObject
from typing import Dict, List, Any 
from pyqtgraph import PlotWidget, BarGraphItem
from collections import defaultdict

# --- Configuration Générale ---
API_BASE_URL = "http://127.0.0.1:8000" # URL de base de l'API (pour référence)

# --- Fonction Utilitaire ---

def get_local_ip():
    """Simule la récupération de l'adresse IP locale de la machine."""
    return "192.168.1.100"

# Adresse IP source utilisée par défaut dans l'onglet Trames
DEFAULT_SOURCE_IP = get_local_ip()

# --- ÉVÉNEMENTS PERSONNALISÉS ---
# Ces classes héritent de QEvent et servent de conteneurs pour transférer 
# les données entre les threads (ou ici, pour simuler la réception de données).

class DashboardDataEvent(QEvent):
    """Événement pour transférer les données du tableau de bord (Dashboard)."""
    EVENT_TYPE = QEvent.registerEventType()
    def __init__(self, data: Dict[str, Any]):
        # Nécessite de caster l'entier EVENT_TYPE en QEvent.Type pour PySide6
        super().__init__(QEvent.Type(DashboardDataEvent.EVENT_TYPE))
        self.data = data

class FrameResultEvent(QEvent):
    """Événement pour afficher le résultat de l'envoi d'une trame."""
    EVENT_TYPE = QEvent.registerEventType()
    def __init__(self, message: str):
        super().__init__(QEvent.Type(FrameResultEvent.EVENT_TYPE))
        self.message = message

class ConfigServersEvent(QEvent):
    """Événement pour transférer la liste des serveurs SNMP configurés."""
    EVENT_TYPE = QEvent.registerEventType()
    def __init__(self, data: List[Dict[str, Any]]):
        super().__init__(QEvent.Type(ConfigServersEvent.EVENT_TYPE))
        self.data = data

class ConfigStatusEvent(QEvent):
    """Événement pour afficher un message de statut (succès/erreur) après une action CRUD."""
    EVENT_TYPE = QEvent.registerEventType()
    def __init__(self, message: str, color: str):
        super().__init__(QEvent.Type(ConfigStatusEvent.EVENT_TYPE))
        self.message = message
        self.color = color

# --- Widgets Personnalisés ---

class CustomListWidget(QListWidget):
    """Widget de liste personnalisé avec un style minimaliste pour l'affichage des données."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        # Style CSS pour une apparence moderne
        self.setStyleSheet("""
            QListWidget {
                border: 1px solid #C0C0C0;
                border-radius: 5px;
                padding: 5px;
                background-color: #F8F8F8;
            }
            QListWidget::item {
                padding: 5px;
                margin-bottom: 2px;
                border-bottom: 1px solid #E0E0E0;
            }
            QListWidget::item:hover {
                background-color: #E6E6E6;
            }
        """)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setMinimumHeight(150)

# --- VUES ONGLETS DE L'APPLICATION ---

class DashboardView(QWidget):
    """Vue du Dashboard : Affiche les indicateurs de performance et les graphiques (Image 1)."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 30, 30, 30)

        # En-tête : Titre et sélecteur de temps (30min, 1h, 1j)
        header_layout = QHBoxLayout()
        title_label = QLabel("Dashboard")
        title_label.setFont(QFont("Arial", 24, QFont.Bold))
        header_layout.addWidget(title_label)
        header_layout.addStretch(1)

        # Boutons de période (design minimaliste)
        self.period_buttons = {}
        for text in ["30min", "1h", "1j"]:
            btn = QPushButton(text)
            btn.setStyleSheet("QPushButton { background-color: #3AA9E8; color: white; border-radius: 5px; padding: 5px 15px; }"
                             "QPushButton:hover { background-color: #308DCF; }")
            self.period_buttons[text] = btn
            header_layout.addWidget(btn)

        self.layout.addLayout(header_layout)
        self.layout.addSpacing(20)

        # Contenu principal (Row 2) : Colonne Graphiques (Gauche) et Listes (Droite)
        content_layout = QHBoxLayout()

        # Colonne de Gauche (Graphiques)
        left_column = QVBoxLayout()
        
        # 1. Graphique: Nombres d'Alertes (Graphique de distribution simulé)
        alert_chart_label = QLabel("Nombres d'Alertes")
        alert_chart_label.setFont(QFont("Arial", 14))
        left_column.addWidget(alert_chart_label)

        # Utilisation de PlotWidget pour le graphique
        self.alert_chart = PlotWidget()
        self.alert_chart.setMinimumHeight(200)
        self.alert_chart.hideAxis('left')
        self.alert_chart.hideAxis('bottom')
        left_column.addWidget(self.alert_chart)

        # 2. Graphique: Nombres d'alertes par heures (Histogramme)
        hourly_chart_label = QLabel("Nombres d'alertes par heures")
        hourly_chart_label.setFont(QFont("Arial", 14))
        left_column.addWidget(hourly_chart_label)
        
        self.hourly_chart = PlotWidget()
        self.hourly_chart.setMinimumHeight(200)
        left_column.addWidget(self.hourly_chart)
        
        content_layout.addLayout(left_column, 2)
        content_layout.addSpacing(30)

        # Colonne de Droite (Listes)
        right_column = QVBoxLayout()
        
        # 1. Liste des équipements en alerte
        right_column.addWidget(QLabel("Liste équipement remontant les alertes"))
        self.alerting_devices_list = CustomListWidget()
        right_column.addWidget(self.alerting_devices_list)

        right_column.addSpacing(20)
        
        # 2. Liste totale des équipements surveillés
        right_column.addWidget(QLabel("Total liste équipements qui remonte sur le snmp"))
        self.snmp_devices_list = CustomListWidget()
        right_column.addWidget(self.snmp_devices_list)

        content_layout.addLayout(right_column, 1)

        self.layout.addLayout(content_layout)
        self.layout.addStretch(1)
        
        # Chargement initial des données mockées pour l'affichage
        self.load_data()

    def load_data(self):
        """Charge les données mockées (simulées) pour le Dashboard."""
        
        # Données statiques pour le prototype
        data = {
            "alerting_devices": ["DESKTOP-WINHEPIS12", "PC-Louis", "PC-Audric"],
            "snmp_devices": ["PC-Audric", "PC-Eliot", "PC-Louis", "SRV-BDD-01", "RTR-CORE-05"],
            "hourly_alerts": [
                {"hour": 0, "count": 1},
                {"hour": 2, "count": 2},
                {"hour": 4, "count": 4},
                {"hour": 6, "count": 6},
                {"hour": 8, "count": 5},
                {"hour": 10, "count": 3},
                {"hour": 12, "count": 2},
                {"hour": 14, "count": 1},
            ],
            "alert_counts": [
                {"category": "Critical", "count": 15},
                {"category": "Major", "count": 8},
                {"category": "Minor", "count": 4},
                {"category": "Info", "count": 2}
            ]
        }
        
        # Envoie les données mockées pour la mise à jour de l'interface utilisateur
        QApplication.instance().postEvent(self, DashboardDataEvent(data))


    def customEvent(self, event):
        """Gère les événements personnalisés de réception de données."""
        if isinstance(event, DashboardDataEvent):
            self.update_ui(event.data)
            
    def update_ui(self, data):
        """Met à jour les widgets du Dashboard avec les données reçues."""
        
        # 1. Mise à jour de la liste des équipements en alerte
        self.alerting_devices_list.clear()
        for device in data.get('alerting_devices', []):
            QListWidgetItem(device, self.alerting_devices_list)

        # 2. Mise à jour de la liste totale des équipements SNMP
        self.snmp_devices_list.clear()
        for device in data.get('snmp_devices', []):
            QListWidgetItem(device, self.snmp_devices_list)

        # 3. Mise à jour du graphique des alertes par heure (Histogramme)
        hourly_data = data.get('hourly_alerts', [])
        hours = [item['hour'] for item in hourly_data]
        counts = [item['count'] for item in hourly_data]
        
        self.hourly_chart.clear()
        
        # Création et ajout de l'histogramme
        bg = BarGraphItem(x=hours, height=counts, width=1.0, brush='#3AA9E8') 
        self.hourly_chart.addItem(bg)
        
        # Configuration des axes
        self.hourly_chart.getAxis('bottom').setLabel('Heures')
        self.hourly_chart.getAxis('left').setLabel('Nombres d\'alertes')
        if hours:
             self.hourly_chart.setXRange(min(hours) - 1, max(hours) + 1)
        
        # 4. Mise à jour du graphique des nombres d'alertes (Simulé)
        alert_data = data.get('alert_counts', [])
        
        alert_categories = [item['category'] for item in alert_data]
        alert_counts = [item['count'] for item in alert_data]
        x_ticks = list(range(len(alert_categories))) 

        self.alert_chart.clear()
        # Simulation d'un graphique de répartition
        bg_donut = BarGraphItem(x=x_ticks, height=alert_counts, width=0.8, brushes=['#3AA9E8', '#2D8BCF', '#1F6BB5', '#104A9B'])
        self.alert_chart.addItem(bg_donut)

        # Configuration des axes avec les catégories d'alerte
        self.alert_chart.getAxis('bottom').setTicks([[(i, category) for i, category in enumerate(alert_categories)]])
        self.alert_chart.getAxis('bottom').setLabel('Catégorie d\'alerte')
        self.alert_chart.getAxis('left').show()
        

class FramesView(QWidget):
    """Vue de l'envoi de trames : Permet d'envoyer des requêtes SNMP (GET/SET/etc.) (Image 2)."""
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        # Marges et espacements de la vue
        layout.setContentsMargins(20, 20, 20, 20) 

        title_label = QLabel("Trames")
        title_label.setFont(QFont("Arial", 24, QFont.Bold))
        layout.addWidget(title_label)
        layout.addSpacing(15)

        # Conteneur du formulaire
        form_frame = QFrame()
        form_layout = QGridLayout(form_frame)
        form_layout.setAlignment(Qt.AlignTop) 
        form_frame.setStyleSheet("QFrame { background-color: #EFEFEF; border-radius: 10px; padding: 20px; }")

        # Configuration de la grille du formulaire
        form_layout.setHorizontalSpacing(10)
        form_layout.setVerticalSpacing(8)
        form_layout.setContentsMargins(10, 10, 10, 10) 
        
        # Dictionnaire pour stocker les champs du formulaire
        self.fields = {}
        
        # --- Champ 1 : Type de trame (Menu Déroulant) ---
        frame_type_combobox = QComboBox()
        frame_type_combobox.addItems(["GET", "GETNEXT", "GETBULK", "SET", "TRAP", "INFORM"]) 
        frame_type_combobox.setStyleSheet("QComboBox { background-color: white; border: 1px solid #CCC; border-radius: 4px; padding: 5px; min-height: 30px; }")
        # Connexion pour activer/désactiver le champ SET
        frame_type_combobox.currentIndexChanged.connect(self.toggle_set_value_field)
        self.fields["type"] = frame_type_combobox
        
        # --- Champ 2 : Adresse Source ---
        source_ip_input = QLineEdit()
        source_ip_input.setText(DEFAULT_SOURCE_IP) 
        source_ip_input.setPlaceholderText("IP source (par défaut: IP locale)")
        source_ip_input.setStyleSheet("QLineEdit { background-color: white; border: 1px solid #CCC; border-radius: 4px; padding: 5px; min-height: 30px; }")
        self.fields["source_ip"] = source_ip_input

        # Champs 3 à 6 (LineEdit)
        self.fields["community"] = QLineEdit()
        self.fields["target_ip"] = QLineEdit()
        self.fields["oid"] = QLineEdit()
        self.fields["set_value"] = QLineEdit() # Champ pour la valeur SET
        
        # Organisation des champs dans la grille
        form_inputs = [
            ("Type de trame :", self.fields["type"]),
            ("Adresse Source :", self.fields["source_ip"]),
            ("Communauté :", self.fields["community"]),
            ("Adresse Cible :", self.fields["target_ip"]),
            ("OID :", self.fields["oid"]),
            ("Valeur SET Uniquement :", self.fields["set_value"]),
        ]

        for i, (label_text, input_widget) in enumerate(form_inputs):
            label = QLabel(label_text)
            label.setAlignment(Qt.AlignRight | Qt.AlignVCenter) 
            
            if isinstance(input_widget, QLineEdit) or isinstance(input_widget, QComboBox):
                input_widget.setMinimumHeight(30)
                input_widget.setStyleSheet("QLineEdit, QComboBox { background-color: white; border: 1px solid #CCC; border-radius: 4px; padding: 5px; }")
                if isinstance(input_widget, QLineEdit):
                    input_widget.setPlaceholderText("Entrez la valeur...")

            # Désactive le champ SET par défaut
            if label_text == "Valeur SET Uniquement :":
                input_widget.setEnabled(False) 
                
            form_layout.addWidget(label, i, 0)
            form_layout.addWidget(input_widget, i, 1)
            
            # La colonne 0 (Labels) prend la place minimale, la colonne 1 (Inputs) s'étire
            form_layout.setColumnStretch(0, 0) 
            form_layout.setColumnStretch(1, 1) 

        # Bouton d'envoi
        send_btn = QPushButton("Envoyer la trame")
        send_btn.setStyleSheet("QPushButton { background-color: #3AA9E8; color: white; border-radius: 5px; padding: 10px 20px; }"
                               "QPushButton:hover { background-color: #308DCF; }")
        send_btn.setFixedSize(150, 40)
        send_btn.clicked.connect(self.send_frame)
        form_layout.addWidget(send_btn, len(form_inputs), 1, Qt.AlignRight)
        
        layout.addWidget(form_frame)
        layout.addSpacing(20)

        # Zone de retour de trame (Console)
        self.return_area = QLabel(
            "Indication de la trame est envoyée\nRetour de la cible"
        )
        self.return_area.setAlignment(Qt.AlignCenter)
        self.return_area.setMinimumHeight(150)
        self.return_area.setStyleSheet(
            "QLabel { background-color: #3AA9E8; color: white; border-radius: 10px; padding: 20px; font-size: 12pt; }"
        )
        layout.addWidget(self.return_area)

        layout.addStretch(1)

    def toggle_set_value_field(self, index):
        """Active/désactive le champ de valeur SET selon le type de trame sélectionné."""
        selected_type = self.fields["type"].currentText()
        if selected_type == "SET":
            self.fields["set_value"].setEnabled(True)
            self.fields["set_value"].setPlaceholderText("VALEUR OBLIGATOIRE pour SET")
        else:
            self.fields["set_value"].setEnabled(False)
            self.fields["set_value"].clear()
            self.fields["set_value"].setPlaceholderText("Entrez la valeur...")


    def send_frame(self):
        """Simule la logique d'envoi de la trame SNMP et affiche un résultat."""
        
        # Récupération des données du formulaire
        data = {
            "type": self.fields["type"].currentText(),
            "source_ip": self.fields["source_ip"].text(),
            "community": self.fields["community"].text(),
            "target_ip": self.fields["target_ip"].text(),
            "oid": self.fields["oid"].text(),
            "set_value": self.fields["set_value"].text() if self.fields["set_value"].isEnabled() else "N/A"
        }
        
        # Validation minimale des champs requis
        required_fields = ["community", "target_ip", "oid"]
        if data["type"] == "SET":
            required_fields.append("set_value")

        if not all(data.get(key) for key in required_fields):
             self.return_area.setText("ERREUR: Veuillez remplir tous les champs obligatoires.")
             return

        # Simulation du résultat de l'envoi
        message = (
            f"Statut: SUCCESS\n"
            f"Trame {data['type']} envoyée à {data['target_ip']}.\n\n"
            f"OID interrogé: {data['oid']}\n"
            f"Valeur simulée reçue: 'System Description - V1.0'"
        )

        # Affiche le résultat dans la zone de retour
        QApplication.instance().postEvent(self, FrameResultEvent(message))


    def customEvent(self, event):
        """Gère l'événement de réception du résultat d'envoi de trame."""
        if isinstance(event, FrameResultEvent):
            self.return_area.setText(event.message)


class ConfigView(QWidget):
    """Vue de la Configuration : Gère la liste des équipements SNMP surveillés (Image 3)."""
    
    # Données statiques/mockées en mémoire pour le prototype
    mock_servers = [
        {"id": 1, "ip": "192.168.1.1", "port": 161, "community": "beziers"},
        {"id": 2, "ip": "10.0.0.50", "port": 161, "community": "public"},
        {"id": 3, "ip": "172.16.0.1", "port": 162, "community": "private"}
    ]
    next_id = 4 # Compteur d'ID pour les nouveaux serveurs

    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20) 
        
        # État de l'édition et message de statut
        self.server_to_edit_id = None
        self.status_message = QLabel("") 

        title_label = QLabel("Configuration des Serveurs SNMP")
        title_label.setFont(QFont("Arial", 24, QFont.Bold))
        self.layout.addWidget(title_label)
        self.layout.addSpacing(15)

        # Zone de défilement pour la liste des serveurs configurés
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setMinimumHeight(200) 
        self.servers_container = QWidget()
        self.servers_layout = QVBoxLayout(self.servers_container)
        self.servers_layout.setAlignment(Qt.AlignTop)
        self.servers_container.setStyleSheet("QWidget { background-color: #EFEFEF; border-radius: 10px; padding: 20px; }")
        scroll_area.setWidget(self.servers_container)
        self.layout.addWidget(scroll_area)
        
        self.layout.addSpacing(15)

        # Formulaire d'ajout/modification
        self.ip_input = QLineEdit()
        self.port_input = QLineEdit()
        self.port_input.setText("161")
        self.community_input = QLineEdit()
        
        self.add_server_frame = QFrame()
        self.add_server_frame.setStyleSheet("QFrame { background-color: #E0E0E0; border-radius: 10px; padding: 20px; }")
        add_layout = QGridLayout(self.add_server_frame)
        add_layout.setContentsMargins(10, 10, 10, 10)
        add_layout.setSpacing(10)
        add_layout.setAlignment(Qt.AlignTop) 

        # Ajout des champs du formulaire dans la grille
        inputs = [("IP :", self.ip_input), ("Port :", self.port_input), ("Communauté :", self.community_input)]
        for i, (label_text, input_widget) in enumerate(inputs):
             label = QLabel(label_text)
             label.setAlignment(Qt.AlignRight | Qt.AlignVCenter) 
             input_widget.setMinimumHeight(30)
             input_widget.setStyleSheet("QLineEdit { background-color: white; border: 1px solid #CCC; border-radius: 4px; padding: 5px; }")
             add_layout.addWidget(label, i, 0)
             add_layout.addWidget(input_widget, i, 1)

        # Configuration d'étirement de la grille (les inputs s'étirent)
        add_layout.setColumnStretch(0, 0)
        add_layout.setColumnStretch(1, 1)
        
        # Message de statut (erreurs, succès, infos)
        self.status_message.setStyleSheet("QLabel { color: red; font-weight: bold; }")
        self.status_message.setMinimumHeight(20) # Maintient la hauteur pour éviter les décalages (anti-saut de mise en page)
        
        # Ajout du message de statut dans sa propre ligne
        add_layout.addWidget(self.status_message, len(inputs), 0, 1, 2)

        # Bouton principal (Ajouter/Enregistrer)
        self.save_btn = QPushButton("Ajouter un serveur")
        self.save_btn.setStyleSheet("QPushButton { background-color: #3AA9E8; color: white; border-radius: 5px; padding: 10px 20px; }"
                              "QPushButton:hover { background-color: #308DCF; }")
        self.save_btn.setFixedSize(150, 40)
        self.save_btn.clicked.connect(self.save_server)

        # Bouton d'annulation (mode édition)
        self.cancel_btn = QPushButton("Annuler l'édition")
        self.cancel_btn.setFixedSize(150, 40)
        self.cancel_btn.setStyleSheet("QPushButton { background-color: #AAAAAA; color: white; border-radius: 5px; padding: 10px 20px; }"
                                      "QPushButton:hover { background-color: #888888; }")
        self.cancel_btn.clicked.connect(self.reset_form)
        self.cancel_btn.setVisible(False)

        # Layout des boutons d'action (Alignés à droite)
        button_layout = QHBoxLayout()
        button_layout.addStretch(1)
        button_layout.addWidget(self.cancel_btn)
        button_layout.addWidget(self.save_btn)
        
        # Placement des boutons sous le message de statut
        add_layout.addLayout(button_layout, len(inputs) + 1, 1)
        
        self.layout.addWidget(self.add_server_frame)
        self.layout.addStretch(1)
        
        # Chargement initial des serveurs mockés
        self.load_servers()

    def load_servers(self):
        """Charge la liste des serveurs à partir de la source (mockée pour l'instant)."""
        QApplication.instance().postEvent(self, ConfigServersEvent(self.mock_servers))

    def reset_form(self, clear_status=True):
        """Réinitialise les champs du formulaire et revient au mode 'Ajout'."""
        self.ip_input.clear()
        self.port_input.setText("161")
        self.community_input.clear()
        self.server_to_edit_id = None
        self.save_btn.setText("Ajouter un serveur")
        self.cancel_btn.setVisible(False)
        # Réinitialisation du style du bouton
        self.save_btn.setStyleSheet("QPushButton { background-color: #3AA9E8; color: white; border-radius: 5px; padding: 10px 20px; }"
                              "QPushButton:hover { background-color: #308DCF; }")
        if clear_status:
            self.status_message.clear()

    def save_server(self):
        """Gère l'ajout (Insert) ou la modification (Update) d'un serveur (logique UPSERT simulée)."""
        
        ip = self.ip_input.text()
        port_text = self.port_input.text()
        community = self.community_input.text()
        
        # Validation des champs
        if not ip or not port_text or not community:
            self.status_message.setText("ERREUR: Tous les champs (IP, Port, Communauté) sont obligatoires.")
            self.status_message.setStyleSheet("QLabel { color: red; font-weight: bold; }")
            return
        
        try:
            port = int(port_text)
        except ValueError:
            self.status_message.setText("ERREUR: Le port doit être un nombre entier.")
            self.status_message.setStyleSheet("QLabel { color: red; font-weight: bold; }")
            return
        
        # Logique d'UPDATE (Modification)
        if self.server_to_edit_id is not None:
            found = False
            for server in self.mock_servers:
                if server.get('id') == self.server_to_edit_id:
                    server['ip'] = ip
                    server['port'] = port
                    server['community'] = community
                    found = True
                    break
            
            if found:
                success_msg = f"SUCCESS: Serveur ID {self.server_to_edit_id} modifié."
                QApplication.instance().postEvent(self, ConfigStatusEvent(success_msg, "green"))
            else:
                success_msg = f"ERREUR: Serveur ID {self.server_to_edit_id} non trouvé pour modification."
                QApplication.instance().postEvent(self, ConfigStatusEvent(success_msg, "red"))

        # Logique d'INSERT (Ajout)
        else:
            new_server = {"id": self.next_id, "ip": ip, "port": port, "community": community}
            self.mock_servers.append(new_server)
            ConfigView.next_id += 1
            
            success_msg = f"SUCCESS: Serveur {ip}:{port} ajouté."
            QApplication.instance().postEvent(self, ConfigStatusEvent(success_msg, "green"))
            
        # Réinitialisation et rechargement
        self.reset_form(clear_status=False)
        self.load_servers()


    def delete_server(self, server_id):
        """Simule la suppression d'un serveur par ID."""
        initial_count = len(self.mock_servers)
        
        # Filtrage pour supprimer l'élément
        self.mock_servers[:] = [s for s in self.mock_servers if s.get('id') != server_id]
        
        # Gestion du mode édition si le serveur supprimé était en cours d'édition
        if self.server_to_edit_id == server_id:
            self.reset_form(clear_status=False)

        if len(self.mock_servers) < initial_count:
            success_msg = f"SUCCESS: Serveur ID {server_id} supprimé."
            QApplication.instance().postEvent(self, ConfigStatusEvent(success_msg, "darkred"))
        else:
            error_msg = f"ERREUR: Serveur ID {server_id} non trouvé."
            QApplication.instance().postEvent(self, ConfigStatusEvent(error_msg, "red"))
            
        self.load_servers()

    def edit_server(self, server_id):
        """Charge les données du serveur dans le formulaire et active le mode édition."""
        server_to_edit = next((s for s in self.mock_servers if s.get('id') == server_id), None)
        
        if server_to_edit:
            # 1. Active le mode édition
            self.server_to_edit_id = server_id
            
            # 2. Charge les données
            self.ip_input.setText(server_to_edit['ip'])
            self.port_input.setText(str(server_to_edit['port']))
            self.community_input.setText(server_to_edit['community'])
            
            # 3. Mise à jour de l'UI pour le mode édition
            self.save_btn.setText(f"Enregistrer ID {server_id}")
            self.save_btn.setStyleSheet("QPushButton { background-color: orange; color: white; border-radius: 5px; padding: 10px 20px; }"
                                        "QPushButton:hover { background-color: darkorange; }")
            self.cancel_btn.setVisible(True)
            
            info_msg = f"INFO: Serveur ID {server_id} chargé. Cliquez sur 'Enregistrer ID {server_id}' pour confirmer la modification."
            QApplication.instance().postEvent(self, ConfigStatusEvent(info_msg, "orange"))
            
        else:
            error_msg = f"ERREUR: Serveur ID {server_id} non trouvé pour modification."
            QApplication.instance().postEvent(self, ConfigStatusEvent(error_msg, "red"))


    def customEvent(self, event):
        """Gère les événements personnalisés de réception des données/statut."""
        if isinstance(event, ConfigServersEvent):
            self.update_servers_ui(event.data)
        elif isinstance(event, ConfigStatusEvent):
            self.status_message.setText(event.message)
            self.status_message.setStyleSheet(f"QLabel {{ color: {event.color}; font-weight: bold; }}")

    def update_servers_ui(self, servers: List[Dict[str, Any]]):
        """Met à jour l'affichage de la liste des serveurs configurés."""
        # Nettoyage du conteneur
        while self.servers_layout.count():
            item = self.servers_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        if not servers:
            empty_label = QLabel("Aucun serveur configuré. Veuillez en ajouter un.")
            empty_label.setAlignment(Qt.AlignCenter)
            self.servers_layout.addWidget(empty_label)
            return

        # Ajout d'un widget par serveur
        for i, server in enumerate(servers):
            server_frame = QFrame()
            server_frame.setFrameShape(QFrame.StyledPanel)
            # Alternance de couleurs pour la lisibilité
            bg_color = "#FFFFFF" if i % 2 == 0 else "#F8F8F8"
            server_frame.setStyleSheet(f"QFrame {{ background-color: {bg_color}; border: 1px solid #CCC; border-radius: 5px; padding: 10px; margin-bottom: 10px; }}")
            
            server_layout = QGridLayout(server_frame)
            
            # Titre du serveur (ex: Serveur 1 : (ID: 1))
            title_label = QLabel(f"Serveur {i+1} : (ID: {server.get('id', 'N/A')})") 
            title_label.setFont(QFont("Arial", 12, QFont.Bold))
            
            # Conteneur des boutons Modifier/Supprimer
            button_container = QHBoxLayout()
            button_container.setSpacing(5)

            edit_btn = QPushButton("Modifier")
            edit_btn.setStyleSheet("QPushButton { background-color: orange; color: white; border-radius: 5px; padding: 5px 10px; }"
                                   "QPushButton:hover { background-color: darkorange; }")
            edit_btn.clicked.connect(lambda checked, id=server.get('id'): self.edit_server(id))
            button_container.addWidget(edit_btn)

            delete_btn = QPushButton("Supprimer")
            delete_btn.setStyleSheet("QPushButton { background-color: #C0392B; color: white; border-radius: 5px; padding: 5px 10px; }"
                                     "QPushButton:hover { background-color: #A93226; }")
            delete_btn.clicked.connect(lambda checked, id=server.get('id'): self.delete_server(id))
            button_container.addWidget(delete_btn)
            
            # Ligne 0 : Titre à gauche (colonne 0) et Boutons à droite (colonne 1)
            server_layout.addWidget(title_label, 0, 0, 1, 1)
            server_layout.addLayout(button_container, 0, 1, 1, 1, Qt.AlignRight | Qt.AlignTop)
            
            server_layout.setColumnStretch(0, 1) # Titre s'étire
            server_layout.setColumnStretch(1, 0) # Boutons fixes

            # Ligne 1 : Informations IP, Port, Communauté (Affichage compact)
            
            data_labels = [
                ("IP :", server.get('ip', 'N/A')), 
                ("Port :", str(server.get('port', 'N/A'))), 
                ("Communauté :", server.get('community', 'N/A'))
            ]
            
            info_layout = QHBoxLayout()
            info_layout.setSpacing(10)

            for label, value in data_labels:
                 block_layout = QHBoxLayout()
                 block_layout.setSpacing(5)
                 
                 label_widget = QLabel(f"<b>{label}</b>")
                 value_label = QLabel(value)
                 
                 block_layout.addWidget(label_widget)
                 block_layout.addWidget(value_label)
                 block_layout.addStretch(1)

                 info_layout.addLayout(block_layout, 1)
            
            info_layout.addStretch(10)

            # Ajout du layout d'informations
            server_layout.addLayout(info_layout, 1, 0, 1, 2)
            
            self.servers_layout.addWidget(server_frame)


# --- CLASSE PRINCIPALE FENÊTRE ---

class MainApplication(QMainWindow):
    """Fenêtre principale de l'application : Contient la navigation et les vues."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gestionnaire SNMP v2c")
        self.setGeometry(100, 100, 1000, 700)
        
        # Style de base pour l'application
        self.setStyleSheet("""
            QMainWindow { background-color: #F0F0F0; }
            QWidget { color: #333; }
        """)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # --- Panneau de Navigation (Gauche) ---
        self.nav_panel = QFrame()
        self.nav_panel.setFixedWidth(150)
        self.nav_panel.setStyleSheet("QFrame { background-color: #E0E0E0; border-right: 2px solid #D0D0D0; }")
        
        nav_layout = QVBoxLayout(self.nav_panel)
        nav_layout.setContentsMargins(0, 20, 0, 10)
        nav_layout.setSpacing(10)
        
        # Conteneur des vues
        self.page_stack = QStackedWidget()
        
        # Création des boutons de navigation et connexion
        self.nav_buttons = {}
        for text in ["SNMP", "TRAMES", "CONFIG"]:
            btn = QPushButton(text)
            btn.setCheckable(True)
            btn.setFont(QFont("Arial", 12, QFont.Bold))
            btn.setStyleSheet(self._get_nav_button_style())
            btn.clicked.connect(lambda checked, t=text: self.switch_page(t))
            self.nav_buttons[text] = btn
            nav_layout.addWidget(btn)

        # Création et ajout des vues principales
        self.dashboard_view = DashboardView()
        self.frames_view = FramesView()
        self.config_view = ConfigView()
        
        self.page_stack.addWidget(self.dashboard_view) # Index 0 : SNMP (Dashboard)
        self.page_stack.addWidget(self.frames_view)    # Index 1 : TRAMES
        self.page_stack.addWidget(self.config_view)    # Index 2 : CONFIG

        # Espace flexible et icône utilisateur
        nav_layout.addStretch(1)
                
        user_icon = QLabel("👤")
        user_icon.setFont(QFont("Arial", 28))
        user_icon.setAlignment(Qt.AlignCenter)
        user_icon.setFixedSize(40, 40)
        user_icon.setStyleSheet("QLabel { background-color: #F5A9A9; border-radius: 20px; border: 2px solid #B0B0B0; }")
        
        user_container = QHBoxLayout()
        user_container.addStretch(1)
        user_container.addWidget(user_icon)
        user_container.addStretch(1)
        
        nav_layout.addLayout(user_container)
        nav_layout.addSpacing(10)

        main_layout.addWidget(self.nav_panel)
        main_layout.addWidget(self.page_stack)

        # Initialisation de la vue par défaut
        self.switch_page("SNMP")

    def _get_nav_button_style(self):
        """Définit la feuille de style pour les boutons de navigation (effet actif/inactif)."""
        return """
            QPushButton {
                background-color: transparent;
                border: none;
                text-align: left;
                padding: 10px 15px;
                color: #555;
            }
            QPushButton:hover {
                background-color: #D0D0D0;
            }
            QPushButton:checked {
                background-color: #F0F0F0; /* Correspond à l'arrière-plan du contenu */
                border-left: 5px solid #F5A9A9; /* Barre latérale rose */
                color: #333;
            }
        """

    def switch_page(self, page_name):
        """Change la vue principale et met à jour l'état des boutons de navigation."""
        index_map = {"SNMP": 0, "TRAMES": 1, "CONFIG": 2}
        if page_name in index_map:
            self.page_stack.setCurrentIndex(index_map[page_name])
            
            # Met à jour l'état visuel du bouton actif
            for name, btn in self.nav_buttons.items():
                btn.setChecked(name == page_name)
            
            # Recharge les données mockées lors du changement d'onglet
            if page_name == "SNMP":
                 self.dashboard_view.load_data()
            if page_name == "CONFIG":
                 self.config_view.load_servers()


def main():
    """Point d'entrée principal de l'application graphique."""
    app = QApplication(sys.argv)
    
    # Configuration globale de la police
    app_font = QFont("Arial")
    app_font.setPointSize(10)
    app.setFont(app_font)

    main_window = MainApplication()
    main_window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()