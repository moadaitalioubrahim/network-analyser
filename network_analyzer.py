from scapy.all import *
import time

# Dictionnaire pour stocker les tentatives de connexion par adresse IP
# Format : { "192.168.1.10": [timestamp1, timestamp2, ...] }
ip_attempts = {}
SEUIL_ALERTE = 5 # Si une IP tente 5 connexions en moins de 10 secondes
FENETRE_TEMPS = 10 

def detecter_force_brute(packet):
    # On vérifie si le paquet est un paquet TCP (couche 4)
    if packet.haslayer(TCP):
        # On vérifie si c'est une tentative de connexion sur le port SSH (22)
        # Le flag "S" signifie SYN (début de connexion)
        if packet[TCP].dport == 22 and packet[TCP].flags == "S":
            ip_source = packet[IP].src
            temps_actuel = time.time()
            
            # Si on n'a jamais vu cette IP, on crée une liste vide
            if ip_source not in ip_attempts:
                ip_attempts[ip_source] = []
            
            # On ajoute le temps actuel à la liste de cette IP
            ip_attempts[ip_source].append(temps_actuel)
            
            # On nettoie les anciennes tentatives (plus vieilles que 10 secondes)
            ip_attempts[ip_source] = [t for t in ip_attempts[ip_source] if temps_actuel - t < FENETRE_TEMPS]
            
            # On vérifie si le nombre de tentatives dépasse le seuil
            if len(ip_attempts[ip_source]) >= SEUIL_ALERTE:
                print(f"⚠️ ALERTE : Attaque par force brute détectée depuis {ip_source} !")
                # On vide la liste pour ne pas spammer l'alerte
                ip_attempts[ip_source] = []

def demarrer_analyse():
    print("🔍 Démarrage de l'analyseur de trafic réseau...")
    print("En attente de tentatives de connexion SSH (port 22)...")
    # sniff() capture les paquets. prn= appelle notre fonction pour chaque paquet
    # store=0 évite de saturer la mémoire
    sniff(filter="tcp", prn=detecter_force_brute, store=0)

if __name__ == "__main__":
    demarrer_analyse()