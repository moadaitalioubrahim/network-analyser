from scapy.all import *
import time

ip_attempts = {}
SEUIL_ALERTE = 5 
FENETRE_TEMPS = 10 

def detecter_force_brute(packet):
    if packet.haslayer(TCP):
        if packet[TCP].dport == 22 and packet[TCP].flags == "S":
            ip_source = packet[IP].src
            temps_actuel = time.time()
            
            if ip_source not in ip_attempts:
                ip_attempts[ip_source] = []
            
            ip_attempts[ip_source].append(temps_actuel)
            
            ip_attempts[ip_source] = [t for t in ip_attempts[ip_source] if temps_actuel - t < FENETRE_TEMPS]
            
            if len(ip_attempts[ip_source]) >= SEUIL_ALERTE:
                print(f"⚠️ ALERTE : Attaque par force brute détectée depuis {ip_source} !")
                ip_attempts[ip_source] = []

def demarrer_analyse():
    print("🔍 Démarrage de l'analyseur de trafic réseau...")
    print("En attente de tentatives de connexion SSH (port 22)...")
    sniff(filter="tcp", prn=detecter_force_brute, store=0)

if __name__ == "__main__":
    demarrer_analyse()
