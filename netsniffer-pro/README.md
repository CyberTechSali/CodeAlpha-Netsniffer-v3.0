# 🛡️ NetSniffer Pro

<p>
  <img src="netsniffer/assets/icon.png" width="96" align="right" alt="NetSniffer Pro logo">
</p>

**Analyseur de trafic réseau moderne — GUI (CustomTkinter) et CLI, même
cœur applicatif.** Réalisé dans le cadre du stage cybersécurité CodeAlpha
(Task 1) par **Ouchahed Salma** ([@cybertechsali](https://github.com/cybertechsali)).

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)](#installation)
[![Scapy](https://img.shields.io/badge/engine-Scapy-orange)](https://scapy.net/)

---

## Sommaire

- [Aperçu](#aperçu)
- [Fonctionnalités](#fonctionnalités)
- [Installation](#installation)
- [Lancer l'application (mode développement)](#lancer-lapplication-mode-développement)
- [Version CLI (terminal, sans GUI)](#version-cli-terminal-sans-gui)
- [Packaging binaire + lancement sans sudo](#packaging-binaire--lancement-sans-sudo)
- [Lancer les tests](#lancer-les-tests)
- [Architecture](#architecture)
- [Logo / icône de l'application](#logo--icône-de-lapplication)
- [Roadmap](#pas-encore-fait-prochaines-étapes-suggérées)
- [Licence](#licence)

## Aperçu

<!--
  Remplacer par un vrai screenshot/GIF une fois hébergé (voir la section
  "présenter ce repo sur GitHub" fournie par l'assistant) :
  ![Capture d'écran de la GUI](docs/screenshot-gui.png)
  ![Démo de la CLI](docs/demo-cli.gif)
-->

| GUI (CustomTkinter) | CLI (terminal) |
|---|---|
| Tableau de paquets en direct, dashboard de stats, graphiques temps réel, mini-IDS | Même moteur de capture, sortie colorée en direct, export CSV/PCAP, bannière d'accueil |

## Fonctionnalités

- 🔴 Capture live multi-interface (scapy `AsyncSniffer`)
- 🧠 Classification multi-protocole (TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS/TLS via SNI, SSH via bannière)
- 🔎 Filtres BPF combinables (presets + expression libre : `tcp and port 443`, `arp or icmp`, ...)
- 📊 Dashboard de statistiques + graphiques temps réel (GUI)
- 🕵️ Mini-IDS heuristique : détection de scan de ports et d'ARP spoofing
- 🔬 Analyse de payload : hex dump, décodage UTF-8, entropie de Shannon
- 💾 Export CSV et PCAP (compatible Wireshark)
- 🖥️ Deux façades, un seul cœur : GUI CustomTkinter *et* CLI terminal, zéro duplication de logique métier
- 🔓 Lancement sans `sudo` possible via `setcap` sur le binaire packagé (PyInstaller)

## Installation

```bash
pip install -r requirements.txt   # ou: pip install scapy customtkinter matplotlib pillow pytest pyinstaller
```

## Lancer l'application (mode développement)

```bash
sudo python3 main.py
```

(`sudo` est nécessaire car scapy ouvre un socket brut pour capturer les paquets.
En binaire packagé, voir la section suivante pour s'en passer.)

## Version CLI (terminal, sans GUI)

Même coeur applicatif que la GUI (`PacketCapture`, `classify_packet`,
`AlertEngine`, `SessionStats`, export CSV/PCAP) — `netsniffer/cli.py` est
juste une deuxième façade au-dessus, sans aucune dépendance Tkinter. Utile
pour un serveur headless, du scripting, ou juste tourner en SSH.

```bash
pip install rich       # optionnel : sortie live colorée (fallback texte simple sinon)
pip install pyfiglet   # optionnel : ASCII-art dans la bannière d'accueil (fallback cadre simple sinon)

sudo python3 main_cli.py --list-interfaces
sudo python3 main_cli.py -i eth0
sudo python3 main_cli.py -i eth0 -f "https/tls (port 443)"      # mêmes presets que la GUI
sudo python3 main_cli.py -i eth0 --bpf "tcp and port 22"        # BPF libre
sudo python3 main_cli.py -i eth0 -d 30 -o capture.pcap          # 30s puis export PCAP
sudo python3 main_cli.py -i eth0 -c 500 -o rapport.csv -q       # 500 paquets, silencieux, export CSV
sudo python3 main_cli.py -i eth0 -p                             # + hex dump/entropie du payload par paquet
sudo python3 main_cli.py -i eth0 --no-banner                    # sans la bannière d'accueil (scripting)
python3 main_cli.py --version
```

Au lancement, une bannière d'accueil (nom, logo ASCII, auteur, GitHub,
version, liste des fonctionnalités) s'affiche automatiquement — `--no-banner`
pour la désactiver dans un contexte scripté.

Ctrl+C arrête proprement la capture (comme le bouton Stop de la GUI) et
affiche le résumé de session (mêmes compteurs par protocole que le
dashboard). Options complètes : `python3 main_cli.py --help`.

Packaging binaire équivalent à la GUI (voir section suivante) :

```bash
pyinstaller netsniffer_cli.spec
sudo ./scripts/setcap_linux.sh dist/netsniffer-cli
dist/netsniffer-cli -i eth0    # sans sudo
```

## Packaging binaire + lancement sans sudo

Le binaire autonome (PyInstaller) peut recevoir directement les capabilities
Linux nécessaires à la capture (`cap_net_raw` + `cap_net_admin`, ce dernier
pour le mode promiscuous), au lieu de lancer toute l'appli avec `sudo` :

```bash
pip install pyinstaller
./scripts/build_linux.sh        # build + setcap en une commande (demande sudo une fois)
# ou, séparément :
pyinstaller netsniffer.spec
sudo ./scripts/setcap_linux.sh dist/netsniffer

# ensuite, n'importe quel utilisateur peut lancer le binaire sans sudo :
dist/netsniffer
```

Le `sudo` n'est requis qu'une seule fois, au moment du packaging, pour poser
les capabilities sur le fichier binaire (attribut étendu du système de
fichiers) — pas à chaque exécution. Voir les commentaires dans
`scripts/setcap_linux.sh` pour le détail (limites : `--onefile` uniquement,
capabilities perdues si le binaire est recopié/reconstruit sans repasser
`setcap`).

## Lancer les tests

```bash
PYTHONPATH=. pytest tests/ -v
```

Les tests portent sur la logique pure (`classifier.py`, `alerts.py`,
`payload.py`, `traffic_rate.py`), sans carte réseau ni interface graphique —
donc rapides et exécutables sans privilèges root. Le mini-IDS est testé avec
une horloge simulée (`FakeClock`), pour que les fenêtres temporelles
(scan de ports, cooldown d'alerte) soient déterministes.

## Architecture

```
netsniffer/
  config.py              # couleurs, filtres BPF, seuils IDS, limites UI — rien en dur ailleurs
  models.py               # dataclasses CapturedPacket / ClassificationResult / SessionStats / Alert
  logging_setup.py        # config du module logging (remplace les print())
  capture/
    classifier.py         # classification pure d'un paquet -> protocole (0 dépendance Tkinter)
                           #   dont reconnaissance SSH (bannière) et SNI TLS (ClientHello)
    alerts.py               # mini-IDS pur : détection scan de ports + ARP spoofing
    sniffer.py               # thread de capture scapy + queues thread-safe (paquets + alertes)
  analysis/
    payload.py               # hex dump, entropie, devinette de nature du payload (pur)
    traffic_rate.py           # bucketing paquets/seconde pour le graphique temps réel (pur)
  export/
    exporters.py                # export CSV / PCAP
  ui/
    app.py                      # la fenêtre principale (widgets + réactions aux événements)
    save_dialog.py               # dialogue de sauvegarde façon "dark mode"
main.py                          # point d'entrée
tests/                            # tests unitaires (paquets scapy synthétiques en mémoire)
```

## Ce qui a changé par rapport à la v1 (script unique)

- **Séparation capture / UI** : `PacketCapture` (dans `capture/sniffer.py`) ne connaît
  pas Tkinter. La classification (`classify_packet`) est une fonction pure testable.
- **Batching de l'UI** : les paquets sont poussés dans une `queue.Queue` par le thread
  de capture, et l'interface les vide toutes les `UI_FLUSH_INTERVAL_MS` (150 ms par
  défaut, voir `config.py`) au lieu d'un `after()` par paquet — ça évite de saturer
  la boucle Tkinter sur un trafic chargé.
- **Limite d'affichage** : le tableau (Treeview) est plafonné à `MAX_VISIBLE_ROWS`
  lignes visibles (5000 par défaut) ; tous les paquets restent en mémoire pour
  la recherche et l'export CSV/PCAP.
- **`CapturedPacket` (dataclass)** remplace les tuples positionnels `(num, time, src, ...)`.
- **Logging** structuré (`logging_setup.py`) au lieu de `print`, `messagebox` réservé
  aux messages utilisateur.
- **`AsyncSniffer`** au lieu d'un thread manuel autour de `sniff(stop_filter=...)` :
  `Stop` coupe immédiatement la capture au lieu d'attendre le paquet suivant.
- **Bug fixes** repris de la v1 : le filtre "tcp" garde désormais les paquets tagués
  `TCP` (au lieu d'être masqués sous HTTP/HTTPS) ; le compteur `Other` fonctionne.

## Nouveautés v3

- **Filtres BPF combinables** (`ui/app.py` : `bpf_entry`) : le menu déroulant de
  presets ne fait plus que pré-remplir un champ de texte librement éditable.
  On peut combiner à la main : `tcp and port 443`, `arp or icmp`,
  `port 22 or port 2222`, etc. — même syntaxe que le champ de capture de
  Wireshark. La validation se fait par libpcap au démarrage de la capture ;
  une expression invalide remonte dans la boîte de dialogue d'erreur existante.
- **Reconnaissance protocolaire au-delà du port** (`capture/classifier.py`) :
  - **SSH** est reconnu à sa bannière d'identification en clair (`SSH-2.0-...`),
    donc détecté même sur un port non standard (ex. 2222), pas seulement 22.
  - **SNI TLS** : le `ClientHello` (toujours en clair, avant chiffrement) est
    parsé pour en extraire le nom d'hôte demandé (extension `server_name`),
    affiché comme `TLS ClientHello -> SNI: example.com`. Fonctionne aussi sur
    un port TLS non standard (ex. 8443), puisque la détection se base sur le
    format du paquet et non sur le port.
- **Mini-IDS** (`capture/alerts.py`, onglet "🛡 Alerts") :
  - **Scan de ports** : alerte si une IP source touche un grand nombre de ports
    de destination distincts (`PORT_SCAN_DISTINCT_PORTS_THRESHOLD`, 15 par
    défaut) sur une fenêtre glissante courte (`PORT_SCAN_WINDOW_SECONDS`, 5 s).
  - **ARP spoofing** : alerte si une même IP est revendiquée ("is-at") par
    plusieurs adresses MAC différentes pendant la session.
  - Un cooldown par IP évite de noyer le journal d'alertes ; un badge dans la
    barre latérale résume l'état ("🛡 No alerts" / "⚠ N warning" / "🚨 N critical").
  - Reste un outil heuristique pédagogique, pas un remplaçant d'un vrai IDS
    (pas de suivi d'état TCP, pas de résistance à l'évasion).
- **Graphiques temps réel** (`analysis/traffic_rate.py`, onglet "📈 Charts") :
  un graphique paquets/seconde sur les 60 dernières secondes (`matplotlib`,
  intégré via `FigureCanvasTkAgg`) et un histogramme de répartition par
  protocole, tous deux redessinés à un rythme volontairement plus lent
  (`CHART_REDRAW_INTERVAL_MS`, 1 s) que le flux de paquets, et uniquement
  quand l'onglet est visible, pour ne pas alourdir l'UI.

## Logo / icône de l'application

`netsniffer/assets/icon.png` (512×512) et `icon.ico` (multi-résolution,
16 à 256 px) sont le logo bouclier bleu de l'app. `netsniffer/assets.py`
résout leur chemin aussi bien en lancement depuis les sources qu'une fois
figés dans le binaire PyInstaller (`sys._MEIPASS`). `ui/app.py` l'applique
comme icône de fenêtre/barre des tâches au démarrage (`iconbitmap` sur
Windows, `iconphoto` via Pillow ailleurs) ; `netsniffer.spec` l'embarque
aussi comme icône de l'exécutable Windows.

## Pas encore fait (prochaines étapes suggérées)

- Mode lecture d'un fichier PCAP existant (pas seulement capture live)
- Filtres BPF combinables *sauvegardables* (favoris nommés)
- Détection d'anomalies DNS (tunneling, requêtes à volume anormal)
- Mode interactif (REPL) pour la CLI

## Contribuer

Les PR sont bienvenues. Avant de proposer un changement :

```bash
pip install -r requirements.txt
PYTHONPATH=. pytest tests/ -v
```

Merci de garder la séparation logique métier / frontend (voir
[Architecture](#architecture)) : toute nouvelle fonctionnalité de capture,
classification ou export doit rester testable sans Tkinter.

## Licence

[MIT](LICENSE) © 2026 Ouchahed Salma
