# 🔎 portBscanner

**portBscanner** est un outil développé en Python par **Mouad Benyaya** qui permet de scanner les ports d’un hôte spécifié pour détecter s’ils sont **ouverts**, **fermés** ou **filtrés**. Il est compatible avec **Windows et Linux**, et utilise des techniques avancées pour l’analyse des ports, tout en offrant une interface simple à utiliser.

⚠️ **ATTENTION : Cet outil est à usage éducatif uniquement. Son utilisation sur des systèmes sans autorisation explicite est illégale.**

---

## ⚙️ Fonctionnalités principales

- 🔀 **Types de Scan disponibles :**
  - TCP Connect (classique)
  - UDP Scan
  - SYN Scan ("furtif")
- 📡 **Détection de Services :**
  - Identification des services via "banner grabbing"
  - Vérification simple de vulnérabilités potentielles *(à définir selon l’implémentation)*
- 🧐 **Scan Approfondi (Deep Scan) :**
  - Analyse tous les ports (1-65535) avec différentes méthodes
- ⚡ **Multithreading :**
  - Utilise `ThreadPoolExecutor` pour accélérer le scan
- 🌯️ **Personnalisation complète :**
  - Cible, plage de ports, méthode de scan, timeout, nombre de threads...
- 📀 **Résultats clairs et exportables :**
  - Affichage coloré des ports ouverts/services
  - Possibilité d’afficher les ports fermés
  - Export en **TXT**, **JSON** ou **CSV** *(si activé)*

---

## 🧰 Prérequis

- Python 3.6 ou plus
- pip
- Git
- **Droits administrateur/root** pour certains scans (ex: SYN ou UDP avec raw sockets)

---

## 📅 Installation

```bash
git clone https://github.com/Mouadbenyaya/port-Bscanner.git
cd port-Bscanner
```

### (Optionnel) Créer un environnement virtuel :
```bash
python -m venv venv
# Windows :
.\venv\Scripts\activate
# Linux/macOS :
source venv/bin/activate
```

### Installer les dépendances :
```bash
pip install -r requirements.txt
```

---

## 🚀 Utilisation

### Mode interactif :

```bash
# Windows
python main.py

# Linux (si besoin de privilèges)
sudo python3 main.py
```

## 🛑 Avertissement Légal

Cet outil ne doit être utilisé que **sur des réseaux/systèmes pour lesquels vous avez une autorisation explicite**. Tout usage non autorisé est illégal et l’auteur décline toute responsabilité en cas de mauvaise utilisation.

---

## 👨‍💻 Auteur

- **Mouad Benyaya** – Développeur principal  
  🔗 GitHub : [Mouadbenyaya](https://github.com/Mouadbenyaya)