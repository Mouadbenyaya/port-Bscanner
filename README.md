# portBscanner

**portBscanner** est un outil développé en Python par Mouad Benyaya qui permet de scanner les ports d'un hôte spécifié pour déterminer s'ils sont ouverts ou fermés. Ce projet utilise le module `socket` de Python pour les connexions et `ThreadPoolExecutor` pour une exécution parallèle rapide et efficace, tout en offrant des fonctionnalités de scan avancées.

**ATTENTION : Cet outil est destiné à des fins éducatives et à des tests de pénétration autorisés UNIQUEMENT. N'utilisez jamais cet outil sur des systèmes ou réseaux sans permission explicite. L'utilisation non autorisée est illégale.**

## Fonctionnalités principales

* **Types de Scan Multiples :**
    * Scan **TCP** Connect (standard)
    * Scan **UDP**
    * Scan **SYN** ("Stealth Scan" / furtif)
* **Détection de Services et Vulnérabilités :**
    * Tente d'identifier les services et leurs versions sur les ports ouverts ("Banner Grabbing").
    * Effectue une **vérification de vulnérabilités basiques** associées aux services détectés (si implémenté). *(Merci de préciser dans le code ou ici la nature exacte de cette vérification)*.
* **Scan Approfondi ("Deep Scan") :**
    * Permet des analyses plus poussées. *(Merci de préciser ici ce que fait le "deep scan" : scan de tous les ports 1-65535 ? combinaison de techniques ? options spécifiques ?)*.
* **Exécution parallèle :**
    * Utilise `ThreadPoolExecutor` pour scanner plusieurs ports simultanément, optimisant la vitesse.
* **Personnalisation :**
    * Choix de la cible (IP ou nom d'hôte), de la plage de ports, du type de scan, du timeout, du nombre de threads, etc.
* **Affichage et Export des Résultats :**
    * Affichage clair des ports ouverts, services, et potentiellement vulnérabilités.
    * Option pour afficher les ports fermés.
    * Possibilité d'exporter les résultats (ex: TXT, JSON, CSV - si implémenté). *(Confirmez si l'export est possible et les formats supportés)*.

## Prérequis

* Python 3 (version 3.6 ou supérieure recommandée)
* pip (le gestionnaire de paquets Python, généralement inclus avec Python 3)
* Git (pour cloner le code source)
* **Privilèges administrateur/root :** Nécessaires pour certains types de scans (ex: SYN scan, scans UDP nécessitant des raw sockets sur certains OS).

## Installation

1.  **Clonez ce dépôt sur votre machine locale :**
    ```bash
    git clone [https://github.com/Mouadbenyaya/port-Bscanner.git](https://github.com/Mouadbenyaya/port-Bscanner.git)
    ```

2.  **Naviguez dans le répertoire du projet :**
    ```bash
    cd portBscanner
    ```

3.  **(Recommandé) Créez et activez un environnement virtuel :**
    ```bash
    # Créer l'environnement
    python -m venv venv 
    # Activer (Linux/macOS)
    source venv/bin/activate
    # Activer (Windows CMD)
    # .\venv\Scripts\activate.bat
    # Activer (Windows PowerShell)
    # .\venv\Scripts\Activate.ps1
    ```

4.  **Installez les dépendances :**
    Vérifiez les `import` dans tous les fichiers `.py` de votre projet pour identifier les bibliothèques externes nécessaires (ex: `cryptography`, etc.).
    * **Méthode 1 (Préférée - si un fichier `requirements.txt` existe) :**
        ```bash
        pip install -r requirements.txt
        ```
        *(Assurez-vous que ce fichier liste toutes les dépendances externes)*
    * **Méthode 2 (Manuelle - si pas de `requirements.txt`) :**
        Installez les bibliothèques nécessaires une par une.
        ```bash
        # Exemple (adaptez selon les imports réels dans votre code !) :
        # pip install cryptography
        # pip install ... 
        ```
        *(Si aucune bibliothèque externe n'est utilisée, vous pouvez l'indiquer ou simplifier cette étape)*.

## Utilisation

Lancez le script `main.py` depuis le terminal, en étant dans le dossier `portBscanner`. **N'oubliez pas d'utiliser `sudo` (ou d'exécuter en tant qu'administrateur) si vous effectuez des scans nécessitant des privilèges élevés (comme SYN ou UDP).**

* **Mode Interactif (si supporté sans options) :**
    Si le script est conçu pour être interactif sans arguments :
    ```bash
    # Exécutez avec sudo si des scans privilégiés sont possibles en mode interactif
    sudo python main.py 
    ```
    *Note : Le script peut demander d'accepter les conditions d'utilisation au démarrage.*


## Avertissement Légal / Disclaimer

Ce projet est destiné uniquement à des fins éducatives et à des tests de pénétration légitimes. **N'utilisez cet outil que sur des réseaux et systèmes pour lesquels vous avez une autorisation explicite.** Scanner des réseaux sans permission est illégal et peut entraîner des poursuites judiciaires.

L'auteur de `port-Bscanner` décline toute responsabilité pour les dommages directs ou indirects causés par l'utilisation ou la mauvaise utilisation de ce logiciel. L'utilisateur assume l'entière responsabilité de ses actions et s'engage à utiliser cet outil conformément à toutes les lois applicables.

## Auteur

* **Mouad benyaya** - Développeur principal
    * GitHub : [Mouadbenyaya](https://github.com/Mouadbenyaya)