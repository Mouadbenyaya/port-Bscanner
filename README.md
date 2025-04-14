**portBscanner** est un outil développé en Python qui permet de scanner les ports d'un hôte spécifié pour déterminer s'ils sont ouverts ou fermés. Ce projet utilise le module socket de Python pour se connecter aux ports et effectuer les tests de manière rapide et efficace en utilisant l'exécution parallèle (multithreading).

**Fonctionnalités principales**

Scan de ports : Vérifie si les ports spécifiés sur un hôte donné sont ouverts ou fermés.
Exécution parallèle : Utilise ThreadPoolExecutor pour scanner plusieurs ports simultanément, réduisant ainsi le temps nécessaire pour effectuer le scan.

Affichage des résultats : Les résultats sont clairement affichés, indiquant les ports ouverts et fermés.
Personnalisation de la plage de ports : Permet à l'utilisateur de définir la plage de ports à scanner.

Option d'affichage des ports fermés : Possibilité d'afficher également les ports fermés pour une vue complète de l'état du serveur.


**Installation**

Clonez ce dépôt sur votre machine locale :

git clone https://github.com/Mouadbenyaya/port-Bscanner.git


Naviguez dans le répertoire du projet :


cd portBscanner



**Utilisation** 


Lancez le fichier Python en exécutant la commande suivante :

 
python portBscanner.py




**Avertissement Légal / Disclaimer**

Ce projet est destiné uniquement à des fins éducatives et à des tests de pénétration légitimes. N'utilisez cet outil que sur des réseaux et systèmes pour lesquels vous avez une autorisation explicite. Scanner des réseaux sans permission est illégal.

L'auteur de `port-Bscanner` décline toute responsabilité pour les dommages directs ou indirects causés par l'utilisation ou la mauvaise utilisation de ce logiciel. L'utilisateur assume l'entière responsabilité de ses actions et s'engage à utiliser cet outil conformément à toutes les lois applicables.



**Auteur**
Mouad benyaya - Développeur principal