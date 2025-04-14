"""
Point d'entrée principal pour le scanner de ports avancé
"""

import sys
import argparse
from scanner import PortScanner  
from config import Config        
from utils.banner import print_banner 

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Scanner de Ports Avancé pour la Cybersécurité')
    parser.add_argument('-t', '--target', help='Target hostname or IP address')
    parser.add_argument('-p', '--ports', help='Port range (format: start-end or single port)', default='1-1024')
    parser.add_argument('-T', '--timeout', type=float, help='Connection timeout in seconds', default=1.0)
    parser.add_argument('-c', '--threads', type=int, help='Number of concurrent threads', default=100)
    parser.add_argument('-s', '--show-closed', action='store_true', help='Show closed ports in results')
    parser.add_argument('-m', '--scan-type', choices=['tcp', 'udp', 'stealth', 'full'],
                        help='Scan method to use', default='tcp')
    parser.add_argument('-o', '--output', choices=['txt', 'json', 'csv'],
                        help='Output format', default='txt')
    parser.add_argument('-r', '--random', action='store_true', help='Randomize port scan order')
    parser.add_argument('-d', '--delay', type=float, help='Add random delay between scans (seconds)', default=0)
    parser.add_argument('-b', '--banner', action='store_true', help='Attempt banner grabbing')
    parser.add_argument('-v', '--check-vulns', action='store_true', help='Check for vulnerabilities (basic)')

    return parser.parse_args()

def interactive_mode():
    """Run scanner in interactive mode"""
    config = Config()

    print("\n==== Mode Interactif ====")
    config.target = input("Cible (IP ou hostname) [127.0.0.1]: ") or "127.0.0.1"

    # Port range
    while True:
        try:
            port_range_input = input("Plage de ports (ex: 1-1024, ou un seul port) [1-1024]: ") or "1-1024"
            if '-' in port_range_input:
                start_str, end_str = port_range_input.split('-')
                config.start_port = int(start_str.strip())
                config.end_port = int(end_str.strip())
            else:
                config.start_port = config.end_port = int(port_range_input.strip())

            if not (1 <= config.start_port <= 65535 and 1 <= config.end_port <= 65535):
                print("Erreur: Les numéros de port doivent être entre 1 et 65535.")
            elif config.start_port > config.end_port:
                print("Erreur: Le port de début doit être inférieur ou égal au port de fin.")
            else:
                break # Valid input
        except ValueError:
            print("Erreur: Format de plage de ports invalide. Utilisez start-end ou un seul numéro.")
        except Exception as e:
            print(f"Erreur inattendue lors de la lecture des ports: {e}")

    # Scan type
    scan_types = {
        '1': 'tcp', '2': 'udp', '3': 'stealth', '4': 'full'
    }
    print("\nTypes de scan disponibles:")
    print("1. TCP Connect (standard)")
    print("2. UDP Scan")
    print("3. Stealth Scan (TCP SYN)")
    print("4. Full Scan (TCP+UDP)")
    scan_choice = input("Choisissez un type de scan [1]: ") or "1"
    config.scan_type = scan_types.get(scan_choice, 'tcp')

    # Other options
    while True:
        try:
            config.timeout = float(input("Timeout de connexion (secondes) [1.0]: ") or "1.0")
            if config.timeout <= 0: raise ValueError("Timeout must be positive")
            break
        except ValueError: print("Entrée invalide. Veuillez entrer un nombre positif.")
    while True:
        try:
            config.threads = int(input("Nombre de threads concurrents [100]: ") or "100")
            if config.threads <= 0: raise ValueError("Number of threads must be positive")
            break
        except ValueError: print("Entrée invalide. Veuillez entrer un entier positif.")

    config.show_closed = input("Afficher les ports fermés? (o/n) [n]: ").strip().lower() == 'o'
    config.randomize = input("Ordre de scan aléatoire? (o/n) [n]: ").strip().lower() == 'o'

    while True:
        try:
            config.delay = float(input("Délai aléatoire entre les scans (secondes) [0]: ") or "0")
            if config.delay < 0: raise ValueError("Delay cannot be negative")
            break
        except ValueError: print("Entrée invalide. Veuillez entrer un nombre positif ou zéro.")

    config.banner_grab = input("Tentative de récupération des bannières? (o/n) [n]: ").strip().lower() == 'o'
    config.vuln_check = input("Vérification de vulnérabilités basiques? (o/n) [n]: ").strip().lower() == 'o'

    # Output format
    print("\nFormats de sortie disponibles:")
    print("1. Texte (.txt)")
    print("2. JSON (.json)")
    print("3. CSV (.csv)")
    output_choice = input("Choisissez un format de sortie [1]: ") or "1"
    output_formats = {'1': 'txt', '2': 'json', '3': 'csv'}
    config.output_format = output_formats.get(output_choice, 'txt')

    return config

def main():
    print_banner()

    # --- Disclaimer and User Agreement ---
    disclaimer = """
   *** AVERTISSEMENT / WARNING ***

Cette outil est conçu pour l'analyse de sécurité et à des fins éducatives UNIQUEMENT.

L'utilisation de cet outil sur des réseaux ou systèmes sans autorisation explicite est ILLÉGALE et contraire à l'éthique. Vous ne devez l'utiliser que sur des systèmes pour lesquels vous avez obtenu une permission écrite préalable.

L'auteur décline toute responsabilité pour une utilisation abusive ou illégale de cet outil.

En continuant, vous reconnaissez avoir lu et compris cet avertissement et vous acceptez d'utiliser cet outil de manière responsable et légale.

    """
    print(disclaimer)

    try:
        # Loop until valid input ('oui' or 'non') is received
        while True:
            agreement = input("Acceptez-vous ces conditions ? (oui/non): ").strip().lower()
            if agreement == 'oui' or agreement == 'yes':
                print("\nConditions acceptées. Poursuite du script...")
                break  # Exit the loop and continue the script
            elif agreement == 'non' or agreement == 'no':
                print("Vous devez accepter les conditions pour utiliser cet outil. Arrêt du script.")
                sys.exit(1) # Exit the script cleanly
            else:
                print("Réponse invalide. Veuillez taper 'oui' ou 'non'.")
    except KeyboardInterrupt:
        print("\nOpération annulée par l'utilisateur. Arrêt du script.")
        sys.exit(1)
    # --- End of Disclaimer ---


    # Check for command line arguments
    if len(sys.argv) > 1 and sys.argv[1] not in ['-h', '--help']: # Avoid parsing args if only help is requested initially
        args = parse_arguments()

        if not args.target:
             print("Erreur: L'argument --target (-t) est requis en mode ligne de commande.")
             sys.exit(1)

        config = Config()
        config.target = args.target

        # Parse port range
        try:
            if '-' in args.ports:
                start_str, end_str = args.ports.split('-')
                config.start_port = int(start_str.strip())
                config.end_port = int(end_str.strip())
            else:
                config.start_port = config.end_port = int(args.ports.strip())

            if not (1 <= config.start_port <= 65535 and 1 <= config.end_port <= 65535):
                raise ValueError("Les numéros de port doivent être entre 1 et 65535.")
            if config.start_port > config.end_port:
                raise ValueError("Le port de début doit être inférieur ou égal au port de fin.")
        except ValueError as e:
            print(f"Erreur dans la plage de ports '{args.ports}': {e}")
            sys.exit(1)

        config.timeout = args.timeout
        config.threads = args.threads
        config.show_closed = args.show_closed
        config.scan_type = args.scan_type
        config.output_format = args.output
        config.randomize = args.random
        config.delay = args.delay
        config.banner_grab = args.banner
        config.vuln_check = args.check_vulns

        # Validate arguments
        if config.timeout <= 0:
            print("Erreur: Le timeout doit être un nombre positif.")
            sys.exit(1)
        if config.threads <= 0:
            print("Erreur: Le nombre de threads doit être un entier positif.")
            sys.exit(1)
        if config.delay < 0:
            print("Erreur: Le délai ne peut pas être négatif.")
            sys.exit(1)

    else:
        # If no command line arguments (or only help), run interactive mode
        if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
             parse_arguments() # Just show help and exit
             sys.exit(0)
        config = interactive_mode()
        if config is None:
            print("Configuration interactive échouée. Arrêt.")
            return # Exit main if interactive mode failed

    # Proceed with scanning only if configuration is valid
    if config and config.target:
        try:
            print(f"\nConfiguration du scan :")
            print(f"  Cible          : {config.target}")
            print(f"  Ports          : {config.start_port}-{config.end_port}")
            print(f"  Type de Scan   : {config.scan_type.upper()}")
            print(f"  Threads        : {config.threads}")
            print(f"  Timeout (s)    : {config.timeout}")
            print(f"  Afficher fermés: {'Oui' if config.show_closed else 'Non'}")
            print(f"  Ordre Aléatoire: {'Oui' if config.randomize else 'Non'}")
            print(f"  Délai (s)      : {config.delay}")
            print(f"  Banner Grab    : {'Oui' if config.banner_grab else 'Non'}")
            print(f"  Vuln Check     : {'Oui' if config.vuln_check else 'Non'}")
            print(f"  Format Sortie  : {config.output_format.upper()}")
            print("-" * 30)

            scanner = PortScanner(config)
            scanner.run()

        except KeyboardInterrupt:
            print("\nScan interrompu par l'utilisateur.")
        except ImportError as e:
             print(f"\nErreur d'importation: {e}. Assurez-vous que les fichiers 'scanner.py', 'config.py', et 'utils/banner.py' existent.")
        except AttributeError as e:
             print(f"\nErreur d'attribut: {e}. Vérifiez que les classes et méthodes existent comme attendu (ex: PortScanner, Config).")
        except Exception as e:
            print(f"\nUne erreur inattendue est survenue: {e}")
            import traceback
            traceback.print_exc() # Print detailed traceback for debugging
    else:
        if not config:
             print("Erreur: La configuration n'a pas pu être chargée.")
        elif not config.target:
             print("Erreur: Aucune cible spécifiée.")


if __name__ == "__main__":
    main()