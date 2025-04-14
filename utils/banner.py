
import sys
import time

def print_banner():
    """Print the application banner"""
    banner = """
    ╔═════════════════════════════════════════════════════╗
    ║                                                     ║
    ║       ███████╗ ██████╗ █████╗ ███╗   ██╗███████╗    ║
    ║       ██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝    ║
    ║       ███████╗██║     ███████║██╔██╗ ██║█████╗      ║
    ║       ╚════██║██║     ██╔══██║██║╚██╗██║██╔══╝      ║
    ║       ███████║╚██████╗██║  ██║██║ ╚████║███████╗    ║
    ║       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝    ║
    ║                                                     ║
    ║                PortBScanner - Cybersecurity         ║
    ║        Utilisez de manière responsable et légale    ║
    ║                                                     ║
    ╚═════════════════════════════════════════════════════╝
    """
    print(banner)

def print_progress(current, total, bar_length=50, prefix=""):
    """Display a progress bar in the console"""
    percent = float(current) * 100 / total
    arrow = '█' * int(percent / 100 * bar_length)
    spaces = ' ' * (bar_length - len(arrow))
    
    sys.stdout.write(f"\r{prefix} [{arrow + spaces}] {percent:.2f}% ({current}/{total})")
    sys.stdout.flush()

def animate_text(text, delay=0.05):
    """Animate text in the console"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()
def print_result(port, status, service=None, banner=None):
    """Print portBscanner result with color coding"""
    if status == "open":
        status_str = "\033[92mOPEN\033[0m"  # Green
        result = f"Port {port}: {status_str}"
        if service:
            result += f" - Service: {service}"
        if banner:
            result += f"\n  Banner: {banner[:100]}"
            if len(banner) > 100:
                result += "..."
        print(result)
    elif status == "filtered":
        if service:
            print(f"Port {port}: \033[93mFILTERED\033[0m - Service: {service}")  
        else:
            print(f"Port {port}: \033[93mFILTERED\033[0m")  
    elif status == "closed" and service:
        print(f"Port {port}: \033[91mCLOSED\033[0m - Service: {service}") 