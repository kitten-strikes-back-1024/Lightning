import importlib
import pkgutil
import os

SCRIPTS_DIR = "scripts"


class ScriptEngine:
    def __init__(self):
        self.scripts = {}  # service -> [script modules]
        self.load_scripts()

    def load_scripts(self):
        """
        Dynamically load all scripts from scripts/ directory
        """
        if not os.path.isdir(SCRIPTS_DIR):
            print("[!] scripts/ directory not found")
            return

        for _, module_name, _ in pkgutil.iter_modules([SCRIPTS_DIR]):
            module = importlib.import_module(f"{SCRIPTS_DIR}.{module_name}")

            # script must define SERVICE and run()
            if hasattr(module, "SERVICE") and hasattr(module, "run"):
                service = module.SERVICE
                self.scripts.setdefault(service, []).append(module)

    def list_scripts(self):
        """
        Print available scripts
        """
        print("\n[+] Available scripts:\n")
        for service, modules in self.scripts.items():
            for mod in modules:
                desc = getattr(mod, "DESCRIPTION", "No description")
                print(f" {service:10} -> {mod.__name__} : {desc}")

    def run_scripts(self, service, target, port, args=None):
        """
        Run all scripts for a detected service
        """
        if service not in self.scripts:
            return

        print(f"\n[+] Running scripts for {service} ({port}/tcp)\n")

        for script in self.scripts[service]:
            try:
                script.run(target, port, args or {})
            except Exception as e:
                print(f"[!] Script {script.__name__} failed: {e}")
