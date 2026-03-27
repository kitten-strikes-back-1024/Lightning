import importlib
import pkgutil
import os

SCRIPTS_DIR = "scripts"


class ScriptEngine:
    def __init__(self):
        # service -> list of script modules
        self.scripts = {}
        self.load_scripts()

    def load_scripts(self):
        """
        Dynamically load all scripts from scripts/ directory
        """
        if not os.path.isdir(SCRIPTS_DIR):
            print("[!] scripts/ directory not found")
            return

        for _, module_name, _ in pkgutil.iter_modules([SCRIPTS_DIR]):
            try:
                module = importlib.import_module(f"{SCRIPTS_DIR}.{module_name}")
            except Exception as e:
                print(f"[!] Failed to load script {module_name}: {e}")
                continue

            # Script contract
            if not hasattr(module, "SERVICE") or not hasattr(module, "run"):
                continue

            # Defaults
            module.SCRIPT_NAME = getattr(module, "SCRIPT_NAME", module_name)
            module.DESCRIPTION = getattr(module, "DESCRIPTION", "No description")
            module.OPTIONAL = getattr(module, "OPTIONAL", False)

            service = module.SERVICE
            self.scripts.setdefault(service, []).append(module)

    def list_scripts(self):
        """
        Print available scripts
        """
        print("\n[+] Available scripts:\n")
        for service, modules in self.scripts.items():
            for mod in modules:
                opt = "optional" if mod.OPTIONAL else "default"
                print(f" {service:12} -> {mod.SCRIPT_NAME:20} [{opt}] - {mod.DESCRIPTION}")

    def run_scripts(self, service, target, port, args=None):
        """
        Run scripts for a detected service
        """
        if service not in self.scripts:
            return

        args = args or {}

        # Flags
        run_optional = args.get("active", False)      # --active
        selected = args.get("scripts")                # --scripts a,b,c

        print(f"\n[+] Running scripts for {service} ({port}/tcp)\n")

        for script in self.scripts[service]:
            name = script.SCRIPT_NAME

            # 1️⃣ Explicit script selection overrides everything
            if selected is not None:
                if name not in selected:
                    continue

            # 2️⃣ Optional scripts require --active
            elif script.OPTIONAL and not run_optional:
                continue

            try:
                script.run(target, port, args)
            except Exception as e:
                print(f"[!] Script {name} failed: {e}")
