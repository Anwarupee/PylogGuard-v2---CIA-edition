# main.py
"""
PyLogGuard CLI - main entrypoint (extended)
Includes Users, Logs, Detectors (bruteforce/dos), Generators (tools)
Replace your current main.py with this file.
"""

import subprocess
import sys
from typing import Optional

# Models (ensure these files exist in models/)
from core.models.user_model import UserModel
from core.models.log_model import LogModel
from core.models.role_model import RoleModel
from core.models.attack_type_model import AttackTypeModel

# Try to import detector runner functions (fall back to module runner)
try:
    # if you implemented detector as callable function in tools module
    from detector.detect_bruteforce import run_detector as run_bruteforce_detector
except Exception:
    run_bruteforce_detector = None

try:
    from detector.detect_DoS import run_detector as run_dos_detector
except Exception:
    run_dos_detector = None

# generator module names (run with -m) — adjust if your files differ
GEN_BRUTE_MODULE = "generator.gen_bruteforce"
GEN_DOS_MODULE = "generator.gen_DoS"

# Helpers ---------------------------------------------------------------------
def read_int(prompt: str, default: Optional[int] = None) -> Optional[int]:
    v = input(prompt).strip()
    if v == "" and default is not None:
        return default
    try:
        return int(v)
    except ValueError:
        return None

def press_enter():
    input("\nPress Enter to continue...")

def run_generator(module_name: str, *args):
    """
    Run a generator module via python -m to avoid import path issues.
    module_name: like "tools.gen_dos"
    args: string args to pass
    """
    cmd = [sys.executable, "-m", module_name] + [str(a) for a in args]
    print("Running generator:", " ".join(cmd))
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print("❌ Generator failed:", e)
    except FileNotFoundError as e:
        print("❌ Could not run generator. Is Python path correct?", e)

def run_detector_module_or_func(func, module_name: str, created_by=None, extra_args=None):
    """
    Try to call detector function (func). If None, run via python -m module_name.
    extra_args: dict to supply to function if calling directly (optional).
    """
    if func:
        try:
            kwargs = extra_args.copy() if extra_args else {}
            if created_by is not None:
                kwargs["created_by"] = created_by
            print(f"Running detector function {func.__name__}...")
            return func(**kwargs)
        except Exception as e:
            print("❌ Detector function raised an error:", e)
            return None
    else:
        cmd = [sys.executable, "-m", module_name]
        if created_by is not None:
            cmd += ["--created-by", str(created_by)]
        if extra_args:
            if "threshold" in extra_args:
                cmd += ["--threshold", str(extra_args["threshold"])]
            if "window_minutes" in extra_args:
                cmd += ["--window", str(extra_args["window_minutes"])]
            if extra_args.get("debug"):
                cmd += ["--debug"]
        print("Running detector module:", " ".join(cmd))
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print("❌ Detector module failed:", e)
        except FileNotFoundError as e:
            print("❌ Could not run detector module. Is Python path correct?", e)

# Submenus -------------------------------------------------------------------
def users_menu(user_model: UserModel, role_model: RoleModel):
    while True:
        print("\n--- Users Menu ---")
        print("1. Create user")
        print("2. List users")
        print("3. Update user")
        print("4. Delete user")
        print("5. Back to main menu")
        choice = input("Choose: ").strip()

        if choice == "1":
            roles = role_model.read_roles()
            print("\nAvailable Roles:")
            for r in roles:
                print(f"{r['role_id']}: {r['role_name']}")
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            role_id = read_int("Role ID: ")
            if role_id is None:
                print("❌ Invalid role id.")
                continue
            if not user_model.role_exists(role_id):
                print("❌ Role does not exist.")
                continue
            try:
                uid = user_model.create_user(username, password, role_id)
                print(f"✅ Created user id: {uid}")
            except Exception as e:
                print("❌ Error creating user:", e)
            press_enter()

        elif choice == "2":
            users = user_model.read_user()
            if not users:
                print("No users.")
            else:
                print(f"\n{'ID':<6}{'Username':<20}{'Role ID':<8}")
                print("-" * 40)
                for u in users:
                    print(f"{u['user_id']:<6}{u['username']:<20}{u['role_id']:<8}")
            press_enter()

        elif choice == "3":
            uid = read_int("User ID to update: ")
            if not uid:
                print("❌ Invalid user id.")
                continue
            username = input("New username (leave blank to skip): ").strip()
            password = input("New password (leave blank to skip): ").strip()
            role_input = input("New role ID (leave blank to skip): ").strip()
            kwargs = {}
            if username:
                kwargs["username"] = username
            if password:
                kwargs["password"] = password
            if role_input:
                try:
                    rid = int(role_input)
                except ValueError:
                    print("❌ Invalid role id.")
                    continue
                if not user_model.role_exists(rid):
                    print("❌ Role does not exist.")
                    continue
                kwargs["role_id"] = rid
            if not kwargs:
                print("Nothing to update.")
                continue
            updated = user_model.update_user(uid, **kwargs)
            print(f"✅ Rows updated: {updated}")
            press_enter()

        elif choice == "4":
            uid = read_int("User ID to delete: ")
            if not uid:
                print("❌ Invalid user id.")
                continue
            deleted = user_model.delete_user(uid)
            print(f"✅ Rows deleted: {deleted}")
            press_enter()

        elif choice == "5":
            return

        else:
            print("Invalid option.")


def logs_menu(log_model: LogModel, user_model: UserModel, attack_model: AttackTypeModel):
    while True:
        print("\n--- Logs Menu ---")
        print("1. Create log")
        print("2. List logs")
        print("3. Update log")
        print("4. Delete log")
        print("5. Back to main menu")
        choice = input("Choose: ").strip()

        if choice == "1":
            source_ip = input("Source IP: ").strip()

            # show attack types
            attacks = attack_model.read_attacks()
            print("\nAvailable Attack Types:")
            for a in attacks:
                name_key = "name" if "name" in a else "attack_name"
                print(f"{a['attack_id']}: {a[name_key]}")
            aid = read_int("Choose Attack ID: ")
            if not aid:
                print("❌ Invalid attack id.")
                continue

            status = input("Status (default 'Detected'): ").strip() or "Detected"
            details = input("Details (optional): ").strip()

            # show users
            users = user_model.read_user()
            print("\nAvailable Users:")
            for u in users:
                print(f"{u['user_id']}: {u['username']}")
            created_by_input = input("Created by (User ID, optional): ").strip()
            created_by = int(created_by_input) if created_by_input else None

            try:
                lid = log_model.create_log(source_ip, aid, status, details, created_by)
                print(f"✅ Log created with ID {lid}")
            except Exception as e:
                print("❌ Error creating log:", e)
            press_enter()

        elif choice == "2":
            logs = log_model.read_log()
            if not logs:
                print("No logs.")
            else:
                print(f"\n{'ID':<6}{'Source IP':<18}{'Attack ID':<10}{'Status':<15}{'Created By':<10}")
                print("-" * 70)
                for l in logs:
                    print(f"{l['log_id']:<6}{l['source_ip']:<18}{str(l.get('attack_id','')):<10}{l.get('status',''):<15}{str(l.get('created_by','')):<10}")
            press_enter()

        elif choice == "3":
            lid = read_int("Log ID to update: ")
            if not lid:
                print("❌ Invalid log id.")
                continue
            source_ip = input("New Source IP (leave blank to skip): ").strip()
            attack_id_input = input("New Attack ID (leave blank to skip): ").strip()
            status = input("New Status (leave blank to skip): ").strip()
            details = input("New Details (leave blank to skip): ").strip()
            created_by_input = input("New Created by (leave blank to skip): ").strip()

            kwargs = {}
            if source_ip:
                kwargs["source_ip"] = source_ip
            if attack_id_input:
                try:
                    kwargs["attack_id"] = int(attack_id_input)
                except ValueError:
                    print("❌ Invalid attack id.")
                    continue
            if status:
                kwargs["status"] = status
            if details:
                kwargs["details"] = details
            if created_by_input:
                try:
                    kwargs["created_by"] = int(created_by_input)
                except ValueError:
                    print("❌ Invalid user id.")
                    continue

            updated = log_model.update_log(lid, **kwargs)
            print(f"✅ Rows updated: {updated}")
            press_enter()

        elif choice == "4":
            lid = read_int("Log ID to delete: ")
            if not lid:
                print("❌ Invalid log id.")
                continue
            deleted = log_model.delete_log(lid)
            print(f"✅ Rows deleted: {deleted}")
            press_enter()

        elif choice == "5":
            return
        else:
            print("Invalid option.")


def detector_menu(current_user_id: Optional[int]):
    while True:
        print("\n--- Detector Menu ---")
        print("1. Run Brute-Force Detector (now)")
        print("2. Run DoS Detector (now)")
        print("3. Back to main menu")
        choice = input("Choose: ").strip()

        if choice == "1":
            extra_args = {"threshold": 5, "window_minutes": 60, "debug": True}
            # use tools module name used earlier; fallback to python -m tools.detect_bruteforce
            run_detector_module_or_func(run_bruteforce_detector, "tools.detect_bruteforce", created_by=current_user_id, extra_args=extra_args)
            press_enter()

        elif choice == "2":
            extra_args = {"threshold": 200, "window_minutes": 1, "debug": True}
            run_detector_module_or_func(run_dos_detector, "tools.detect_DoS", created_by=current_user_id, extra_args=extra_args)
            press_enter()

        elif choice == "3":
            return
        else:
            print("Invalid option.")


def generator_menu():
    while True:
        print("\n--- Generator Menu ---")
        print("1. Generate brute-force logs")
        print("2. Generate DoS logs")
        print("3. Back to main")
        choice = input("Choose: ").strip()

        if choice == "1":
            ip = input("IP to generate (default 203.0.113.5): ").strip() or "203.0.113.5"
            attempts = read_int("Number of attempts (default 10): ", default=10) or 10
            attack_id = read_int("Attack ID for these logs (e.g. Brute Force id): ")
            user_id = read_int("Created by user id (optional, default 1): ", default=1) or 1
            if not attack_id:
                print("❌ Invalid attack id.")
                continue
            run_generator(GEN_BRUTE_MODULE, ip, attempts, attack_id, user_id)
            press_enter()

        elif choice == "2":
            ip = input("IP to generate (default 203.0.113.80): ").strip() or "203.0.113.80"
            hits = read_int("Number of hits (default 200): ", default=200) or 200
            attack_id = read_int("Attack ID for these logs (e.g. DoS id): ")
            user_id = read_int("Created by user id (optional, default 1): ", default=1) or 1
            if not attack_id:
                print("❌ Invalid attack id.")
                continue
            run_generator(GEN_DOS_MODULE, ip, hits, attack_id, user_id, 0)
            press_enter()

        elif choice == "3":
            return
        else:
            print("Invalid option.")

# ----------------- Summary Menu -----------------
def summary_menu(log_model: LogModel):
    """
    Print attack summary: attack name, total count, last seen timestamp.
    Uses log_model.summarize_logs() which should return rows with
    keys: attack_name, total, last_seen
    """
    print("\n=== Attack Summary ===")
    try:
        rows = log_model.summarize_logs()
    except Exception as e:
        print("❌ Error fetching summary:", e)
        press_enter()
        return

    if not rows:
        print("No logs to summarize.")
    else:
        # header
        print(f"{'Attack Type':<30} {'Count':<10} {'Last Seen':<25}")
        print("-" * 70)
        for r in rows:
            attack_name = r.get("attack_name") or r.get("attack_name".lower(), "")
            total = r.get("total", 0)
            last_seen = r.get("last_seen")
            print(f"{str(attack_name):<30} {str(total):<10} {str(last_seen):<25}")
    press_enter()

# Main flow ------------------------------------------------------------------
def main():
    user_model = UserModel()
    log_model = LogModel()
    role_model = RoleModel()
    attack_model = AttackTypeModel()

    print("=== PyLogGuard CLI ===")

    # Simple login: choose user to operate as (for audit fields)
    users = user_model.read_user()
    current_uid = None
    if users:
        print("\nSelect user to login as (for audit fields):")
        for u in users:
            print(f"{u['user_id']}: {u['username']}")
        uid = read_int("Enter user id to login as (or blank to continue as anonymous): ")
        if uid:
            current_uid = uid
            print(f"Logged in as user id {current_uid}")
        else:
            print("Continuing without logged-in user (created_by will be None).")
    else:
        print("No users present. Create an admin user first (use Users -> Create user).")

    # Main submenu loop
    while True:
        print("\n=== Main Menu ===")
        print("1. Users")
        print("2. Logs")
        print("3. Detector")
        print("4. Generator")
        print("5. Summary")
        print("6. Exit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            users_menu(user_model, role_model)
        elif choice == "2":
            logs_menu(log_model, user_model, attack_model)
        elif choice == "3":
            detector_menu(current_uid)
        elif choice == "4":
            generator_menu()
        elif choice == "5":
            summary_menu(log_model)
        elif choice == "6":
            print("Goodbye.")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()