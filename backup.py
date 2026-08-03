import shutil
import os
from datetime import datetime

DB_FILE = "database.db"
BACKUP_DIR = "backup"

def backup():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"database_{timestamp}.db")
    try:
        shutil.copy2(DB_FILE, backup_path)
        print(f"[✅] Бэкап создан: {backup_path}")
    except FileNotFoundError:
        print("[❌] Файл database.db не найден!")
    except Exception as e:
        print(f"[❌] Ошибка: {e}")

if __name__ == "__main__":
    backup()
