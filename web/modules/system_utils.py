# -----------------------
# System
# -----------------------
def get_version_old():
    try:
        with open("version.txt", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "unknown"