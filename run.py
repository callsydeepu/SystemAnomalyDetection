import streamlit.web.cli as stcli
import sys
from pathlib import Path

if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent
    app_path = project_root / "src" / "dashboard" / "app.py"
    
    sys.argv = ["streamlit", "run", str(app_path), "--global.developmentMode=false"]
    sys.exit(stcli.main())
