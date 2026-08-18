import streamlit.web.cli as stcli
import sys
import os

if __name__ == "__main__":
    # Get the absolute path of app.py relative to this entrypoint
    dir_path = os.path.dirname(os.path.realpath(__file__))
    app_path = os.path.join(dir_path, "app.py")
    
    # Configure arguments to run streamlit
    sys.argv = ["streamlit", "run", app_path, "--global.developmentMode=false"]
    sys.exit(stcli.main())
