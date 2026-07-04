import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn
from agent.api.server import create_app

app = create_app()
uvicorn.run(app, host="127.0.0.1", port=8001, log_level="info")
