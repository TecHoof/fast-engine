"""

Application configuration

"""
from flask import Flask

app = Flask(__name__)
app.config.from_json('config-dev.json')

import engine.views  # sorry for that x)
