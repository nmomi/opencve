from flask import jsonify
from opencve.controllers.main import main

@main.route("/healthcheck")
def health_check():
    health_status = {'status': 'ok'}
    return jsonify(health_status)
