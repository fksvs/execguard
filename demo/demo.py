from flask import Flask, jsonify
import subprocess

app = Flask(__name__)

@app.route('/run-id')
def run_id():
    try:
        result = subprocess.run(["id"], capture_output=True, text=True, check=True)
        return jsonify({"status": "success", "output": result.stdout.strip()}), 200
    except Exception as e:
        return jsonify({"status": "blocked", "error": str(e)}), 403

if __name__ == '__main__':
    app.run()
