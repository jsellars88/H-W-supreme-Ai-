from flask import Flask, render_template, jsonify
import json, os

app = Flask(__name__, template_folder='templates', static_folder='static')
DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'posts.json')

def load_posts():
    with open(DATA_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)

@app.route('/')
def index():
    posts = sorted(load_posts(), key=lambda p: p.get('id', 0), reverse=True)
    return render_template('index.html', posts=posts, title="Holmes & Watson Supreme AI Ecosystem")

@app.route('/api/posts')
def api_posts():
    return jsonify(load_posts())

if __name__ == '__main__':
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=False)
