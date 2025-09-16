# Holmes & Watson Supreme AI Ecosystem — GitHub Starter

A minimal, production-friendly skeleton for hosting your **posts, prompts, and investor collateral**.

### Quick Start
```bash
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app/main.py
```
Open http://localhost:8080

### Deploy to Replit
Import this repo to Replit and run `python app/main.py`.

### Project Layout
- `app/main.py` — Flask server
- `app/templates/` — Jinja2 templates (`index.html`)
- `app/static/images/` — put images here
- `data/posts.json` — your social copies/visual prompts
- `.github/workflows/` — CI to lint/start app
- `.gitignore`, `LICENSE`, `README.md`

### Push Helper
Use `./push.sh "commit message"` to add/commit/push quickly.

---
© 2025 Holmes & Watson AI