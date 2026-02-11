# Holmes & Watson Supreme AI Repository

This repository currently contains a **Flask-based web app** for rendering Holmes & Watson content cards from JSON data, plus a few legacy/experimental JavaScript entry points.

## What this repo actually includes

- A runnable Flask service in `app/main.py`.
- Jinja templates in `app/templates/`.
- Post/content data in `data/posts.json`.
- Supporting platform files (`requirements.txt`, `render.yaml`, `package.json`, etc.).

## Project Structure

```text
app/
  main.py                # Flask app and API routes
  templates/
    base.html            # Base page shell
    index.html           # Card/grid rendering template

data/
  posts.json             # Source content rendered by Flask

requirements.txt         # Python dependencies (Flask, gunicorn)
render.yaml              # Deployment config (Render)
package.json             # Legacy/experimental Next.js metadata
server.js                # Minimal Express test server
```

## Runtime (Flask)

### 1) Install dependencies

```bash
pip install -r requirements.txt
```

### 2) Start locally

```bash
python app/main.py
```

The app runs on `http://localhost:8080` by default.

## Available endpoints

- `GET /` → Renders the HTML dashboard from `data/posts.json`.
- `GET /api/posts` → Returns raw post JSON.

## Data model (posts)

Each post object in `data/posts.json` supports fields such as:

- `id`
- `title`
- `topic`
- `x`
- `linkedin`
- `facebook`
- `visual_prompt`
- `image`

## Notes on JavaScript files

This repository also includes JS/Node artifacts (`package.json`, `next.config.js`, `server.js`, `app.js`, etc.). At present, the primary implemented application path is the Flask app in `app/main.py`.

## Architecture documentation

For the latest constitutional architecture specification, see `WHITE_SWAN_OS_V3_5_ARCHITECTURE_GUIDE.md`.

## Release notes

See `RELEASE_NOTES.md` for the latest governance-related release summary.
