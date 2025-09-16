#!/usr/bin/env bash
set -e

REPO_URL="${1:-https://github.com/jsellars88/H-W-supreme-Ai-}"
shift || true

MSG="${*:-chore: update site content}"

git init
git branch -M main || true
git add .
git commit -m "$MSG" || true
git remote remove origin 2>/dev/null || true
git remote add origin "$REPO_URL"
git push -u origin main
