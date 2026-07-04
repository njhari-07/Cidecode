# Contributing to DroidRaksha

Thanks for wanting to contribute! Here's how to get your dev environment running fast.

---

## 🛠️ Dev Setup

### 1. Fork & Clone

```bash
git clone https://github.com/<your-username>/Cidecode.git
cd Cidecode
git checkout -b feature/your-feature-name
```

### 2. Backend

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env             # Fill in your API keys
uvicorn backend.main:app --reload
```

**API docs live at:** http://localhost:8000/docs

### 3. Frontend

```bash
cd frontend
cp .env.example .env.local
npm install
npm run dev
```

**App lives at:** http://localhost:3000

---

## 📐 Code Style

| Layer | Convention |
|-------|-----------|
| Python | `black` + `isort`; type-hint everything |
| TypeScript | ESLint (`next/core-web-vitals`); prefer `const` |
| Commits | `feat:`, `fix:`, `docs:`, `refactor:`, `test:` prefixes |

---

## 🗂️ Where to add things

| What | Where |
|------|-------|
| New detection engine | `backend/engines/` |
| New threat intel feed | `backend/intel/` |
| New API route | `backend/routes/` |
| New UI component | `frontend/components/` |
| New page | `frontend/app/<route>/page.tsx` |

---

## 🧪 Testing

```bash
# Backend tests (when available)
pytest backend/tests/ -v

# Frontend type check
cd frontend && npx tsc --noEmit

# Lint
cd frontend && npm run lint
```

---

## 🔀 Pull Request Checklist

- [ ] Code follows the style guide above
- [ ] No `.env` or secrets committed (use `.env.example` for new vars)
- [ ] PR title follows commit convention (`feat: add xyz engine`)
- [ ] Description explains *what* and *why*, not just *what*

---

## 🐛 Reporting Issues

Open a GitHub issue with:
1. What you expected
2. What actually happened
3. Steps to reproduce
4. OS / Python / Node version

---

Happy hacking! 🛡️
