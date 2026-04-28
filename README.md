# microlend-finance

Micro-lending finance management system with customer management, loan tracking, collections, and reporting.

## Run Locally

**Prerequisites:** Node.js, npm

1. Install dependencies:
   `npm install`
2. Copy `.env.example` to `.env` and configure:
   - Set `JWT_SECRET` (generate with: `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"`)
   - Set `GEMINI_API_KEY` for AI features (optional)
3. Start both frontend and backend:
   `npm run dev:all`

The app will be available at http://localhost:3001
