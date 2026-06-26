# AI-Ticket-Investigator Backend API

Backend API for the **bKash Presents SUST CSE Carnival 2026 – Codex Community Hackathon Preliminary Round**.

This project provides the backend services for the AI-Ticket-Investigator platform, including REST APIs, authentication, AI integration, caching, and database management.

---

# Live Demo

The deployed backend is available at:

**🔗 Live URL:** `https://ai-ticket-investigator.vercel.app`

---

# Tech Stack

* Node.js
* Express.js
* Redis
* Docker & Docker Compose
* Google Gemini API

---

# Prerequisites

Before running the project locally, make sure you have installed:

* Docker
* Docker Compose
* Git

---

# Local Setup

### 1. Clone the repository

```bash
git clone https://github.com/Foridul35962/AI-Ticket-Investigator.git
cd AI-Ticket-Investigator
```

### 2. Create `.env`

Copy the `.env.example` file and rename it to `.env`.

```bash
cp .env.example .env
```

If you are using Windows CMD:

```cmd
copy .env.example .env
```

Then open the `.env` file and provide values for the required environment variables.

```env
CORS_ORIGIN=http://localhost:3000

REDIS_PREFIX=sustPreli

GEMINI_API_KEY=YOUR_GEMINI_API_KEY
```

> **Note**
>
> `TOKEN_SECRET`, `TOKEN_EXPIRY`, and `GEMINI_API_KEY` must be configured before starting the application.

---

# Run the Project

From the project root directory, simply execute:

```bash
docker compose up
```

Docker will automatically build the containers and start all required services.

Once the containers are running, the backend will be available locally.

---

# Stopping the Project

```bash
docker compose down
```

---

# Project Structure

```
.
├── src/
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── package.json
└── README.md
```

---

# Environment Variables

| Variable         | Description           |
| ---------------- | --------------------- |
| `CORS_ORIGIN`    | Frontend origin       |
| `REDIS_PREFIX`   | Redis key prefix      |
| `GEMINI_API_KEY` | Google Gemini API key |

---

# Notes

* Redis are managed through Docker Compose.
* No manual database setup is required.
* Make sure Docker Desktop is running before executing `docker compose up`.
* Update the `.env` file with valid credentials before starting the application.

---

# Hackathon Submission

This repository has been submitted as part of the **bKash Presents SUST CSE Carnival Hackathon 2026 – Preliminary Round**.

---

# License

This project is intended solely for hackathon evaluation purposes.