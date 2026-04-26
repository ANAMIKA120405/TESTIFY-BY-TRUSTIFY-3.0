# TESTIFY by Trustify 2.0

A comprehensive cybersecurity scanning and threat intelligence platform. TESTIFY provides security professionals and developers with an integrated suite of tools to analyze URLs, domains, IPs, ports, SSL certificates, and more—all backed by AI-powered threat analysis and OCR capabilities.

![Version](https://img.shields.io/badge/version-2.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Built with React](https://img.shields.io/badge/built%20with-React%2B%20TypeScript-blue)

---

## 🎯 Overview

TESTIFY by Trustify is a full-stack cybersecurity application that combines multiple threat intelligence sources, advanced scanning capabilities, and AI-driven analysis to help identify and mitigate security risks. Whether you're conducting penetration testing, performing threat analysis, or monitoring attack surfaces, TESTIFY provides the tools you need.

---

## ✨ Key Features

### Security Scanning & Analysis
- **URL Scanner** — Comprehensive URL threat analysis with multiple feed sources
- **IP Geolocation & Intelligence** — GeoIP lookup and IP reputation analysis
- **DNS Lookup** — DNS resolution and record analysis
- **Port Scanning** — Network port discovery and service detection
- **SSL Certificate Analysis** — SSL/TLS certificate validation and security checks
- **Hash Analysis** — File hash lookup against known malware databases

### Advanced Features
- **Image Processor** — OCR text extraction from images using Tesseract.js
- **Attack Surface Mapping** — Visualize and analyze organizational attack surfaces
- **Dark Web Monitoring** — Monitor for compromised credentials and threats
- **Security Box** — Secure note-taking and credential management
- **Scan History** — Track and review all previous scans
- **AI Assistant** — Google GenAI-powered threat analysis

---

## 🛠️ Tech Stack

### Frontend
- **React 19** — Modern UI framework
- **TypeScript** — Type-safe development
- **Vite** — Lightning-fast build tool
- **React Router** — Client-side routing
- **Tailwind CSS** — Utility-first styling

### Backend
- **Node.js + Express** — Server framework
- **Helmet** — Security headers
- **CORS** — Cross-origin resource sharing
- **Express Rate Limit** — Request rate limiting
- **Tesseract.js** — OCR for image processing
- **Axios** — HTTP client

---

## 📋 Prerequisites

- **Node.js** (v16 or higher)
- **npm** or **yarn**
- **Git**

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/TESTIFY-BY-TRUSTIFY-2.0.git
cd TESTIFY-BY-TRUSTIFY-2.0-main
```

### 2. Set Up Environment Variables

Create a `.env` file in the root directory:

```env
PORT=4000
FRONTEND_URL=http://localhost:5173
GOOGLE_GENAI_API_KEY=your_api_key
```

### 3. Install Dependencies

**Frontend:**
```bash
npm install
```

**Backend:**
```bash
cd backend
npm install
cd ..
```

### 4. Development Mode

```bash
npm run dev
```

- Frontend: http://localhost:5173
- Backend: http://localhost:4000

### 5. Production Build

```bash
npm run build
npm start
```

---

## 📁 Project Structure

```
├── src/                      # React frontend
│   ├── views/               # Page components
│   ├── ui/                  # UI components
│   ├── lib/                 # Utilities
│   ├── App.tsx              # Root component
│   └── router.tsx           # Route definitions
├── backend/                 # Express.js backend
│   ├── controllers/         # Business logic
│   ├── routes/              # API endpoints
│   └── server.js            # Express app setup
└── README.md                # This file
```

---

## 📡 Key Endpoints

- `POST /api/url-scan` — Analyze URL for threats
- `POST /api/port-scan` — Scan ports
- `POST /api/ssl` — Analyze SSL certificate
- `POST /api/ip-geo` — Get IP location
- `POST /api/dns` — DNS lookup
- `POST /api/hash` — Hash analysis
- `POST /api/image-scan` — OCR image processing
- `POST /api/whois` — WHOIS lookup
- `POST /api/ai-chat` — AI analysis

---

## 🔒 Security Features

- **Helmet.js** — Protective HTTP headers
- **CORS Protection** — Restricted cross-origin requests
- **Rate Limiting** — 120 requests per 15 minutes per IP
- **Body Size Limits** — Max 10KB JSON payloads
- **Environment-based Configuration** — Secure API key management

---

## 📝 Available Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start with live reload |
| `npm start` | Production build and serve |
| `npm run build` | Build for production |
| `npm run lint` | Run ESLint |

---

## 🤝 Contributing

Contributions are welcome! Please fork and submit pull requests.

---

## 📄 License

MIT License — see the LICENSE file for details.

---

## 📞 Support

For issues and questions, please open an issue on GitHub or contact the development team.

---

## 🙏 Acknowledgments

Built with:
- [React](https://react.dev)
- [Express.js](https://expressjs.com)
- [Tailwind CSS](https://tailwindcss.com)
- [Vite](https://vitejs.dev)
