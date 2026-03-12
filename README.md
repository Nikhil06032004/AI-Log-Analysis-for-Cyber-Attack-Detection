AI Log Threat Detection System
An AI-powered cybersecurity log analysis platform designed to detect potential threats from system logs using machine learning. This project features a modern full-stack architecture, combining a high-performance FastAPI backend with a reactive React frontend.

🚀 Overview
The system provides a seamless workflow for security analysts to upload system logs, process them through machine learning models to identify suspicious patterns, and visualize security insights through an interactive dashboard.

Key Components
Frontend: A sleek UI built with React and Vite for real-time data visualization.

Backend: A robust FastAPI service handling high-concurrency log processing.

AI Engine: Utilizes Scikit-learn and Pandas for anomaly detection and threat classification.

🏗️ Project Architecture
The application is split into two primary layers to ensure scalability and separation of concerns:

Frontend (React + Vite)
Landing Page: Project introduction and quick-start actions.

Dashboard: Interactive UI for log uploads and threat visualization.

State Management: Efficient data handling for API responses.

Backend (FastAPI)
REST APIs: Structured endpoints for frontend communication.

ML Services: Logic for processing raw logs and running inference.

Uvicorn: High-performance ASGI server implementation.
Log-Analysis
│
├── backend
│   └── app
│       ├── main.py            # API Entry point
│       ├── routes
│       │   └── threat_routes.py # Threat detection endpoints
│       └── services           # ML Logic & processing
│
├── frontend
│   ├── index.html
│   ├── package.json
│   └── src
│       ├── main.tsx
│       ├── App.tsx
│       └── pages
│           └── Dashboard.tsx  # Analysis interface
│
├── venv                       # Python Virtual Environment
├── .gitignore
└── README.md

Layer,Technologies
Frontend,"React, Vite, TypeScript, React Router, Tailwind CSS (optional)"
Backend,"FastAPI, Python, Uvicorn"
Machine Learning,"Pandas, Scikit-learn, Joblib"
Tools,"Git, NPM, Pip"

⚙️ Installation & Setup
1. Clone the Repository
Bash
git clone <repository-url>
cd Log-Analysis
2. Backend Setup
Step 1: Create and Activate Virtual Environment

Bash
python -m venv venv

# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
Step 2: Install Dependencies

Bash
pip install fastapi uvicorn pandas scikit-learn joblib python-multipart python-dotenv
Step 3: Launch the API Server

Bash
cd backend
uvicorn app.main:app --reload
The backend will be available at: http://127.0.0.1:8000

3. Frontend Setup
Step 1: Install Node Modules

Bash
cd frontend
npm install
Step 2: Start Development Server

Bash
npm run dev
The frontend will be available at: http://localhost:5173

🔄 Application Flow
Entry: User arrives at the Landing Page and clicks "Explore System".

Navigation: User is redirected to the /dashboard.

Ingestion: User uploads .log or .csv files via the dashboard.

Processing: Frontend sends data to the FastAPI /analyze endpoint.

Detection: Backend runs ML models to flag anomalies or known threat patterns.

Visualization: Results are returned and rendered as security insights/graphs.
🔮 Future Enhancements
[ ] Real-time Monitoring: WebSocket integration for live log streaming.

[ ] Advanced ML: Implementation of Deep Learning (LSTMs) for sequential log analysis.

[ ] Visualization: Graph-based threat maps and D3.js charts.

[ ] Auth: Secure user authentication and Role-Based Access Control (RBAC).

🛡️ Use Cases
SOC Operations: Speeding up manual log reviews.

Infrastructure Audit: Identifying unauthorized access attempts.

Education: Demonstrating AI application in Cybersecurity.
