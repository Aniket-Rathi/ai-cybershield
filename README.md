🛡️ AI CyberShield: Enterprise AI Threat Intelligence & URL Inspector
Python Streamlit Scikit-Learn SQLite License: MIT

An enterprise-grade, multi-user cyber threat intelligence platform engineered for real-time phishing detection, hyperlink heuristic inspection, and isolated audit logging.

📋 Executive Overview
AI CyberShield is an advanced machine learning and heuristic-driven security web application designed to defend against modern digital threats. Built as a multi-user platform with persistent backend storage, it allows individuals and security teams to evaluate suspicious email payloads, inspect embedded malicious hyperlinks, and track historical audit trails securely.

🚀 Key Features
🛡️ Real-Time NLP Threat Analyzer: Uses a trained Scikit-Learn Random Forest Classifier coupled with TF-IDF Vectorization (trained on curated Kaggle phishing datasets) to distinguish between malicious phishing payloads and safe communications with high confidence scores.
🔗 Embedded Hyperlink Inspector: Extracts destination domains and scans for high-risk structural markers, including raw IP-address hosting, suspicious top-level domains (.tk, .xyz, .ru), and URL shorteners.
📊 Model Analytics Dashboard: Provides performance metrics, precision/recall architecture breakdowns, and feature dimensionality documentation.
🔐 Secure Multi-User Authentication: Features a robust login and registration system with complete database partitioning (WHERE username = ?) to ensure user data isolation and privacy.
📜 Persistent User-Isolated Audit Logs: Automatically logs historical threat assessments and URL checks into a backend SQLite database keyed uniquely to the authenticated user account.
🛠️ Technology Stack
Frontend & UI Framework: Python Streamlit (Custom Dark-Theme Enterprise Styling)
Machine Learning Core: Scikit-Learn (RandomForestClassifier, TfidfVectorizer), Pandas
Database & Persistence: SQLite3 Relational Database with schema migration safeguards
Deployment Platform: Streamlit Community Cloud
⚙️ Local Installation & Setup
To run this project locally on your machine, follow these steps:

Clone the Repository:

git clone https://github.com/your-username/ai-cybershield.git
cd ai-cybershield
Install Dependencies: Make sure you have Python installed, then install the required packages:

pip install -r requirements.txt
Run the Application:

streamlit run app.py
📁 Project Structure
ai-cybershield/
│
├── app.py                  # Main Streamlit application & ML pipeline
├── requirements.txt        # Python package dependencies
├── CEAS_08_trimmed.csv     # Optimized training dataset (Kaggle Phishing subset)
└── threat_logs.db          # SQLite persistent database (Auto-generated)
👨‍💻 Author & Credits
Developer: Aniket Rathi
Project Type: Minor Project / Professional Portfolio Showcase
⭐ Feel free to star this repository if you find it useful!
