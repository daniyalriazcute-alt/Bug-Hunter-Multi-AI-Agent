
### Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11+ |
| Orchestration | LangGraph |
| LLM | Groq (Llama 3.3 70B) |
| UI | Streamlit |
| PDF | ReportLab + Jinja2 |
| Recon | nmap, dnspython, python-whois, subfinder |
| Vuln Scanning | nuclei (auto-downloaded) |

---

## 🚀 Quickstart

### Local Setup

```bash
# 1. Clone the repository
git clone https://github.com/daniyalriazcute-alt/Testing-Purpose-.git
cd Testing-Purpose-

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install system tools (Linux/macOS)
sudo apt install nmap            # Debian/Ubuntu
brew install nmap                # macOS

# 5. Set up environment variables
cp .env.example .env
# Edit .env and add: GROQ_API_KEY=gsk_your_key_here

# 6. Run the app
streamlit run app.py
