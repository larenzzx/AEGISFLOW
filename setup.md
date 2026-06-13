# ⚙️ AegisFlow: Local Setup & Deployment Guide

This guide details how to configure, run, and host the AegisFlow Threat Intelligence dashboard locally on your system or deploy it online to Vercel.

---

## 💻 1. Local Development Setup

Follow these steps to run the application on your computer:

### Prerequisites
Make sure you have [Node.js](https://nodejs.org/) (version 20 or higher recommended) and `npm` installed.

### Step 1: Install Dependencies
Open your shell (Command Prompt, PowerShell, or Bash) in the project root directory and install node packages:
```bash
npm install
```

### Step 2: Launch Dev Server
Start the local development server:
```bash
npm run dev
```

### Step 3: Access the App
Open your web browser and navigate to:
```text
http://localhost:5173
```
*Vite's Hot Module Replacement (HMR) is active; any edits made to `src/App.tsx` or `src/lib/threatService.ts` will immediately render in the browser.*

---

## 🔑 2. Configuring Live API Keys

By default, AegisFlow runs in a simulated **sandbox sandbox mode**. It intercepts requests and feeds mock threat data so you can test features instantly. 

To enable live query lookup:
1. Register and acquire free API keys from the respective threat intelligence feeds:
   * **VirusTotal API v3**: [virustotal.com](https://www.virustotal.com/) (API key from your profile dropdown)
   * **AbuseIPDB API v2**: [abuseipdb.com](https://www.abuseipdb.com/) (API tab under Account menu)
   * **AlienVault OTX API v1**: [otx.alienvault.com](https://otx.alienvault.com/) (API key from registration settings)
2. In the AegisFlow dashboard sidebar on the left, click **CONFIGURE API KEYS**.
3. Paste your API keys into the corresponding input fields and click **SAVE KEYS**.
4. The indicators in the bottom left sidebar will change from `NOT SET` to `LIVE`.
5. Run a scan. The tool will query live threat databases and display real-time security logs.

*Note: All API keys are stored securely inside your browser's local storage (`localStorage.getItem("aegisflow_keys")`) and sent directly to endpoints without going through a middle-man server.*

---

## 🚀 3. Deploying to Vercel

Vercel is the easiest way to deploy and share front-end projects online.

### Option A: Deployment via Vercel CLI

1. **Install Vercel CLI globally**:
   ```bash
   npm install -g vercel
   ```
2. **Log in**:
   ```bash
   vercel login
   ```
3. **Deploy**:
   Run the deploy script from your project directory:
   ```bash
   vercel
   ```
4. **Answer Prompts**:
   * Set up and deploy: **Yes**
   * Select scope: **(your workspace)**
   * Link to existing project: **No**
   * Project name: **aegisflow**
   * Directory: **./**
   * Override default settings? **No**
5. **Get production link**:
   Vercel will build the bundles and output a live preview URL (e.g. `https://aegisflow.vercel.app`).
   To deploy it to your production domain:
   ```bash
   vercel --prod
   ```

### Option B: Deploying via GitHub Integration (Recommended)

This method enables automatic deployment every time you push code to GitHub:
1. Initialize git and push the directory to a new **GitHub repository**:
   ```bash
   git init
   git add .
   git commit -m "Initial AegisFlow commit"
   # Create a repository on GitHub, then link it:
   git remote add origin https://github.com/yourusername/aegisflow.git
   git branch -M main
   git push -u origin main
   ```
2. Go to [vercel.com](https://vercel.com/) and log in.
3. Click **Add New** > **Project**.
4. Import your `aegisflow` repository from GitHub.
5. In the configuration panel:
   * **Framework Preset**: select **Vite** (Vercel should auto-detect this).
   * **Build Command**: `npm run build`
   * **Output Directory**: `dist`
6. Click **Deploy**. Vercel will build and host your command center. Every time you push changes to your repository, it will rebuild automatically!
