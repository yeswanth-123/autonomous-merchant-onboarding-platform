# Autonomous Merchant Onboarding Platform

Merchants apply online and upload their PAN card, GST certificate and cancelled cheque. The platform reads the
documents, verifies them with (mock) providers, and either activates the merchant or sends the application to a
reviewer.

## Requirements

- Linux (Ubuntu / Debian / Fedora) or macOS. On Windows, use WSL (Ubuntu).

## Setup

1. Open a terminal and go to the project folder. The name has spaces, so keep the quotes:

   ```bash
   cd "Autonomous Merchant Onboarding Platform"
   ```

2. Run the setup script:

   ```bash
   ./setup.sh
   ```

   If you see `Permission denied`, give the scripts permission to run:

   ```bash
   chmod +x setup.sh run.sh reset.sh
   ```

   `setup.sh` does the following, and skips anything that is already done:

   | Step | What happens |
   |---|---|
   | 1 | Finds Python 3.10 or newer; installs it if missing |
   | 2 | Installs Python's `venv` module if missing |
   | 3 | Creates `.venv/` inside the folder and installs the packages from `requirements.txt` |
   | 4 | Creates `data/` and the settings file `.env` (copied from `.env.example`) |
   | 5 | Creates the database `data/onboarding.db` and the demo accounts |
   | 6 | Installs Tesseract (reads photos of documents) if missing |

   On Linux, steps 1, 2 and 6 use `sudo` and may show:

   ```
   [sudo] password for <your-username>:
   ```

   Type your login password (nothing appears while typing) and press Enter. On macOS, Homebrew is used and no
   password is needed.

   Setup finishes with:

   ```
   Setup complete. Next:
     ./run.sh            start mock providers + worker + API   (open http://127.0.0.1:8000)
   ```

3. Start the platform:

   ```bash
   ./run.sh
   ```

4. Open http://127.0.0.1:8000 in a browser.

5. Stop it with `Ctrl+C` in the terminal.

Run `./setup.sh` once. After that, `./run.sh` is all you need.

## Sign in

Password for all demo accounts: `Demo-Passw0rd!`

| Role | Email | Can do |
|---|---|---|
| Merchant | `merchant@demo.local` | Apply, upload documents, track and fix their own applications |
| Reviewer | `reviewer@demo.local` | Review queue: approve, reject, request info, re-verify |
| Admin | `admin@demo.local` | Everything a reviewer can do, plus failed jobs and metrics |

New merchants can also create their own account with **Create an account** on the sign-in page.

## Addresses

| What | Address |
|---|---|
| Platform | http://127.0.0.1:8000 |
| API docs | http://127.0.0.1:8000/docs |
| Mock providers | http://127.0.0.1:8001/docs |

## Start over

Deletes all accounts, applications and uploaded documents, then recreates the demo accounts. Stop `./run.sh` first.

```bash
./reset.sh
```

## Accounts from the command line

```bash
.venv/bin/python scripts/manage_users.py list
.venv/bin/python scripts/manage_users.py create EMAIL reviewer --name "Full Name"   # asks for the password twice
.venv/bin/python scripts/manage_users.py set-role EMAIL admin        # merchant | reviewer | admin
.venv/bin/python scripts/manage_users.py disable EMAIL
.venv/bin/python scripts/manage_users.py enable EMAIL
.venv/bin/python scripts/manage_users.py reset-password EMAIL
```

## Settings

Edit `.env`, then restart `./run.sh`. All settings are listed in `.env.example`. The common ones:

| Setting | Default | Meaning |
|---|---|---|
| `API_PORT` | `8000` | Port of the platform |
| `MOCK_PORT` | `8001` | Port of the mock providers |
| `ONB_DEMO_STEP_SECONDS` | `0` | Seconds each state lasts, to follow a demo; `0` is full speed |
| `ONB_TIMEOUT_SECONDS` | `30` | How long to wait for a provider's answer |

## Document templates

`document_templates/` shows what each document looks like, with placeholders instead of real data: PAN card
(company and individual), GST certificate and cancelled cheque, plus blurred and name-mismatch versions. To try the
platform, upload documents that contain data, in the same format as these templates.

## Troubleshooting

| Problem | Fix |
|---|---|
| `Permission denied` when running a script | `chmod +x setup.sh run.sh reset.sh` |
| `Run ./setup.sh first` | Run `./setup.sh` |
| The page does not open, or the terminal reports the address or port is already in use | Another program uses port 8000 or 8001: stop it, or set `API_PORT` / `MOCK_PORT` in `.env` |
| A demo account cannot sign in | Stop `./run.sh`, run `./reset.sh`, start `./run.sh` again |
| Setup says tesseract could not be installed | Install it yourself: `sudo apt install tesseract-ocr` (Linux) or `brew install tesseract` (macOS). Until then, PDFs work and photos go to a reviewer |
| `pip` fails during setup | Check the internet connection and run `./setup.sh` again |
