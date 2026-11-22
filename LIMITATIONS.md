# Limitations

This is a working prototype, not a production system. Each limitation is mentioned below:

## Simulated services

| Limitation | Details | Label |
|---|---|---|
| PAN, GST, bank and risk checks are mocks | They answer from scripted scenarios. Real providers differ in request format, authentication, speed, rate limits and failure behaviour. | By design |
| No email or SMS | Messages to a merchant appear on their application page and in the audit trail only. | Not built |

## Reading documents

| Limitation | Details | Label |
|---|---|---|
| Accuracy on genuine documents is unknown | No real customer documents were used. Real PAN cards, GST certificates and cheques vary in layout; older or unusual layouts may need more label patterns. | Unverified |
| Small, compressed or low-quality photos read poorly | Tesseract misses small or heavily compressed text. | Weak spot |
| Only moderate tilts are corrected | Sideways, upside-down and tilted photos up to about 15° are straightened. Larger tilts and photos taken at an angle (perspective) are not. | Weak spot |
| Some photos are slow to read | A rotated photo takes a few seconds longer; a large image that is not a document takes up to about 10 s before the merchant is asked for a new one. | Weak spot |
| Strict upload rules | PDF, PNG and JPEG only; at most 5 MB and 40 million pixels; photos at least 800 pixels on the long side. | By design |

## Scale and deployment

| Limitation | Details | Label |
|---|---|---|
| Runs on one machine | The SQLite database and encrypted files live on local disk; several servers cannot share them. | By design |
| Writes happen one at a time | Correct under concurrent load, but requests queue. In a development load test (400 merchants, 60 at a time), all reached ACTIVE with no errors or duplicate merchants; most submissions took under 0.7 s and the slowest 7.7 s. | Weak spot |
| Not built for very high volume | Thousands of merchants per minute would need a shared database (e.g. Postgres) and different locking. | Not built |
| Document reading runs in the worker | A burst of photo uploads queues behind it. | Weak spot |
| Provider health is tracked per process | Each process learns separately that a provider is down. | Weak spot |
| No database migrations | After a code change that alters tables, the database may need `./reset.sh`. | Not built |

## Security and accounts

| Limitation | Details | Label |
|---|---|---|
| No password reset, email verification or multi-factor login | These need an email service. An admin can reset a password from the command line. | Not built |
| Sign-up reveals registered emails | Signing up with an existing email says the account exists. (Sign-in does not reveal this.) | Weak spot |
| Demo accounts and tokens are public | `Demo-Passw0rd!`, `reviewer-token` and `admin-token` are for demos. Set `ONB_SEED_DEMO_USERS=0` and `ONB_ALLOW_DEFAULT_TOKENS=0`, with your own tokens, for anything else. | By design |
| Encryption keys are plain files | Stored in `data/`, not in a key vault, with no rotation. Losing them makes stored data unreadable. | Not built |
| Accounts are managed from the command line | No admin web page for users; it needs shell access. | By design |
| Reviewers are trusted | Their decisions are recorded, not second-guessed. Approving can never skip a check that has not run. | By design |

## Data and workflow

| Limitation | Details | Label |
|---|---|---|
| Unfinished applications are never cleaned up | Retention starts only when an application ends (rejected, expired, withdrawn). One left in review or verification keeps its data. | Not built |
| Business name and PIN code are stored unencrypted | Needed to detect duplicates; cleared when a record is anonymised. | By design |
| The audit trail is protected only on SQLite | Database triggers make it append-only; another database would need its own protection. | Weak spot |
| A live merchant account cannot be closed | Withdraw works only before activation; closing an account (payouts, refunds) is not built. | Not built |
| Merchants cannot export or delete their data | They can view their applications and download their own uploads. | Not built |
| Duplicate detection is simple | Matches hashed PAN, GSTIN and bank account, plus a similar name in the same PIN code. Can miss clever variations or flag look-alikes. | Weak spot |
