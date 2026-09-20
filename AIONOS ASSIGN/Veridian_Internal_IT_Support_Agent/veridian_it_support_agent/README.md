# Veridian Corp — Internal IT Support Agent

A runnable prototype for **Assignment 2: Internal Service Agent (IT Support)**.

## Features
- Employee chat interface
- Source-grounded intent classification and resolution
- Sensible follow-up questions
- Escalation for security/risky/unclear requests
- Structured ticket generation
- Source/policy shown with every response
- Session audit trail
- Existing ticket history and 15 supplied employee requests
- No external API key required

## Run locally

Requires Python 3.10+.

```bash
python -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate

pip install -r requirements.txt
streamlit run app.py
```

Then open the local URL shown by Streamlit.

## Demo script
Try these:
1. `I'm locked out of my account, tried my password 6 times.`
2. `My VPN stopped working, credentials expired.`
3. `I got a phishing email asking for my login.`
4. `Can I get Wi-Fi for a guest tomorrow?`
5. `My mailbox is full and I can't send emails.`
6. `I work from home 4 days a week, how do I get a monitor?`
7. `I need a browser extension that isn't in the catalog.`
8. `hey can you help, its not working`

## Architecture

```text
Streamlit UI
   ↓
Agent Orchestrator
   ├── Intent classifier
   ├── Policy/source matcher
   ├── Follow-up decision
   ├── Resolution / escalation policy
   ├── Ticket generator
   └── Audit logger
        ↓
Local JSON source data
   ├── policies.json
   ├── employee_requests.json
   └── tickets.json
```

## Important design decision
The prototype intentionally uses a deterministic policy engine rather than inventing company procedures. The assignment says to use only the supplied material as source data. An LLM can be added later for natural-language interpretation, while the policy/routing layer remains the guardrail.

## Submission
The assignment notes that a reviewer should be able to open and try the submission, such as through a hosted demo or a clearly documented one-command local run/GitHub.
