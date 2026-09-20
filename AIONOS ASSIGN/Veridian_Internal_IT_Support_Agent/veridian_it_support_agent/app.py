import json, re, uuid
from datetime import datetime
from pathlib import Path
import streamlit as st

BASE = Path(__file__).parent
DATA = BASE / "data"

def load(name):
    return json.loads((DATA / name).read_text(encoding="utf-8"))

POLICIES = load("policies.json")
HISTORY = load("tickets.json")
REQUESTS = load("employee_requests.json")
PBYID = {p["id"]: p for p in POLICIES}

def policy(pid):
    return PBYID[pid]

def add_audit(event, detail, source=None):
    st.session_state.audit.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event": event, "detail": detail, "source": source or "-"
    })

def make_ticket(employee, email, summary, category, priority, status, source, next_action, fields=None):
    t = {
        "ticket_id": "TK-AUTO-" + uuid.uuid4().hex[:6].upper(),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "employee": employee or "Unknown",
        "email": email or "Unknown",
        "category": category,
        "summary": summary,
        "priority": priority,
        "status": status,
        "source": source,
        "next_action": next_action,
        "fields": fields or {}
    }
    st.session_state.tickets.insert(0, t)
    add_audit("Ticket created", f'{t["ticket_id"]}: {summary}', source)
    return t

def classify(text):
    t = text.lower()
    # Security must be checked first.
    if any(x in t for x in ["phishing", "malware", "unauthorized access", "suspicious email", "suspicious link"]):
        return "security"
    if "expense" in t or "expense tool" in t:
        return "expense"
    if "vpn" in t:
        return "vpn"
    if any(x in t for x in ["password", "locked out", "login", "account locked"]):
        return "password"
    if any(x in t for x in ["laptop", "computer", "screen flicker"]):
        return "laptop"
    if "printer" in t or "paper jam" in t:
        return "printer"
    if any(x in t for x in ["mailbox", "mail", "email quota", "inbox full"]):
        return "mailbox"
    if any(x in t for x in ["guest wi-fi", "guest wifi", "guest wifi", "visitor wi-fi", "visitor wifi"]):
        return "guest_wifi"
    if any(x in t for x in ["monitor", "home office", "work from home", "wfh"]):
        return "home_equipment"
    if any(x in t for x in ["software", "install", "browser extension", "extension"]):
        return "software"
    if any(x in t for x in ["admin access", "server access", "administrator"]):
        return "admin"
    return "unclear"

def run_agent(message, employee="", email=""):
    intent = classify(message)
    add_audit("Request received", message)

    if intent == "unclear":
        add_audit("Follow-up requested", "Issue could not be safely classified")
        return {
            "status":"Need information",
            "understanding":"I need a little more information before I can route this safely.",
            "action":"What exactly is not working, and which application/device/service is affected?",
            "source":"None — no policy was safely matched.",
            "ticket":None
        }

    if intent == "security":
        p = policy("KB-09")
        ticket = make_ticket(employee,email,"Suspected security incident: " + message,
                             "Security Incident","High","Escalated to Security","KB-09",
                             "Report immediately to security@veridian-corp.example; do not forward the suspicious message.")
        add_audit("Security escalation","Suspected phishing/malware/unauthorized access", "KB-09")
        return {"status":"Escalated","understanding":"This may be a security incident.",
                "action":"Report immediately to security@veridian-corp.example and do not forward the message to other employees.",
                "source":"KB-09 — Security Incident Reporting","ticket":ticket}

    if intent == "password":
        if re.search(r"\b(5|6|7|8|9|10|[1-9]\d+)\s*(?:failed )?(?:attempts|tries|times)\b", message.lower()):
            p=policy("KB-01")
            ticket=make_ticket(employee,email,"Account locked after repeated password attempts",
                               "Account Access","Normal","Escalated to IT","KB-01",
                               "IT must manually unlock the account; no approval required.")
            add_audit("Escalated","Account lockout after more than 5 failed attempts","KB-01")
            return {"status":"Escalated","understanding":"The account appears locked after repeated failed attempts.",
                    "action":"IT needs to unlock the account manually. No approval is required.",
                    "source":"KB-01 — Password Reset","ticket":ticket}
        p=policy("KB-01")
        return {"status":"Resolved","understanding":"You can reset your own password using the self-service portal.",
                "action":"Use the self-service password reset portal. If you are locked out after 5 failed attempts, IT must unlock the account manually.",
                "source":"KB-01 — Password Reset","ticket":None}

    if intent == "vpn":
        contractor = "contractor" in message.lower()
        expired = "expired" in message.lower()
        p=policy("KB-02")
        if contractor:
            ticket=make_ticket(employee,email,"Contractor VPN access request","VPN Access","Normal","Pending manager approval","KB-02",
                               "Manager approval must be submitted via the access request form.")
            add_audit("Escalated","Contractor VPN requires manager approval","KB-02")
            return {"status":"Escalated","understanding":"This is a contractor VPN access request.",
                    "action":"Manager approval must be submitted via the access request form before access can be granted.",
                    "source":"KB-02 — VPN Access","ticket":ticket}
        if expired:
            return {"status":"Resolved","understanding":"The VPN credentials have expired.",
                    "action":"Renew the VPN credentials; VPN credentials expire every 90 days and must be renewed by the employee.",
                    "source":"KB-02 — VPN Access","ticket":None}
        return {"status":"Resolved","understanding":"VPN access is available automatically to full-time employees.",
                "action":"If you are a full-time employee, VPN access is granted automatically. Credentials must be renewed every 90 days.",
                "source":"KB-02 — VPN Access","ticket":None}

    if intent == "laptop":
        age = re.search(r"(\d+(?:\.\d+)?)\s*(?:years|yrs)", message.lower())
        hardware = any(x in message.lower() for x in ["won’t turn on","won't turn on","completely dead","dead","hardware failure","flickering"])
        years = float(age.group(1)) if age else None
        if hardware and years is not None and years >= 3:
            ticket=make_ticket(employee,email,"Laptop hardware issue / possible replacement","Hardware","Normal","Needs IT assessment","KB-03; POL-01",
                               "Verify hardware failure and replacement eligibility. Requests normally require 2 weeks advance notice; early replacement outside the 4-year refresh cycle also requires Finance sign-off.",
                               {"reported_age_years":years})
            add_audit("Escalated","Laptop issue requires hardware verification; policy sources conflict on refresh timing, so human review is retained","KB-03; POL-01")
            return {"status":"Escalated","understanding":f"The laptop is reported at about {years:g} years old and has a hardware/power problem.",
                    "action":"Create an IT hardware assessment. Replacement eligibility depends on verified hardware failure and the applicable replacement policy; human review is required.",
                    "source":"KB-03 — Laptop Replacement; POL-01 — Asset Management Policy","ticket":ticket}
        if years is not None and years >= 3:
            ticket=make_ticket(employee,email,"Laptop replacement eligibility inquiry","Hardware","Normal","Needs IT assessment","KB-03; POL-01",
                               "Confirm date of issue and assess replacement eligibility.")
            return {"status":"Need information","understanding":"The laptop may be approaching replacement eligibility.",
                    "action":"Please confirm the laptop's date of issue and whether there is a verified hardware failure.",
                    "source":"KB-03; POL-01","ticket":ticket}
        ticket=make_ticket(employee,email,"Laptop technical issue","Hardware","Normal","Escalated to IT","KB-03",
                           "IT should assess the hardware issue; replacement is not established from the provided information.")
        return {"status":"Escalated","understanding":"This is a laptop technical issue.",
                "action":"IT should inspect the device. The supplied policies do not provide a general repair procedure.",
                "source":"KB-03 — Laptop Replacement","ticket":ticket}

    if intent == "printer":
        asset = re.search(r"(?:asset\s*tag|asset)\s*[:#-]?\s*([A-Za-z0-9-]+)", message, re.I)
        if "after restart" not in message.lower() and "restarted" not in message.lower():
            return {"status":"Need information","understanding":"This is a printer issue.",
                    "action":"First check the printer queue and restart the print spooler. If the issue persists, tell me the printer's asset tag so I can create the ticket.",
                    "source":"KB-05 — Printer Troubleshooting","ticket":None}
        ticket=make_ticket(employee,email,"Printer issue after restart","Printer","Normal","Open — IT review","KB-05",
                           "IT review after queue/spooler troubleshooting.",
                           {"asset_tag":asset.group(1) if asset else "Not provided"})
        return {"status":"Escalated","understanding":"The printer issue persists after the first troubleshooting step.",
                "action":"Ticket created for IT. Include the printer asset tag if not already supplied.",
                "source":"KB-05 — Printer Troubleshooting","ticket":ticket}

    if intent == "mailbox":
        p=policy("KB-06")
        if "increase" in message.lower() or "quota" in message.lower():
            ticket=make_ticket(employee,email,"Mailbox quota increase request","Email","Normal","Pending manager approval","KB-06",
                               "Manager approval required; increase is capped at 50GB.")
            return {"status":"Escalated","understanding":"You are requesting a mailbox quota change.",
                    "action":"Quota increases beyond 25GB require manager approval and are capped at 50GB.",
                    "source":"KB-06 — Email Mailbox Quota","ticket":ticket}
        return {"status":"Resolved","understanding":"The mailbox is full / near its quota.",
                "action":"Archive old mail. The default mailbox quota is 25GB.",
                "source":"KB-06 — Email Mailbox Quota","ticket":None}

    if intent == "guest_wifi":
        return {"status":"Resolved","understanding":"You need temporary Wi-Fi for a guest.",
                "action":"Generate 24-hour guest Wi-Fi credentials from the front-desk kiosk. No IT ticket is required.",
                "source":"KB-07 — Guest Wi-Fi Access","ticket":None}

    if intent == "expense":
        p=policy("KB-08")
        ticket=make_ticket(employee,email,"Expense management tool login/technical issue","Finance-owned application","Normal","Routed to Finance / IT if technical",
                           "KB-08","Finance owns access. IT can assist only with login/technical issues once an account already exists.")
        return {"status":"Escalated","understanding":"This concerns the expense management tool.",
                "action":"Finance owns access. If an account already exists and the issue is technical/login-related, IT can assist.",
                "source":"KB-08 — Expense Software Access","ticket":ticket}

    if intent == "home_equipment":
        if re.search(r"\b[4-9]\s*(?:days|day)\b|\b[4-9]\s*days/week", message.lower()):
            ticket=make_ticket(employee,email,"Home-office equipment request","Home Office Equipment","Normal","Pending manager sign-off / Finance","KB-10",
                               "Manager sign-off and Finance processing are required; IT handles shipping only after approval.")
            return {"status":"Escalated","understanding":"You work remotely more than 3 days per week and are asking about home-office equipment.",
                    "action":"You are eligible for the one-time equipment allowance, but manager sign-off and Finance processing are required before IT can handle shipping.",
                    "source":"KB-10 — Work-From-Home Equipment","ticket":ticket}
        return {"status":"Need information","understanding":"You are asking about home-office equipment.",
                "action":"How many days per week do you normally work remotely? The supplied policy applies to employees working remotely more than 3 days/week.",
                "source":"KB-10 — Work-From-Home Equipment","ticket":None}

    if intent == "software":
        if "not in" in message.lower() or "non-catalog" in message.lower() or "browser extension" in message.lower():
            ticket=make_ticket(employee,email,"Non-catalog software installation request","Software","Normal","Pending Security review","KB-04",
                               "IT Security review required; expected review time is 3–5 business days.")
            return {"status":"Escalated","understanding":"This is a non-catalog software/extension request.",
                    "action":"IT Security review is required. The supplied policy says this takes 3–5 business days.",
                    "source":"KB-04 — Software Installation","ticket":ticket}
        return {"status":"Resolved","understanding":"This appears to be a standard software installation request.",
                "action":"If the software is in the approved catalog, it can be self-installed.",
                "source":"KB-04 — Software Installation","ticket":None}

    if intent == "admin":
        ticket=make_ticket(employee,email,"Admin access request","Privileged Access","High","Escalated for human review","Ticket history: TK-1050",
                           "Do not grant directly. Collect a business justification and route for human review.")
        return {"status":"Escalated","understanding":"This is a privileged/admin access request.",
                "action":"I cannot grant this directly. Please provide the business justification; the request will be routed for human review.",
                "source":"Ticket history TK-1050 — prior admin access request; no new grant policy supplied","ticket":ticket}

    return {"status":"Need information","understanding":"I need more information.","action":"Please describe the issue in more detail.","source":"None","ticket":None}

st.set_page_config(page_title="Veridian IT Support Agent", page_icon="🛠️", layout="wide")
if "tickets" not in st.session_state:
    st.session_state.tickets=[]
if "audit" not in st.session_state:
    st.session_state.audit=[]
if "messages" not in st.session_state:
    st.session_state.messages=[]

st.title("🛠️ Veridian Corp — Internal IT Support Agent")
st.caption("Assignment 2 prototype • Source-grounded IT support • Local demo")

with st.sidebar:
    st.header("Agent controls")
    employee = st.text_input("Employee name", value="Demo Employee")
    email = st.text_input("Employee email", value="demo@veridian-corp.example")
    st.info("The agent uses only the supplied assignment data. No external knowledge is used.")
    if st.button("Clear session"):
        st.session_state.tickets=[]
        st.session_state.audit=[]
        st.session_state.messages=[]
        st.rerun()

tabs=st.tabs(["💬 Agent","🎫 Tickets","📋 Audit Trail","📚 Knowledge Base","🧪 Demo Cases"])

with tabs[0]:
    for m in st.session_state.messages:
        with st.chat_message(m["role"]):
            st.markdown(m["content"])
            if m.get("result"):
                r=m["result"]
                st.divider()
                st.write("**Status:**", r["status"])
                st.write("**Source:**", r["source"])
                if r["ticket"]:
                    st.json(r["ticket"])
    prompt=st.chat_input("Describe your IT issue…")
    if prompt:
        st.session_state.messages.append({"role":"user","content":prompt})
        result=run_agent(prompt,employee,email)
        reply=f'### Understanding\n{result["understanding"]}\n\n### Action / follow-up\n{result["action"]}\n\n### Status\n**{result["status"]}**\n\n### Source\n{result["source"]}'
        if result["ticket"]:
            reply += f'\n\n### Ticket created\n`{result["ticket"]["ticket_id"]}` — {result["ticket"]["status"]}'
        st.session_state.messages.append({"role":"assistant","content":reply,"result":result})
        st.rerun()

with tabs[1]:
    st.subheader("Structured ticket queue")
    if st.session_state.tickets:
        st.dataframe(st.session_state.tickets, use_container_width=True, hide_index=True)
    else:
        st.info("No tickets created in this session.")
    st.markdown("### Existing assignment ticket history")
    st.dataframe(HISTORY, use_container_width=True, hide_index=True)

with tabs[2]:
    st.subheader("Immutable-style session audit trail")
    if st.session_state.audit:
        st.dataframe(st.session_state.audit, use_container_width=True, hide_index=True)
    else:
        st.info("No audit events yet.")

with tabs[3]:
    st.subheader("Source material")
    for p in POLICIES:
        with st.expander(f'{p["id"]} — {p["title"]}'):
            st.write(p["text"])

with tabs[4]:
    st.subheader("Preloaded employee cases")
    for r in REQUESTS:
        with st.expander(f'{r["request_id"]} — {r["employee"]}: {r["request"]}'):
            st.write(f'**Email:** {r["email"]}')
            st.write(f'**Initial action:** {r["initial_action"]}')
            if st.button(f'Run agent on {r["request_id"]}', key=r["request_id"]):
                result=run_agent(r["request"],r["employee"],r["email"])
                st.success(result["status"])
                st.write(result["understanding"])
                st.write(result["action"])
                st.caption("Source: " + result["source"])
                if result["ticket"]:
                    st.json(result["ticket"])
