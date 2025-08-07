import streamlit as st
import hashlib
import os
import uuid
from datetime import datetime
import sqlite3
import pandas as pd
import smtplib
import ssl
import google.generativeai as genai

DB_FILE = 'complaints.db'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password_hash BLOB NOT NULL,
            salt BLOB NOT NULL,
            verified BOOLEAN DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tickets (
            ticket_id TEXT PRIMARY KEY,
            query TEXT NOT NULL,
            status TEXT NOT NULL,
            category TEXT,
            priority TEXT,
            assigned_to TEXT,
            timestamp TEXT,
            user_email TEXT,
            feedback TEXT,
            FOREIGN KEY (user_email) REFERENCES users (email),
            FOREIGN KEY (assigned_to) REFERENCES agents (name)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            name TEXT PRIMARY KEY,
            category TEXT,
            workload INTEGER DEFAULT 0,
            available BOOLEAN DEFAULT 1,
            skills TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

if "page" not in st.session_state:
    st.session_state["page"] = "login"
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "user_email" not in st.session_state:
    st.session_state["user_email"] = None

def register_user(email, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT email FROM users WHERE email = ?', (email,))
    if cursor.fetchone():
        conn.close()
        return False, "Email already exists."
    salt = os.urandom(16)
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    cursor.execute('INSERT INTO users (email, password_hash, salt, verified) VALUES (?, ?, ?, ?)',
                   (email, hashed_password, salt, True))
    conn.commit()
    conn.close()
    return True, "User registered successfully."

def authenticate_user(email, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash, salt, verified FROM users WHERE email = ?', (email,))
    user_data = cursor.fetchone()
    conn.close()
    if not user_data:
        return False, "User not registered. Please register first."
    stored_hash, stored_salt, verified = user_data
    provided_password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), stored_salt, 100000)
    if provided_password_hash == stored_hash:
        return True, "Authentication successful."
    else:
        return False, "Invalid email or password."

initial_agents_data = {
    "shipping": [{"name": "Agent_A", "workload": 0, "available": True, "skills": ["shipping", "tracking"]}, {"name": "Agent_E", "workload": 0, "available": True, "skills": ["shipping"]}],
    "refund": [{"name": "Agent_B", "workload": 0, "available": True, "skills": ["refund", "returns"]}, {"name": "Agent_F", "workload": 0, "available": True, "skills": ["refund"]}],
    "login": [{"name": "Agent_C", "workload": 0, "available": True, "skills": ["login", "account management"]}, {"name": "Agent_G", "workload": 0, "available": True, "skills": ["login"]}],
    "cancellation": [{"name": "Agent_D", "workload": 0, "available": True, "skills": ["cancellation"]}, {"name": "Agent_H", "workload": 0, "available": True, "skills": ["cancellation"]}],
    "default": [{"name": "Agent_X", "workload": 0, "available": True, "skills": ["general support"]}, {"name": "Agent_Y", "workload": 0, "available": True, "skills": ["general support"]}]
}

def init_agents():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM agents')
    count = cursor.fetchone()[0]
    if count == 0:
        for category, agents in initial_agents_data.items():
            for agent in agents:
                skills_str = ",".join(agent.get("skills", []))
                cursor.execute('INSERT INTO agents (name, category, workload, available, skills) VALUES (?, ?, ?, ?, ?)',
                               (agent["name"], category, agent["workload"], agent["available"], skills_str))
        conn.commit()
    conn.close()

init_agents()

def get_all_agents():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM agents')
    agents = cursor.fetchall()
    processed_agents = []
    for agent_row in agents:
        agent_dict = {
            'name': agent_row['name'],
            'category': agent_row['category'],
            'workload': agent_row['workload'],
            'available': bool(agent_row['available']),
            'skills': agent_row['skills'].split(',') if agent_row['skills'] else []
        }
        processed_agents.append(agent_dict)
    conn.close()
    return processed_agents

def get_agents_by_category(category):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM agents WHERE category = ? OR category = "default"', (category,))
    agents = cursor.fetchall()
    processed_agents = []
    for agent_row in agents:
        agent_dict = {
            'name': agent_row['name'],
            'category': agent_row['category'],
            'workload': agent_row['workload'],
            'available': bool(agent_row['available']),
            'skills': agent_row['skills'].split(',') if agent_row['skills'] else []
        }
        processed_agents.append(agent_dict)
    conn.close()
    return processed_agents

def update_agent_workload(agent_name, workload_change):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE agents SET workload = workload + ? WHERE name = ?', (workload_change, agent_name))
    conn.commit()
    conn.close()

def categorize_query(query):
    query_lower = query.lower()
    if "shipping" in query_lower or "delivery" in query_lower or "track" in query_lower:
        return "shipping"
    elif "refund" in query_lower or "money back" in query_lower or "return" in query_lower:
        return "refund"
    elif "login" in query_lower or "password" in query_lower or "account" in query_lower:
        return "login"
    elif "cancel" in query_lower or "cancellation" in query_lower:
        return "cancellation"
    else:
        return "default"

def ask_gemini(prompt):
    try:
        api_key = st.secrets["GOOGLE_API_KEY"]
        if api_key is None:
            raise ValueError("API key not found in secrets.")
        try:
            current_config = genai.configure()
            if not hasattr(current_config, 'api_key') or current_config.api_key != api_key:
                genai.configure(api_key=api_key)
        except:
            pass
    except Exception as e:
        if "sentiment and urgency" in prompt:
            if "immediately" in prompt:
                return "Priority: High"
            elif "unhappy" in prompt or "damaged" in prompt:
                return "Priority: Medium"
            else:
                return "Priority: Low"
        elif "Based on the provided FAQs, answer the user query" in prompt:
            for doc in docs:
                if any(word.lower() in prompt.lower() for word in doc.split()[:5]):
                    return "ANSWER: " + doc
            return "NO_ANSWER"
        return "Mock response: Could not process the request."
    try:
        model = genai.GenerativeModel("gemini-2.5-pro")
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return "Error: Could not get response from AI model."

def determine_priority(query):
    prompt = f"""Analyze the sentiment and urgency of the following user support query. Based on the analysis, assign a priority level: 'High', 'Medium', or 'Low'.
Query: {query}
Priority:"""
    try:
        response = ask_gemini(prompt)
        response_lower = response.strip().lower()
        if "high" in response_lower:
            return "High"
        elif "medium" in response_lower:
            return "Medium"
        else:
            return "Low"
    except Exception as e:
        return "Low"

def assign_agent(category, skills_required=None):
    agents = get_agents_by_category(category)
    available_agents = [agent for agent in agents if agent["available"]]
    if skills_required:
        skilled_agents = [agent for agent in available_agents if any(skill in agent["skills"] for skill in skills_required)]
        if skilled_agents:
            available_agents = skilled_agents
    if not available_agents:
        return "No agent available"
    assigned_agent = min(available_agents, key=lambda agent: agent["workload"])
    update_agent_workload(assigned_agent["name"], 1)
    return assigned_agent["name"]

def raise_ticket(query, email):
    conn = sqlite3.connect(DB_FILE)
    category = categorize_query(query)
    priority = determine_priority(query)
    skills_required = [category] if category != "default" else ["general support"]
    agent = assign_agent(category, skills_required)
    ticket_id = str(uuid.uuid4())[:8]
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO tickets (ticket_id, query, status, category, priority, assigned_to, timestamp, user_email, feedback)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (ticket_id, query, "Pending", category, priority, agent, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), email, None))
    conn.commit()
    conn.close()
    return ticket_id

docs = [
    "When will my order be shipped? Your order will typically be shipped within 3-5 business days after confirmation.",
    "How can I track my shipment? You can track your shipment using the tracking link sent to your registered email or phone.",
    "What is the return policy? You can return items within 30 days of delivery if they are in original condition.",
    "How do I initiate a return? To initiate a return, please visit your orders page and select the item you wish to return.",
    "I forgot my password, how can I reset it? Click on 'Forgot Password' on the login page and follow the instructions to reset your password.",
    "How to change my account details? You can update your account details by navigating to your profile settings after logging in.",
    "How do I cancel my order? Orders can be cancelled within 2 hours of placement before processing begins.",
    "Can I cancel my order after it is shipped? Once shipped, orders cannot be cancelled but can be returned upon delivery.",
    "What if I do not receive any updates? Please check your spam folder or contact customer support for updates.",
    "How do I contact customer support? You can contact customer support via the chatbot, email, or phone number listed on our Contact Us page."
]

def handle_query(user_query, email=None):
    prompt = f"""You are a helpful support assistant. Answer the user's query based only on the provided FAQs.
FAQs:
{'- '.join(docs)}
User Query: {user_query}
If you can answer, start with "ANSWER: ". If not, respond with "NO_ANSWER"."""
    try:
        response = ask_gemini(prompt)
        response_text = response.strip()
        if response_text.startswith("ANSWER:"):
            answer = response_text.replace("ANSWER:", "").strip()
            return {"resolved": True, "answer": answer, "ticket_id": None}
        elif response_text == "NO_ANSWER":
            if email:
                ticket_id = raise_ticket(user_query, email)
                return {"resolved": False, "ticket_id": ticket_id, "message": f"Could not resolve query from FAQs. Ticket Raised: {ticket_id}"}
            else:
                return {"resolved": False, "ticket_id": None, "message": "Could not resolve query from FAQs. Please provide an email to raise a ticket."}
        else:
            if email:
                ticket_id = raise_ticket(user_query, email)
                return {"resolved": False, "ticket_id": ticket_id, "message": f"Could not process response from AI. Ticket Raised: {ticket_id}"}
            else:
                return {"resolved": False, "ticket_id": None, "message": "Could not process response from AI. Please provide an email to raise a ticket."}
    except Exception as e:
        if email:
            ticket_id = raise_ticket(user_query, email)
            return {"resolved": False, "ticket_id": ticket_id, "message": f"An error occurred while processing your query. Ticket Raised: {ticket_id}"}
        else:
            return {"resolved": False, "ticket_id": None, "message": "An error occurred while processing your query. Please provide an email to raise a ticket."}

def get_ticket_by_id(ticket_id):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM tickets WHERE ticket_id = ?', (ticket_id,))
    ticket = cursor.fetchone()
    conn.close()
    if ticket:
        return dict(ticket)
    return None

def get_user_tickets(email):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM tickets WHERE user_email = ?', (email,))
    tickets = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return tickets

def view_my_tickets(email):
    user_tickets = get_user_tickets(email)
    if not user_tickets:
        return f"🙁 No tickets found for user: {email}"
    output = f"📋 Your Tickets ({email}):\n"
    for ticket_info in user_tickets:
        output += "-" * 20 + "\n"
        output += f"🎫 Ticket ID: {ticket_info.get('ticket_id', 'N/A')}\n"
        output += f"Query: {ticket_info.get('query', 'N/A')}\n"
        output += f"Status: {ticket_info.get('status', 'N/A')}\n"
        output += f"Category: {ticket_info.get('category', 'N/A')}\n"
        output += f"Priority: {ticket_info.get('priority', 'N/A')}\n"
        output += f"Assigned to: {ticket_info.get('assigned_to', 'N/A')}\n"
        output += f"Timestamp: {ticket_info.get('timestamp', 'N/A')}\n"
        output += f"User Email: {ticket_info.get('user_email', 'N/A')}\n"
        output += f"Feedback: {ticket_info.get('feedback', 'N/A')}\n"
    output += "-" * 20 + "\n"
    return output

def track_ticket(ticket_id):
    ticket = get_ticket_by_id(ticket_id)
    if ticket:
        output = f"🎫 Ticket ID: {ticket_id}\n"
        output += f"Query: {ticket.get('query', 'N/A')}\n"
        output += f"Status: {ticket.get('status', 'N/A')}\n"
        output += f"Category: {ticket.get('category', 'N/A')}\n"
        output += f"Priority: {ticket.get('priority', 'N/A')}\n"
        output += f"Assigned to: {ticket.get('assigned_to', 'N/A')}\n"
        output += f"Timestamp: {ticket.get('timestamp', 'N/A')}\n"
        output += f"User Email: {ticket.get('user_email', 'N/A')}\n"
        output += f"Feedback: {ticket.get('feedback', 'N/A')}\n"
        return output
    else:
        return "❌ Ticket not found."

def provide_feedback(ticket_id, feedback_text):
    conn = sqlite3.connect(DB_FILE)
    ticket = get_ticket_by_id(ticket_id)
    if ticket:
        if ticket.get("status") == "Resolved":
            cursor = conn.cursor()
            cursor.execute('UPDATE tickets SET feedback = ? WHERE ticket_id = ?', (feedback_text, ticket_id))
            conn.commit()
            conn.close()
            return True, f"✅ Feedback recorded for Ticket ID {ticket_id}."
        else:
            conn.close()
            return False, f"🙁 Feedback can only be provided for resolved tickets."
    else:
        conn.close()
        return False, f"❌ Ticket ID {ticket_id} not found."

def admin_view_all_tickets():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM tickets')
    tickets = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return tickets

def admin_update_ticket_status(ticket_id, new_status):
    conn = sqlite3.connect(DB_FILE)
    ticket = get_ticket_by_id(ticket_id)
    if ticket:
        old_status = ticket.get('status')
        cursor = conn.cursor()
        cursor.execute('UPDATE tickets SET status = ? WHERE ticket_id = ?', (new_status, ticket_id))
        conn.commit()
        conn.close()
        message = f"✅ Status for Ticket ID {ticket_id} updated to: {new_status}"
        email = ticket.get('user_email')
        if email and old_status != new_status:
            send_notification(email, f"Your ticket status for ID {ticket_id} has been updated to {new_status}.")
            automated_response(ticket_id, new_status)
        return True, message
    else:
        conn.close()
        message = f"❌ Ticket ID {ticket_id} not found."
        return False, message

def admin_assign_ticket(ticket_id, new_agent):
    conn = sqlite3.connect(DB_FILE)
    ticket = get_ticket_by_id(ticket_id)
    if ticket:
        old_agent = ticket.get('assigned_to')
        if old_agent:
            update_agent_workload(old_agent, -1)
        cursor = conn.cursor()
        cursor.execute('UPDATE tickets SET assigned_to = ? WHERE ticket_id = ?', (new_agent, ticket_id))
        conn.commit()
        conn.close()
        update_agent_workload(new_agent, 1)
        message = f"✅ Ticket ID {ticket_id} assigned to: {new_agent}"
        return True, message
    else:
        conn.close()
        message = f"❌ Ticket ID {ticket_id} not found."
        return False, message

def admin_view_agent_workload():
    agents = get_all_agents()
    output = "📊 Agent Workload:\n"
    if not agents:
        output += "🙁 No agents found or an error occurred retrieving agent data."
    else:
        for agent_dict in agents:
            try:
                agent_name = agent_dict.get('name', 'N/A')
                agent_workload = agent_dict.get('workload', 'N/A')
                output += f"- {agent_name}: {agent_workload} tickets\n"
            except Exception as e:
                output += f"- Error displaying agent data: {e}\n"
    return output

def send_notification(email, message):
    import smtplib
    import ssl
    sender_email = st.secrets["SENDER_EMAIL"]
    sender_password = st.secrets["SENDER_EMAIL_PASSWORD"]
    receiver_email = email
    if not sender_email or not sender_password:
        print(f"\n⚠️ Cannot send email notification to {receiver_email}: Sender email credentials not found.")
        print(f"🔔 Placeholder Notification for {receiver_email}: {message}")
        return
    smtp_server = "smtp.gmail.com"
    port = 587
    context = ssl.create_default_context()
    try:
        server = smtplib.SMTP(smtp_server, port)
        server.starttls(context=context)
        server.login(sender_email, sender_password)
        subject = "Your Ticket Status Update"
        body = message
        email_text = f"Subject: {subject}\n\n{body}"
        server.sendmail(sender_email, receiver_email, email_text)
        print(f"\n✅ Email notification sent to {receiver_email}: {message}")
    except Exception as e:
        print(f"\n❌ Failed to send email notification to {receiver_email}: {e}")
        print(f"🔔 Placeholder Notification for {receiver_email}: {message}")
    finally:
        if 'server' in locals() and server:
            server.quit()

def automated_response(ticket_id, status):
    print(f"\n🤖 Automated Response for Ticket {ticket_id}: Your ticket status has been updated to {status}.")

def export_tickets_to_csv():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM tickets", conn)
    csv_data = df.to_csv(index=False)
    conn.close()
    return csv_data

ADMIN_EMAIL = "admin@test.com"
ADMIN_PASSWORD = "admin123"

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()
cursor.execute('SELECT email FROM users WHERE email = ?', (ADMIN_EMAIL,))
admin_exists = cursor.fetchone()
if not admin_exists:
    reg_success, message = register_user(ADMIN_EMAIL, ADMIN_PASSWORD)
    if reg_success:
        print(f"Admin user '{ADMIN_EMAIL}' registered successfully in DB.")
    else:
        print(f"Failed to register admin user in DB: {message}")
else:
    cursor.execute('UPDATE users SET verified = ? WHERE email = ?', (True, ADMIN_EMAIL))
    conn.commit()
conn.close()

def login_page():
    st.title("Complaint Management System Login")
    email = st.text_input("Email", key="login_email")
    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Login", key="login_button"):
        auth_success, message = authenticate_user(email, password)
        if auth_success:
            st.success(message)
            st.session_state["authenticated"] = True
            st.session_state["user_email"] = email
            st.session_state["page"] = "admin" if email == ADMIN_EMAIL else "user"
            st.rerun()
        else:
            st.error(message)
    st.write("---")
    if st.button("Register Here", key="go_to_register"):
        st.session_state["page"] = "register"
        st.rerun()

def registration_page():
    st.title("Register for Complaint Management System")
    new_email = st.text_input("Enter Email", key="register_email")
    new_password = st.text_input("Enter Password", type="password", key="register_password")
    confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")
    if st.button("Register", key="register_button"):
        if new_password == confirm_password:
            reg_success, message = register_user(new_email, new_password)
            if reg_success:
                st.success(message + " You can now log in.")
                st.session_state["page"] = "login"
                st.rerun()
            else:
                st.error(message)
        else:
            st.error("Passwords do not match.")
    st.write("---")
    if st.button("Back to Login", key="back_to_login"):
        st.session_state["page"] = "login"
        st.rerun()

def user_page():
    if st.session_state.get("authenticated") is not True or st.session_state.get("user_email") is None:
        st.warning("Please log in to access this page.")
        if st.button("Go to Login", key="user_go_to_login"):
            st.session_state["page"] = "login"
            st.rerun()
        return
    user_email = st.session_state["user_email"]
    if user_email == ADMIN_EMAIL:
        st.warning("Admins cannot access the user page.")
        if st.button("Go to Admin Dashboard", key="user_go_to_admin"):
            st.session_state["page"] = "admin"
            st.rerun()
        return
    st.title(f"Welcome, {user_email}!")
    if st.button("Logout", key="user_logout_button"):
        st.session_state["authenticated"] = False
        st.session_state["user_email"] = None
        st.session_state["page"] = "login"
        st.rerun()
    st.sidebar.header("Notifications")
    st.sidebar.info("No new notifications.")
    st.header("Chat with our Support Bot")
    user_query = st.text_input("Enter your query:", key="user_query_input")
    if st.button("Submit Query", key="submit_query_button"):
        if user_query:
            result = handle_query(user_query, email=user_email)
            if result and result.get("resolved"):
                st.success(f"Answer: {result.get('answer', 'N/A')}")
            elif result:
                st.info(result.get("message", "Could not resolve query. Ticket might have been raised."))
                if result.get("ticket_id"):
                    st.write(f"Your Ticket ID is: {result['ticket_id']}")
            else:
                st.error("An error occurred while processing your query.")
        else:
            st.warning("Please enter a query.")
    st.write("---")
    st.header("My Tickets")
    st.text(view_my_tickets(user_email))
    st.write("---")
    st.header("Track a Ticket")
    track_ticket_id = st.text_input("Enter Ticket ID to Track:", key="track_ticket_input")
    if st.button("Track Ticket", key="track_ticket_button"):
        if track_ticket_id:
            st.write(f"Tracking Ticket ID: {track_ticket_id}")
            st.text(track_ticket(track_ticket_id))
        else:
            st.warning("Please enter a Ticket ID.")
    st.write("---")
    st.header("Provide Feedback")
    feedback_ticket_id = st.text_input("Enter Ticket ID for Feedback:", key="feedback_ticket_input")
    feedback_text = st.text_area("Your Feedback:", key="feedback_text_input")
    if st.button("Submit Feedback", key="submit_feedback_button"):
        if feedback_ticket_id and feedback_text:
            success, message = provide_feedback(feedback_ticket_id, feedback_text)
            if success:
                st.success(message)
            else:
                st.error(message)
        else:
            st.warning("Please enter both Ticket ID and feedback.")
    st.write("---")
    st.header("Frequently Asked Questions (FAQs)")
    for i, faq in enumerate(docs):
        if "?" in faq:
            parts = faq.split("?", 1)
            st.write(f"**Q{i+1}:** {parts[0]}?")
            if len(parts) > 1 and parts[1].strip():
                st.write(f"**A{i+1}:** {parts[1].strip()}")
        else:
            st.write(f"**Q{i+1}:** {faq}")

def admin_page():
    if st.session_state.get("authenticated") is not True or st.session_state.get("user_email") is None or st.session_state.get("user_email") != ADMIN_EMAIL:
        st.warning("Please log in as the admin to access this page.")
        if st.button("Go to Login", key="admin_go_to_login"):
            st.session_state["page"] = "login"
            st.rerun()
        return
    st.title("Admin Dashboard")
    if st.button("Logout", key="admin_logout_button"):
        st.session_state["authenticated"] = False
        st.session_state["user_email"] = None
        st.session_state["page"] = "login"
        st.rerun()
    st.sidebar.header("Admin Logs/Notifications")
    st.sidebar.info("System messages or recent activity could appear here.")
    st.header("All Tickets")
    all_tickets = admin_view_all_tickets()
    if not all_tickets:
        st.info("🙁 No tickets found in the database.")
    else:
        for ticket_info in all_tickets:
            st.write(f"**Ticket ID:** {ticket_info.get('ticket_id', 'N/A')}")
            st.write(f"**Query:** {ticket_info.get('query', 'N/A')}")
            st.write(f"**Status:** {ticket_info.get('status', 'N/A')}")
            st.write(f"**Category:** {ticket_info.get('category', 'N/A')}")
            st.write(f"**Priority:** {ticket_info.get('priority', 'N/A')}")
            st.write(f"**Assigned to:** {ticket_info.get('assigned_to', 'N/A')}")
            st.write(f"**Timestamp:** {ticket_info.get('timestamp', 'N/A')}")
            st.write(f"**User Email:** {ticket_info.get('user_email', 'N/A')}")
            st.write(f"**Feedback:** {ticket_info.get('feedback', 'N/A')}")
            st.write("---")
    st.write("---")
    st.header("Update Ticket Status")
    ticket_ids = [ticket.get('ticket_id', 'N/A') for ticket in all_tickets if ticket.get('ticket_id')]
    selected_ticket_id = st.selectbox("Select Ticket ID to Update Status:", ticket_ids, key="update_ticket_id_select")
    new_status = st.selectbox("New Status", ["Pending", "In Progress", "Resolved", "Closed"], key="new_status_select")
    if st.button("Update Status", key="update_status_button"):
        if selected_ticket_id and new_status:
            success, message = admin_update_ticket_status(selected_ticket_id, new_status)
            if success:
                st.success(message)
                st.rerun()
            else:
                st.error(message)
        else:
            st.warning("Please select a Ticket ID and status.")
    st.write("---")
    st.header("Assign Ticket")
    assign_ticket_id = st.text_input("Ticket ID to Assign", key="assign_ticket_id_input")
    all_agents = get_all_agents()
    all_agent_names = [agent.get("name") for agent in all_agents if agent.get("name")]
    new_agent = st.selectbox("Assign Agent", all_agent_names, key="new_agent_select")
    if st.button("Assign Ticket", key="assign_ticket_button"):
        if assign_ticket_id and new_agent:
            success, message = admin_assign_ticket(assign_ticket_id, new_agent)
            if success:
                st.success(message)
                st.rerun()
            else:
                st.error(message)
        else:
            st.warning("Please provide Ticket ID and select an agent.")
    st.write("---")
    st.header("Agent Workload")
    st.text(admin_view_agent_workload())

def main_app():
    if st.session_state.get("page") == "login":
        login_page()
    elif st.session_state.get("page") == "register":
        registration_page()
    elif st.session_state.get("page") == "user":
        user_page()
    elif st.session_state.get("page") == "admin":
        admin_page()
    else:
        st.session_state["page"] = "login"
        st.rerun()

if __name__ == "__main__":
    try:
        main_app()
    except Exception as e:
        st.error(f"An unexpected error occurred: {e}")c
