import streamlit as st

# GitHub Dark Mode Styling with subtle animations
st.markdown("""
    <style>
    html, body, .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }

    .stTextInput>div>div>input,
    .stTextArea>div>textarea,
    .stSelectbox>div>div>div>div {
        background-color: #161b22 !important;
        color: #c9d1d9 !important;
        border-radius: 6px;
        border: 1px solid #30363d;
        padding: 0.4rem;
        transition: all 0.3s ease-in-out;
    }

    .stButton>button {
        background-color: #238636 !important;
        color: white !important;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        font-weight: bold;
        transition: all 0.3s ease-in-out;
    }

    .stButton>button:hover {
        background-color: #2ea043 !important;
        transform: scale(1.03);
    }

    .stSidebar {
        background-color: #161b22 !important;
        color: #c9d1d9 !important;
    }

    .css-1d391kg, .css-18e3th9 {
        background-color: #0d1117 !important;
    }

    h1, h2, h3, h4 {
        color: #c9d1d9;
    }

    .element-container {
        transition: all 0.3s ease-in-out;
    }

    .element-container:hover {
        transform: scale(1.01);
    }

    footer {
        visibility: hidden;
    }
    </style>
""", unsafe_allow_html=True)

import streamlit as st

# GitHub Dark Mode Styling
st.markdown("""
    <style>
    .main {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    .stTextInput>div>div>input,
    .stTextArea>div>textarea,
    .stSelectbox>div>div>div>div {
        background-color: #161b22;
        color: #c9d1d9;
    }
    .stButton>button {
        background-color: #238636;
        color: white;
        border: none;
        border-radius: 6px;
    }
    .stSidebar {
        background-color: #161b22;
    }
    .css-1d391kg {
        background-color: #0d1117 !important;
    }
    footer {
        visibility: hidden;
    }
    </style>
""", unsafe_allow_html=True)

import streamlit as st
import hashlib
import os
import uuid
from datetime import datetime
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
import faiss
import google.generativeai as genai
import sys
from io import StringIO
import sqlite3 
import pandas as pd
import smtplib
import ssl



DB_FILE = 'complaints.db'

def init_db():
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password_hash BLOB NOT NULL,
                salt BLOB NOT NULL,
                verified BOOLEAN DEFAULT 0
            )
        ''')

        # Create tickets table
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

        # Create agents table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agents (
                name TEXT PRIMARY KEY,
                category TEXT,
                workload INTEGER DEFAULT 0,
                available BOOLEAN DEFAULT 1,
                skills TEXT -- Storing skills as a comma-separated string or JSON
            )
        ''')

        # Commit changes
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error during initialization: {e}")

    finally:
        if conn:
            conn.close()


init_db()

if "page" not in st.session_state:
    st.session_state["page"] = "login"
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "user_email" not in st.session_state:
    st.session_state["user_email"] = None


def register_user(email, password):
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT email FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            return False, "Email already exists."

        salt = os.urandom(16)
        hashed_password = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )

        cursor.execute('INSERT INTO users (email, password_hash, salt, verified) VALUES (?, ?, ?, ?)',
                       (email, hashed_password, salt, True)) # Automatically verified
        conn.commit()

        return True, "User registered successfully."
    except sqlite3.Error as e:
        print(f"Database error during user registration: {e}")
        return False, "An error occurred during registration. Please try again."
    finally:
        if conn:
            conn.close()


def authenticate_user(email, password):
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash, salt, verified FROM users WHERE email = ?', (email,))
        user_data = cursor.fetchone()

        if not user_data:
            return False, "User not registered. Please register first."

        stored_hash, stored_salt, verified = user_data

        provided_password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            stored_salt,
            100000
        )

        if provided_password_hash == stored_hash:

            
            return True, "Authentication successful."
        else:
            return False, "Invalid email or password." 
    except sqlite3.Error as e:
        print(f"Database error during user authentication: {e}")
        return False, "An error occurred during authentication. Please try again."
    finally:
        if conn:
            conn.close()

initial_agents_data = {
    "shipping": [{"name": "Agent_A", "workload": 0, "available": True, "skills": ["shipping", "tracking"]}, {"name": "Agent_E", "workload": 0, "available": True, "skills": ["shipping"]}],
    "refund": [{"name": "Agent_B", "workload": 0, "available": True, "skills": ["refund", "returns"]}, {"name": "Agent_F", "workload": 0, "available": True, "skills": ["refund"]}],
    "login": [{"name": "Agent_C", "workload": 0, "available": True, "skills": ["login", "account management"]}, {"name": "Agent_G", "workload": 0, "available": True, "skills": ["login"]}],
    "cancellation": [{"name": "Agent_D", "workload": 0, "available": True, "skills": ["cancellation"]}, {"name": "Agent_H", "workload": 0, "available": True, "skills": ["cancellation"]}],
    "default": [{"name": "Agent_X", "workload": 0, "available": True, "skills": ["general support"]}, {"name": "Agent_Y", "workload": 0, "available": True, "skills": ["general support"]}]
}

def init_agents():
     conn = None
     try:
          conn = sqlite3.connect(DB_FILE)
          cursor = conn.cursor()
          cursor.execute('SELECT COUNT(*) FROM agents')
          count = cursor.fetchone()[0]
          if count == 0:
               print("Initializing agents in the database.")
               for category, agents in initial_agents_data.items():
                    for agent in agents:
               
                         skills_str = ",".join(agent.get("skills", []))
                         cursor.execute('INSERT INTO agents (name, category, workload, available, skills) VALUES (?, ?, ?, ?, ?)',
                                        (agent["name"], category, agent["workload"], agent["available"], skills_str))
               conn.commit()
     except sqlite3.Error as e:
        print(f"Database error during agent initialization: {e}")
     finally:
        if conn:
            conn.close()


init_agents()


def get_all_agents():
     conn = None
     try:
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
                   'available': bool(agent_row['available']), # Convert integer to boolean
                   'skills': agent_row['skills'].split(',') if agent_row['skills'] else [] # Convert string back to list
               }
               processed_agents.append(agent_dict)
          return processed_agents
     except sqlite3.Error as e:
        print(f"Database error getting all agents: {e}")
        return []
     finally:
        if conn:
            conn.close()


def get_agents_by_category(category):
     conn = None
     try:
          conn = sqlite3.connect(DB_FILE)
          conn.row_factory = sqlite3.Row
          cursor = conn.cursor()
          cursor.execute('SELECT * FROM agents WHERE category = ? OR category = "default"', (category,))
          agents = cursor.fetchall() # Get sqlite3.Row objects
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
          return processed_agents
     except sqlite3.Error as e:
        print(f"Database error getting agents by category: {e}")
        return []
     finally:
        if conn:
            conn.close()


def update_agent_workload(agent_name, workload_change):
     conn = None
     try:
          conn = sqlite3.connect(DB_FILE)
          cursor = conn.cursor()
          cursor.execute('UPDATE agents SET workload = workload + ? WHERE name = ?', (workload_change, agent_name))
          conn.commit()
     except sqlite3.Error as e:
        print(f"Database error updating agent workload: {e}")
     finally:
        if conn:
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
        except Exception as config_error:
             print(f"Warning: Could not re-configure genai API key: {config_error}. Proceeding if already configured.")
        


    except Exception as e:
     
        print(f"Warning: Gemini API not available ({e}). Using mock function.")
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
        print(f"Error during real Gemini API call: {e}")
        return "Error: Could not get response from AI model."


def determine_priority(query):

    prompt = f"""Analyze the sentiment and urgency of the following user support query. Based on the analysis, assign a priority level: 'High', 'Medium', or 'Low'.

Consider these factors:
- Keywords indicating urgency (e.g., urgent, immediately, critical, ASAP, important).
- Overall sentiment (e.g., frustration, anger, satisfaction).

Examples:
Query: My order hasn't arrived and I need it immediately.
Priority: High

Query: Can you tell me about your return policy?
Priority: Low

Query: My recent purchase is damaged and I'm very unhappy.
Priority: Medium

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
        print(f"Error determining priority with Gemini: {e}")
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
    conn = None
    try:
        category = categorize_query(query)
        priority = determine_priority(query)
        skills_required = [category] if category != "default" else ["general support"]
        agent = assign_agent(category, skills_required) # Pass skills to assign_agent

        ticket_id = str(uuid.uuid4())[:8]

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO tickets (ticket_id, query, status, category, priority, assigned_to, timestamp, user_email, feedback)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (ticket_id, query, "Pending", category, priority, agent, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), email, None))
        conn.commit()

        return ticket_id
    except sqlite3.Error as e:
        print(f"Database error raising ticket: {e}")
        return None # Indicate failure
    finally:
        if conn:
            conn.close()



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
    prompt = f"""You are a helpful support assistant for a complaint management system.
You have access to a list of frequently asked questions (FAQs) and their answers.
Your primary goal is to answer the user's query based *only* on the information available in the provided FAQs.
If you find a relevant FAQ that directly addresses the user's query, provide the answer from the FAQ.
If the user's query is not covered by any of the provided FAQs, clearly state that you cannot find the answer in the FAQs and indicate that a ticket needs to be raised.

Here are the available FAQs:
{'- '.join(docs)}

User Query: {user_query}

Based *only* on the FAQs above:
If you can answer the query, provide the answer starting with "ANSWER: ".
If you cannot answer the query based on the FAQs, respond with "NO_ANSWER".
"""

    try:
        response = ask_gemini(prompt)
        response_text = response.strip()

        if response_text.startswith("ANSWER:"):
            answer = response_text.replace("ANSWER:", "").strip()
            return {"resolved": True, "answer": answer, "ticket_id": None}
        elif response_text == "NO_ANSWER":
             if email:
                ticket_id = raise_ticket(user_query, email) # Pass email
                return {"resolved": False, "ticket_id": ticket_id, "message": f"Could not resolve query from FAQs. Ticket Raised: {ticket_id}"}
             else:
                 return {"resolved": False, "ticket_id": None, "message": "Could not resolve query from FAQs. Please provide an email to raise a ticket."}
        else:
        
             print(f"Warning: Unexpected response from Gemini: {response_text}")
             if email:
                  ticket_id = raise_ticket(user_query, email)
                  return {"resolved": False, "ticket_id": ticket_id, "message": f"Could not process response from AI. Ticket Raised: {ticket_id}"}
             else:
                 return {"resolved": False, "ticket_id": None, "message": "Could not process response from AI. Please provide an email to raise a ticket."}


    except Exception as e:
        print(f"Error handling query with Gemini prompt: {e}")
        if email:
             ticket_id = raise_ticket(user_query, email)
             return {"resolved": False, "ticket_id": ticket_id, "message": f"An error occurred while processing your query. Ticket Raised: {ticket_id}"}
        else:
             return {"resolved": False, "ticket_id": None, "message": "An error occurred while processing your query. Please provide an email to raise a ticket."}


def get_ticket_by_id(ticket_id):
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM tickets WHERE ticket_id = ?', (ticket_id,))
        ticket = cursor.fetchone()
        if ticket:
            return dict(ticket)
        return None
    except sqlite3.Error as e:
        print(f"Database error getting ticket by ID: {e}")
        return None 
    finally:
        if conn:
            conn.close()


def get_user_tickets(email): 
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row 
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM tickets WHERE user_email = ?', (email,))
        tickets = [dict(row) for row in cursor.fetchall()]
        return tickets
    except sqlite3.Error as e:
        print(f"Database error getting user tickets: {e}")
        return [] 
    finally:
        if conn:
            conn.close()


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
    conn = None
    try:
        ticket = get_ticket_by_id(ticket_id) 
        if ticket:
            if ticket.get("status") == "Resolved": 
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute('UPDATE tickets SET feedback = ? WHERE ticket_id = ?', (feedback_text, ticket_id))
                conn.commit()
                return True, f"✅ Feedback recorded for Ticket ID {ticket_id}."
            else:
                return False, f"🙁 Feedback can only be provided for resolved tickets."
        else:
            return False, f"❌ Ticket ID {ticket_id} not found."
    except sqlite3.Error as e:
        print(f"Database error providing feedback: {e}")
        return False, "An error occurred while submitting feedback."
    finally:
        if conn:
            conn.close()


def admin_view_all_tickets():
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM tickets')
        tickets = [dict(row) for row in cursor.fetchall()] 

        if not tickets:
            return []

        return tickets 
    except sqlite3.Error as e:
        print(f"Database error viewing all tickets: {e}")
        return [] 
    finally:
        if conn:
            conn.close()


def admin_update_ticket_status(ticket_id, new_status):
    conn = None
    try:
        ticket = get_ticket_by_id(ticket_id) # Get ticket from DB
        if ticket:
            old_status = ticket.get('status') # Use lowercase key 'status'
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('UPDATE tickets SET status = ? WHERE ticket_id = ?', (new_status, ticket_id))
            conn.commit()

            message = f"✅ Status for Ticket ID {ticket_id} updated to: {new_status}"
            print(f"{message}") # Keep print for logging
            email = ticket.get('user_email')
            if email and old_status != new_status: # Only notify if status actually changed
                send_notification(email, f"Your ticket status for ID {ticket_id} has been updated to {new_status}.") # Include ticket ID in notification
                automated_response(ticket_id, new_status)
            return True, message
        else:
            message = f"❌ Ticket ID {ticket_id} not found."
            print(f"{message}") # Keep print for logging
            return False, message
    except sqlite3.Error as e:
        print(f"Database error updating ticket status: {e}")
        return False, "An error occurred while updating ticket status."
    finally:
        if conn:
            conn.close()


def admin_assign_ticket(ticket_id, new_agent):
    conn = None
    try:
        ticket = get_ticket_by_id(ticket_id) # Get ticket from DB
        if ticket:
            old_agent = ticket.get('assigned_to')
            if old_agent:
                 update_agent_workload(old_agent, -1) # Decrease workload for old agent

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('UPDATE tickets SET assigned_to = ? WHERE ticket_id = ?', (new_agent, ticket_id))
            conn.commit()

            update_agent_workload(new_agent, 1) # Increase workload for new agent

            message = f"✅ Ticket ID {ticket_id} assigned to: {new_agent}"
            print(f"{message}") # Keep print for logging
            return True, message
        else:
            message = f"❌ Ticket ID {ticket_id} not found."
            print(f"{message}") # Keep print for logging
            return False, message
    except sqlite3.Error as e:
        print(f"Database error assigning ticket: {e}")
        return False, "An error occurred while assigning the ticket."
    finally:
        if conn:
            conn.close()


# Modified to return data instead of printing for Streamlit display
def admin_view_agent_workload():
    agents = get_all_agents() # Get agents from DB
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
                 # Added extra error handling here to try and diagnose the issue if it persists
                 print(f"Error processing agent_dict: {agent_dict} - {e}")
                 output += f"- Error displaying agent data: {e}\n"

    return output

def send_notification(email, message):

    import smtplib
    import ssl
  


    sender_email = st.secrets["SENDER_EMAIL"] # Get sender email from secrets
    sender_password = st.secrets["SENDER_EMAIL_PASSWORD"] # Get sender password from secrets
    receiver_email = email # The user's email address

    if not sender_email or not sender_password:
        print(f"\n⚠️ Cannot send email notification to {receiver_email}: Sender email credentials not found in Colab Secrets.")
        print(f"🔔 Placeholder Notification for {receiver_email}: {message}") # Fallback to print placeholder
        return # Exit if credentials are not set

    # Using Gmail SMTP server as an example
    smtp_server = "smtp.gmail.com"
    port = 587  # For starttls

    # Create a secure SSL context
    context = ssl.create_default_context()

    try:
        # Connect to the SMTP server
        server = smtplib.SMTP(smtp_server, port)
        server.ehlo()  # Can be omitted
        server.starttls(context=context)  # Secure the connection
        server.ehlo()  # Can be omitted
        server.login(sender_email, sender_password)

        # Create the email message
        subject = "Your Ticket Status Update"
        body = message # Use the message passed to the function
        email_text = f"Subject: {subject}\n\n{body}"

        # Send the email
        server.sendmail(sender_email, receiver_email, email_text)
        print(f"\n✅ Email notification sent to {receiver_email}: {message}") # Confirmation print

    except Exception as e:
        # Print error if email sending fails
        print(f"\n❌ Failed to send email notification to {receiver_email}: {e}")
        print(f"🔔 Placeholder Notification for {receiver_email}: {message}") # Fallback to print placeholder
    finally:
        # Quit the SMTP server
        if 'server' in locals() and server:
             server.quit()


def automated_response(ticket_id, status):
    print(f"\n🤖 Automated Response for Ticket {ticket_id}: Your ticket status has been updated to {status}.")

# Example of integrating notifications into status update
def admin_update_ticket_status_with_notification(ticket_id, new_status):
    # This function is essentially the same as admin_update_ticket_status now,
    # as notifications are integrated there. Keeping for clarity.
    return admin_update_ticket_status(ticket_id, new_status)

# --- Export Ticket History (New Function) ---
def export_tickets_to_csv():
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        # Read SQL query into a pandas DataFrame
        df = pd.read_sql_query("SELECT * FROM tickets", conn)
        # Export DataFrame to CSV
        csv_data = df.to_csv(index=False)
        return csv_data
    except sqlite3.Error as e:
        print(f"Database error during CSV export: {e}")
        return None # Indicate failure
    except Exception as e:
        print(f"Error during CSV export: {e}")
        return None # Indicate failure
    finally:
        if conn:
            conn.close()


ADMIN_EMAIL = "admin@test.com"
ADMIN_PASSWORD = "admin123"

conn = None
try:
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
        print(f"Admin user '{ADMIN_EMAIL}' already exists in DB.")
        # Ensure admin user is marked as verified in DB if they already exist
        cursor.execute('UPDATE users SET verified = ? WHERE email = ?', (True, ADMIN_EMAIL))
        conn.commit()
        print(f"Admin user '{ADMIN_EMAIL}' found and marked as verified in DB.")
except sqlite3.Error as e:
    print(f"Database error during admin user check/registration: {e}")
finally:
    if conn:
        conn.close()

if "page" not in st.session_state:
    st.session_state["page"] = "login"
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "user_email" not in st.session_state:
    st.session_state["user_email"] = None

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
            if email == ADMIN_EMAIL:
                st.session_state["page"] = "admin"
            else:
                st.session_state["page"] = "user"
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
    user_query = st.text_input("Enter your query:", key="user_query_input") # Added a key
    if st.button("Submit Query", key="submit_query_button"): # Added a key
        if user_query:
            result = handle_query(user_query, email=user_email)
            if result and result.get("resolved"): # Check if result is not None and resolved
                st.success(f"Answer: {result.get('answer', 'N/A')}") # Use .get for safety
            elif result: # If result is not None but not resolved
                 st.info(result.get("message", "Could not resolve query. Ticket might have been raised.")) # Use .get for safety
                 # You might want to explicitly show the ticket ID if it was raised
                 if result.get("ticket_id"): # Use .get for safety
                      st.write(f"Your Ticket ID is: {result['ticket_id']}")
            else: # Handle case where handle_query returns None or unexpected
                 st.error("An error occurred while processing your query.")

        else:
            st.warning("Please enter a query.")

    st.write("---")

    st.header("My Tickets")
    st.text(view_my_tickets(user_email)) # Directly display returned string

    st.write("---")

    st.header("Track a Ticket")
    track_ticket_id = st.text_input("Enter Ticket ID to Track:", key="track_ticket_input") # Added a key
    if st.button("Track Ticket", key="track_ticket_button"): # Added a key
        if track_ticket_id:
            st.write(f"Tracking Ticket ID: {track_ticket_id}")
            st.text(track_ticket(track_ticket_id)) # Directly display returned string
        else:
            st.warning("Please enter a Ticket ID.")

    st.write("---")

    st.header("Provide Feedback")
    feedback_ticket_id = st.text_input("Enter Ticket ID for Feedback:", key="feedback_ticket_input") # Added a key
    feedback_text = st.text_area("Your Feedback:", key="feedback_text_input") # Added a key
    if st.button("Submit Feedback", key="submit_feedback_button"): # Added a key
        if feedback_ticket_id and feedback_text:
            success, message = provide_feedback(feedback_ticket_id, feedback_text)
            if success:
                st.success(message)
            else:
                st.error(message)
        else:
            st.warning("Please enter both Ticket ID and feedback.")

    st.write("---")

    # --- Display FAQs ---
    st.header("Frequently Asked Questions (FAQs)")
    # Access the global docs list from the main script
    global docs
    if docs: # Check if docs list is not empty
        for i, faq in enumerate(docs):
            # Split FAQ into question and answer for better formatting if possible
            if "?" in faq:
                parts = faq.split("?", 1)
                st.write(f"**Q{i+1}:** {parts[0]}?")
                if len(parts) > 1 and parts[1].strip():
                    st.write(f"**A{i+1}:** {parts[1].strip()}")
            else:
                 st.write(f"**Q{i+1}:** {faq}") # Display as is if no '?'
    else:
        st.info("No FAQs available at this time.")


def admin_page():
    # Add checks for session state variables
    if st.session_state.get("authenticated") is not True or st.session_state.get("user_email") is None or st.session_state.get("user_email") != ADMIN_EMAIL:
        st.warning("Please log in as the admin to access this page.")
        if st.button("Go to Login", key="admin_go_to_login"):
            st.session_state["page"] = "login"
            st.rerun()
        return


    st.title("Admin Dashboard")

    # Add a logout button
    if st.button("Logout", key="admin_logout_button"):
        st.session_state["authenticated"] = False
        st.session_state["user_email"] = None
        st.session_state["page"] = "login"
        st.rerun()

    # --- Placeholder for Admin Notifications/Logs ---
    # Admin might need a different type of notification area,
    # perhaps for system alerts or recent actions.
    st.sidebar.header("Admin Logs/Notifications")
    st.sidebar.info("System messages or recent activity could appear here.")
    # --- End Admin Notification Placeholder ---


    st.header("All Tickets")
    # Get all tickets as a list of dictionaries
    all_tickets = admin_view_all_tickets()

    if not all_tickets:
         st.info("🙁 No tickets found in the database.")
    else:
         # Display tickets in a more structured way (e.g., using st.dataframe or looping)
         # For simplicity, let's loop and display
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
    # Get ticket IDs for the dropdown
    ticket_ids = [ticket.get('ticket_id', 'N/A') for ticket in all_tickets if ticket.get('ticket_id')]
    selected_ticket_id = st.selectbox("Select Ticket ID to Update Status:", ticket_ids, key="update_ticket_id_select") # Changed to selectbox
    new_status = st.selectbox("New Status", ["Pending", "In Progress", "Resolved", "Closed"], key="new_status_select")
    if st.button("Update Status", key="update_status_button"):
        if selected_ticket_id and new_status:
            success, message = admin_update_ticket_status_with_notification(selected_ticket_id, new_status)
            if success:
                st.success(message)
                st.rerun() # Rerun to refresh the ticket list display
            else:
                st.error(message)
        else:
            st.warning("Please select a Ticket ID and status.")


    st.write("---")

    st.header("Assign Ticket")
    assign_ticket_id = st.text_input("Ticket ID to Assign", key="assign_ticket_id_input")
    all_agents = get_all_agents() # Get agents from DB
    all_agent_names = [agent.get("name") for agent in all_agents if agent.get("name")] # Get agent names safely
    new_agent = st.selectbox("Assign Agent", all_agent_names, key="new_agent_select")
    if st.button("Assign Ticket", key="assign_ticket_button"):
        if assign_ticket_id and new_agent:
            success, message = admin_assign_ticket(assign_ticket_id, new_agent)
            if success:
                st.success(message)
                st.rerun() # Rerun to refresh the ticket list display if needed (though assignment doesn't change the display format here)
            else:
                st.error(message)
        else:
            st.warning("Please provide Ticket ID and select an agent.")

    st.write("---")

    st.header("Agent Workload")
    # Ensure that admin_view_agent_workload returns a string
    # Re-attempting to fix the TypeError here by ensuring correct iteration and access
    agents = get_all_agents() # Get agents from DB
    output = "📊 Agent Workload:\n"
    if not agents:
        output += "🙁 No agents found or an error occurred retrieving agent data."
    else:
        # Iterate directly over the list of dictionaries returned by get_all_agents()
        for agent_dict in agents:
            # Access name and workload using dictionary keys, with .get for safety
            # This is the section that has repeatedly caused the TypeError
            try:
                agent_name = agent_dict.get('name', 'N/A')
                agent_workload = agent_dict.get('workload', 'N/A')
                output += f"- {agent_name}: {agent_workload} tickets\n"
            except Exception as e:
                 # Added extra error handling here to try and diagnose the issue if it persists
                 print(f"Error processing agent_dict: {agent_dict} - {e}")
                 output += f"- Error displaying agent data: {e}\n"
    st.text(output)


# --- Notifications and Automated Responses (Conceptual) ---
# In a real system, this would involve sending emails, in-app notifications, etc.
# For this implementation, we'll just add print statements as placeholders.

def send_notification(email, message):
    # Replace with actual email sending logic using smtplib

    # --- !!! IMPORTANT !!! ---
    # For security, store your email and password in Colab Secrets!
    # Add secrets named 'SENDER_EMAIL' and 'SENDER_EMAIL_PASSWORD' (or App Password)
    # --- !!! IMPORTANT !!! ---

    # Ensure userdata, smtplib, and ssl are imported within the function scope for Streamlit reliability
    import smtplib
    import ssl
    


    sender_email = st.secrets["SENDER_EMAIL"] # Get sender email from secrets
    sender_password = st.secrets["SENDER_EMAIL_PASSWORD"] # Get sender password from secrets
    receiver_email = email # The user's email address

    if not sender_email or not sender_password:
        print(f"\n⚠️ Cannot send email notification to {receiver_email}: Sender email credentials not found in Colab Secrets.")
        print(f"🔔 Placeholder Notification for {receiver_email}: {message}") # Fallback to print placeholder
        return # Exit if credentials are not set

    # Using Gmail SMTP server as an example
    smtp_server = "smtp.gmail.com"
    port = 587  # For starttls

    # Create a secure SSL context
    context = ssl.create_default_context()

    try:
        # Connect to the SMTP server
        server = smtplib.SMTP(smtp_server, port)
        server.ehlo()  # Can be omitted
        server.starttls(context=context)  # Secure the connection
        server.ehlo()  # Can be omitted
        server.login(sender_email, sender_password)

        # Create the email message
        subject = "Your Ticket Status Update"
        body = message # Use the message passed to the function
        email_text = f"Subject: {subject}\n\n{body}"

        # Send the email
        server.sendmail(sender_email, receiver_email, email_text)
        print(f"\n✅ Email notification sent to {receiver_email}: {message}") # Confirmation print

    except Exception as e:
        # Print error if email sending fails
        print(f"\n❌ Failed to send email notification to {receiver_email}: {e}")
        print(f"🔔 Placeholder Notification for {receiver_email}: {message}") # Fallback to print placeholder
    finally:
        # Quit the SMTP server
        if 'server' in locals() and server:
             server.quit()


def automated_response(ticket_id, status):
    print(f"\n🤖 Automated Response for Ticket {ticket_id}: Your ticket status has been updated to {status}.")

# Example of integrating notifications into status update
def admin_update_ticket_status_with_notification(ticket_id, new_status):
    # This function is essentially the same as admin_update_ticket_status now,
    # as notifications are integrated there. Keeping for clarity.
    return admin_update_ticket_status(ticket_id, new_status)

# --- Export Ticket History (New Function) ---
def export_tickets_to_csv():
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        # Read SQL query into a pandas DataFrame
        df = pd.read_sql_query("SELECT * FROM tickets", conn)
        # Export DataFrame to CSV
        csv_data = df.to_csv(index=False)
        return csv_data
    except sqlite3.Error as e:
        print(f"Database error during CSV export: {e}")
        return None # Indicate failure
    except Exception as e:
        print(f"Error during CSV export: {e}")
        return None # Indicate failure
    finally:
        if conn:
            conn.close()


ADMIN_EMAIL = "admin@test.com"
ADMIN_PASSWORD = "admin123"

conn = None
try:
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT email FROM users WHERE email = ?', (ADMIN_EMAIL,))
    admin_exists = cursor.fetchone()

    if not admin_exists:
        reg_success, message = register_user(ADMIN_EMAIL, ADMIN_PASSWORD)
        if reg_success:
            print(f"Admin user '{ADMIN_EMAIL}' registered successfully in DB.")
            # Since register_user now auto-verifies in DB, no separate verification needed here.
        else:
            print(f"Failed to register admin user in DB: {message}")
    else:
        print(f"Admin user '{ADMIN_EMAIL}' already exists in DB.")
        # Ensure admin user is marked as verified in DB if they already exist
        cursor.execute('UPDATE users SET verified = ? WHERE email = ?', (True, ADMIN_EMAIL))
        conn.commit()
        print(f"Admin user '{ADMIN_EMAIL}' found and marked as verified in DB.")
except sqlite3.Error as e:
    print(f"Database error during admin user check/registration: {e}")
finally:
    if conn:
        conn.close()

if "page" not in st.session_state:
    st.session_state["page"] = "login"
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "user_email" not in st.session_state:
    st.session_state["user_email"] = None

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
        st.error(f"An unexpected error occurred: {e}")
