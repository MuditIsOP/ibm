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
# from transformers import pipeline # Removed transformers

# Configure Generative AI (replace with your API key or use secrets manager)
# genai.configure(api_key="YOUR_API_KEY")
# Or use secrets manager:
# from google.colab import userdata
# GOOGLE_API_KEY=userdata.get('GOOGLE_API_KEY')
# genai.configure(api_key=GOOGLE_API_KEY)
# Assuming API key is set elsewhere or using a placeholder for local testing

# --- User Registration and Authentication ---
users_db = {} # In-memory storage for demonstration

def register_user(email, password):
    if email in users_db:
        return False, "Email already exists."

    salt = os.urandom(16)
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )

    users_db[email] = {
        "password_hash": hashed_password,
        "salt": salt,
        "verified": False,
        "verification_token": os.urandom(16).hex()
    }
    return True, "User registered successfully. Please verify your email."

def authenticate_user(email, password):
    user = users_db.get(email)
    if not user:
        return False, "Invalid email or password."

    stored_salt = user["salt"]
    stored_hash = user["password_hash"]

    provided_password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        stored_salt,
        100000
    )

    if provided_password_hash == stored_hash:
        # if not user["verified"]:
        #     return False, "Please verify your email."
        return True, "Authentication successful."
    else:
        return False, "Invalid email or password."

# --- AI-Powered Ticketing System ---
tickets_db = {}

category_agents = {
    "shipping": [{"name": "Agent_A", "workload": 0, "available": True, "skills": ["shipping", "tracking"]}, {"name": "Agent_E", "workload": 0, "available": True, "skills": ["shipping"]}], # Added skills
    "refund": [{"name": "Agent_B", "workload": 0, "available": True, "skills": ["refund", "returns"]}, {"name": "Agent_F", "workload": 0, "available": True, "skills": ["refund"]}], # Added skills
    "login": [{"name": "Agent_C", "workload": 0, "available": True, "skills": ["login", "account management"]}, {"name": "Agent_G", "workload": 0, "available": True, "skills": ["login"]}], # Added skills
    "cancellation": [{"name": "Agent_D", "workload": 0, "available": True, "skills": ["cancellation"]}, {"name": "Agent_H", "workload": 0, "available": True, "skills": ["cancellation"]}], # Added skills
    "default": [{"name": "Agent_X", "workload": 0, "available": True, "skills": ["general support"]}, {"name": "Agent_Y", "workload": 0, "available": True, "skills": ["general support"]}] # Added skills
}

agent_indices = {category: 0 for category in category_agents}


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

# Placeholder/Mock ask_gemini if not configured
def ask_gemini(prompt):
    # This is a mock implementation if genai is not configured or fails
    # print("Mock Gemini call:", prompt[:100] + "...")
    if 'genai' not in sys.modules or (hasattr(genai, 'configure') and genai.configure().api_key == "DUMMY_API_KEY"):
        # print("Using dummy ask_gemini function.")
        if "sentiment and urgency" in prompt:
            if "immediately" in prompt:
                return "Priority: High"
            elif "unhappy" in prompt or "damaged" in prompt:
                 return "Priority: Medium"
            else:
                return "Priority: Low"
        elif "Using only the information provided" in prompt:
            # Simple keyword-based mock response for document retrieval
            if "shipping" in prompt and "business days" in prompt:
                return "Your order will typically be shipped within 3-5 business days after confirmation."
            elif "track my shipment" in prompt and "tracking link" in prompt:
                return "You can track your shipment using the tracking link sent to your registered email or phone."
            elif "return policy" in prompt and "30 days" in prompt:
                return "You can return items within 30 days of delivery if they are in original condition."
            elif "initiate a return" in prompt and "orders page" in prompt:
                return "To initiate a return, please visit your orders page and select the item you wish to return."
            elif "forgot my password" in prompt and "Forgot Password" in prompt:
                 return "Click on 'Forgot Password' on the login page and follow the instructions to reset your password."
            elif "change my account details" in prompt and "profile settings" in prompt:
                return "You can update your account details by navigating to your profile settings after logging in."
            elif "cancel my order" in prompt and "within 2 hours" in prompt:
                 return "Orders can be cancelled within 2 hours of placement before processing begins."
            elif "cancel my order after it is shipped" in prompt and "cannot be cancelled" in prompt:
                 return "Once shipped, orders cannot be cancelled but can be returned upon delivery."
            elif "not receive any updates" in prompt and "spam folder" in prompt:
                 return "Please check your spam folder or contact customer support for updates."
            elif "contact customer support" in prompt and "chatbot, email, or phone number" in prompt:
                 return "You can contact customer support via the chatbot, email, or phone number listed on our Contact Us page."
            else:
                 return "I cannot find the answer in the provided document."
        return "Mock response: Could not process the request."
    # Real Gemini call
    try:
        model = genai.GenerativeModel("gemini-2.5-pro")
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Error during Gemini API call: {e}")
        return "Error: Could not get response from AI model."


def determine_priority(query):
    # Use Gemini for sentiment and priority determination
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
        # Attempt to extract priority from Gemini's response
        response_lower = response.strip().lower()
        if "high" in response_lower:
            return "High"
        elif "medium" in response_lower:
            return "Medium"
        else:
            return "Low" # Default to Low if not explicitly High or Medium
    except Exception as e:
        print(f"Error determining priority with Gemini: {e}")
        return "Low" # Default to Low in case of error


def assign_agent(category, skills_required=None): # Modified to include skills
    agents = category_agents.get(category, category_agents["default"])
    available_agents = [agent for agent in agents if agent["available"]]

    if skills_required:
        skilled_agents = [agent for agent in available_agents if any(skill in agent["skills"] for skill in skills_required)]
        if skilled_agents:
            available_agents = skilled_agents

    if not available_agents:
        return "No agent available" # Handle no available agents

    # Assign based on workload (simple load balancing)
    assigned_agent = min(available_agents, key=lambda agent: agent["workload"])
    assigned_agent["workload"] += 1
    return assigned_agent["name"]


def raise_ticket(query, email):
    category = categorize_query(query)
    priority = determine_priority(query)
    # Determine skills required based on category (can be more complex)
    skills_required = [category] if category != "default" else ["general support"]
    agent = assign_agent(category, skills_required) # Pass skills to assign_agent

    ticket_id = str(uuid.uuid4())[:8]
    tickets_db[ticket_id] = {
        "Query": query,
        "Status": "Pending",
        "category": category,
        "priority": priority,
        "assigned_to": agent,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user_email": email, # Changed from "user" to "user_email"
        "feedback": None # Added for feedback mechanism
    }
    return ticket_id

# --- AI-Powered Chatbot Integration ---
# Sample support data
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

# Create TF-IDF embeddings
vectorizer = TfidfVectorizer()
doc_vectors = vectorizer.fit_transform(docs).toarray()

# Setup FAISS index
dimension = doc_vectors.shape[1]
index = faiss.IndexFlatL2(dimension)
index.add(np.array(doc_vectors).astype("float32"))


def retrieve_answer_from_docs(user_query):
    query_vec = vectorizer.transform([user_query]).toarray().astype("float32")
    D, I = index.search(query_vec, k=1)
    # Lower the threshold slightly for better matching in this example
    if D[0][0] > 0.8:  # adjusted threshold
        return None
    return docs[I[0][0]]


def handle_query(user_query, email=None): # Changed username to email
    relevant_doc = retrieve_answer_from_docs(user_query)
    ticket_id = None

    if relevant_doc:
        prompt = f"""You are a helpful and concise support assistant. Using only the information provided in the following document, answer the user's query. If the document does not contain enough information to answer the query, please state that you cannot find the answer in the provided document.

Document: {relevant_doc}
Query: {user_query}
Answer:"""
        response = ask_gemini(prompt)
        # print(f"✅ Answer: {response}") # Remove print for Streamlit
        return {"resolved": True, "answer": response, "ticket_id": None}
    else:
        if email: # Changed username to email
            ticket_id = raise_ticket(user_query, email) # Pass email
            # print(f"🙁 Could not resolve query. Ticket Raised: {ticket_id}") # Remove print for Streamlit
            return {"resolved": False, "ticket_id": ticket_id}
        else:
             # print("🙁 Could not resolve query. Please provide an email to raise a ticket.") # Remove print for Streamlit
             return {"resolved": False, "ticket_id": None, "message": "Please provide an email to raise a ticket."} # Added message


# --- Real-time Complaint Status Tracking ---
def get_ticket_by_id(ticket_id):
    return tickets_db.get(ticket_id)

def get_user_tickets(email): # Changed username to email
    user_tickets = {}
    for ticket_id, ticket_info in tickets_db.items():
        if ticket_info.get("user_email") == email: # Changed "user" to "user_email"
            user_tickets[ticket_id] = ticket_info
    return user_tickets

# Modified to return data instead of printing for Streamlit display
def view_my_tickets(email): # Changed username to email
    user_tickets = get_user_tickets(email) # Pass email
    if not user_tickets:
        return f"🙁 No tickets found for user: {email}" # Changed username to email

    output = f"📋 Your Tickets ({email}):\n" # Changed username to email
    for ticket_id, ticket_info in user_tickets.items():
        output += "-" * 20 + "\n"
        output += f"🎫 Ticket ID: {ticket_id}\n"
        output += f"Query: {ticket_info.get('Query', 'N/A')}\n"
        output += f"Status: {ticket_info.get('Status', 'N/A')}\n"
        output += f"Category: {ticket_info.get('category', 'N/A')}\n"
        output += f"Priority: {ticket_info.get('priority', 'N/A')}\n"
        output += f"Assigned to: {ticket_info.get('assigned_to', 'N/A')}\n"
        output += f"Timestamp: {ticket_info.get('timestamp', 'N/A')}\n"
        output += f"User Email: {ticket_info.get('user_email', 'N/A')}\n" # Changed "User" to "User Email" and "user" to "user_email"
        output += f"Feedback: {ticket_info.get('feedback', 'N/A')}\n" # Added feedback
    output += "-" * 20 + "\n"
    return output


# Modified to return data instead of printing for Streamlit display
def track_ticket(ticket_id):
    ticket = tickets_db.get(ticket_id)
    if ticket:
        output = f"🎫 Ticket ID: {ticket_id}\n"
        output += f"Query: {ticket.get('Query', 'N/A')}\n"
        output += f"Status: {ticket.get('Status', 'N/A')}\n"
        output += f"Category: {ticket.get('category', 'N/A')}\n"
        output += f"Priority: {ticket.get('priority', 'N/A')}\n"
        output += f"Assigned to: {ticket.get('assigned_to', 'N/A')}\n"
        output += f"Timestamp: {ticket.get('timestamp', 'N/A')}\n"
        output += f"User Email: {ticket.get('user_email', 'N/A')}\n" # Changed "User" to "User Email" and "user" to "user_email"
        output += f"Feedback: {ticket.get('feedback', 'N/A')}\n" # Added feedback
        return output
    else:
        return "❌ Ticket not found."

# --- Feedback Mechanism (Innovative Feature) ---
def provide_feedback(ticket_id, feedback_text):
    ticket = tickets_db.get(ticket_id)
    if ticket:
        if ticket.get("Status") == "Resolved": # Only allow feedback on resolved tickets
            ticket["feedback"] = feedback_text
            # print(f"✅ Feedback recorded for Ticket ID {ticket_id}.") # Removed print for UI
            return True, f"✅ Feedback recorded for Ticket ID {ticket_id}."
        else:
            # print(f"🙁 Feedback can only be provided for resolved tickets.") # Removed print for UI
            return False, f"🙁 Feedback can only be provided for resolved tickets."
    else:
        # print(f"❌ Ticket ID {ticket_id} not found.") # Removed print for UI
        return False, f"❌ Ticket ID {ticket_id} not found."


# --- Admin Interface ---
# Modified to return data instead of printing for Streamlit display
def admin_view_all_tickets():
    if not tickets_db:
        return "🙁 No tickets found in the database."

    output = "📋 All Tickets:\n"
    for ticket_id, ticket_info in tickets_db.items():
        output += "-" * 20 + "\n"
        output += f"🎫 Ticket ID: {ticket_id}\n"
        output += f"Query: {ticket_info.get('Query', 'N/A')}\n"
        output += f"Status: {ticket_info.get('Status', 'N/A')}\n"
        output += f"Category: {ticket_info.get('category', 'N/A')}\n"
        output += f"Priority: {ticket_info.get('priority', 'N/A')}\n"
        output += f"Assigned to: {ticket_info.get('assigned_to', 'N/A')}\n"
        output += f"Timestamp: {ticket_info.get('timestamp', 'N/A')}\n"
        output += f"User Email: {ticket_info.get('user_email', 'N/A')}\n" # Changed "User" to "User Email" and "user" to "user_email"
        output += f"Feedback: {ticket_info.get('feedback', 'N/A')}\n" # Added feedback
    output += "-" * 20 + "\n"
    return output

def admin_update_ticket_status(ticket_id, new_status):
    ticket = tickets_db.get(ticket_id)
    if ticket:
        ticket['Status'] = new_status
        # print(f"✅ Status for Ticket ID {ticket_id} updated to: {new_status}") # Removed print for UI
        return True, f"✅ Status for Ticket ID {ticket_id} updated to: {new_status}"
    else:
        # print(f"❌ Ticket ID {ticket_id} not found.") # Removed print for UI
        return False, f"❌ Ticket ID {ticket_id} not found."

def admin_assign_ticket(ticket_id, new_agent):
    ticket = tickets_db.get(ticket_id)
    if ticket:
        old_agent = ticket.get('assigned_to')
        if old_agent:
             for category in category_agents.values():
                 for agent in category:
                     if agent["name"] == old_agent:
                         agent["workload"] -= 1

        ticket['assigned_to'] = new_agent

        for category in category_agents.values():
             for agent in category:
                 if agent["name"] == new_agent:
                     agent["workload"] += 1

        # print(f"✅ Ticket ID {ticket_id} assigned to: {new_agent}") # Removed print for UI
        return True, f"✅ Ticket ID {ticket_id} assigned to: {new_agent}"
    else:
        # print(f"❌ Ticket ID {ticket_id} not found.") # Removed print for UI
        return False, f"❌ Ticket ID {ticket_id} not found."

# Modified to return data instead of printing for Streamlit display
def admin_view_agent_workload():
    output = "📊 Agent Workload:\n"
    all_agents = [agent for agents in category_agents.values() for agent in agents]
    agent_workloads = {}
    for agent in all_agents:
         agent_workloads[agent["name"]] = agent.get("workload", 0)

    for agent_name, workload in agent_workloads.items():
        output += f"- {agent_name}: {workload} tickets\n"
    return output

# --- Notifications and Automated Responses (Conceptual) ---
# In a real system, this would involve sending emails, in-app notifications, etc.
# For this implementation, we'll just add print statements as placeholders.

def send_notification(email, message): # Changed user to email
    print(f"\n🔔 Notification for {email}: {message}") # Changed user to email

def automated_response(ticket_id, status):
    print(f"\n🤖 Automated Response for Ticket {ticket_id}: Your ticket status has been updated to {status}.")

# Example of integrating notifications into status update
def admin_update_ticket_status_with_notification(ticket_id, new_status):
    ticket = tickets_db.get(ticket_id)
    if ticket:
        old_status = ticket.get('Status')
        ticket['Status'] = new_status
        message = f"Status for Ticket ID {ticket_id} updated to: {new_status}"
        print(f"✅ {message}") # Keep print for logging
        email = ticket.get('user_email') # Changed user to user_email
        if email and old_status != new_status: # Only notify if status actually changed
            send_notification(email, f"Your ticket status has been updated to {new_status}.") # Pass email
            automated_response(ticket_id, new_status)
        return True, message
    else:
        message = f"Ticket ID {ticket_id} not found."
        print(f"❌ {message}") # Keep print for logging
        return False, message


ADMIN_EMAIL = "admin@test.com"
ADMIN_PASSWORD = "admin123"

# Check if admin user exists, register if not
if ADMIN_EMAIL not in users_db:
    reg_success, message = register_user(ADMIN_EMAIL, ADMIN_PASSWORD)
    if reg_success:
        print(f"Admin user '{ADMIN_EMAIL}' registered successfully.")
        # Immediately verify the admin user as email verification is not implemented
        users_db[ADMIN_EMAIL]["verified"] = True
        users_db[ADMIN_EMAIL]["verification_token"] = None
        print("Admin user verified.")
    else:
        print(f"Failed to register admin user: {message}")
else:
    # Ensure admin user is marked as verified if they already exist
    if not users_db[ADMIN_EMAIL].get("verified", False):
         users_db[ADMIN_EMAIL]["verified"] = True
         users_db[ADMIN_EMAIL]["verification_token"] = None
         print(f"Admin user '{ADMIN_EMAIL}' found and marked as verified.")
    else:
        print(f"Admin user '{ADMIN_EMAIL}' already exists and is verified.")


# Initialize session state
if "page" not in st.session_state:
    st.session_state["page"] = "login"
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "user_email" not in st.session_state:
    st.session_state["user_email"] = None

# --- Streamlit UI Functions ---

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
            st.rerun() # Changed from st.experimental_rerun() to st.rerun()
        else:
            st.error(message)

    st.write("---")
    # Placeholder for registration link (optional for this task)
    st.write("Don't have an account? [Register Here](link_to_registration_page)") # Replace with actual link later


def user_page():
    # Add checks for session state variables
    if st.session_state.get("authenticated") is not True or st.session_state.get("user_email") is None:
        st.warning("Please log in to access this page.")
        if st.button("Go to Login", key="user_go_to_login"):
            st.rerun() # Changed from st.experimental_rerun() to st.rerun()
        return

    user_email = st.session_state["user_email"]
    # Add an extra check to prevent admin from accessing user page directly
    if user_email == ADMIN_EMAIL:
         st.warning("Admins cannot access the user page.")
         if st.button("Go to Admin Dashboard", key="user_go_to_admin"):
              st.session_state["page"] = "admin"
              st.rerun() # Changed from st.experimental_rerun() to st.rerun()
         return


    st.title(f"Welcome, {user_email}!")

    # Add a logout button
    if st.button("Logout", key="user_logout_button"):
        st.session_state["authenticated"] = False
        st.session_state["user_email"] = None
        st.session_state["page"] = "login"
        st.rerun() # Changed from st.experimental_rerun() to st.rerun()

    # --- Placeholder for Notification Display ---
    # In a full implementation, this area could display recent notifications
    # fetched from a state variable or a dedicated notification system.
    st.sidebar.header("Notifications")
    # Example placeholder:
    # if "notifications" in st.session_state and st.session_state["notifications"]:
    #     for notif in st.session_state["notifications"]:
    #         st.sidebar.info(notif)
    # else:
    st.sidebar.info("No new notifications.")
    # --- End Notification Placeholder ---


    st.header("Chat with our Support Bot")
    user_query = st.text_input("Enter your query:", key="user_query_input") # Added a key
    if st.button("Submit Query", key="submit_query_button"): # Added a key
        if user_query:
            result = handle_query(user_query, email=user_email)
            if result["resolved"]:
                st.success(f"Answer: {result['answer']}")
            else:
                 if result.get("ticket_id"):
                    st.info(f"Could not resolve query. Ticket Raised: {result['ticket_id']}")
                 else:
                     st.warning(result.get("message", "Could not resolve query."))
        else:
            st.warning("Please enter a query.")

    st.write("---")

    st.header("My Tickets")
    st.write(view_my_tickets(user_email)) # Directly display returned string

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


def admin_page():
    # Add checks for session state variables
    if st.session_state.get("authenticated") is not True or st.session_state.get("user_email") != ADMIN_EMAIL:
        st.warning("Please log in as the admin to access this page.")
        if st.button("Go to Login", key="admin_go_to_login"):
            st.session_state["page"] = "login"
            st.rerun() # Changed from st.experimental_rerun() to st.rerun()
        return


    st.title("Admin Dashboard")

    # Add a logout button
    if st.button("Logout", key="admin_logout_button"):
        st.session_state["authenticated"] = False
        st.session_state["user_email"] = None
        st.session_state["page"] = "login"
        st.rerun() # Changed from st.experimental_rerun() to st.rerun()

    # --- Placeholder for Admin Notifications/Logs ---
    # Admin might need a different type of notification area,
    # perhaps for system alerts or recent actions.
    st.sidebar.header("Admin Logs/Notifications")
    st.sidebar.info("System messages or recent activity could appear here.")
    # --- End Admin Notification Placeholder ---


    st.header("All Tickets")
    st.text(admin_view_all_tickets()) # Directly display returned string

    st.write("---")

    st.header("Update Ticket Status")
    update_ticket_id = st.text_input("Ticket ID to Update Status", key="update_ticket_id_input") # Added a key
    new_status = st.selectbox("New Status", ["Pending", "In Progress", "Resolved", "Closed"], key="new_status_select") # Added a key
    if st.button("Update Status", key="update_status_button"): # Added a key
        if update_ticket_id and new_status:
            success, message = admin_update_ticket_status_with_notification(update_ticket_id, new_status)
            if success:
                st.success(message)
            else:
                st.error(message)
        else:
            st.warning("Please provide Ticket ID and select a status.")

    st.write("---")

    st.header("Assign Ticket")
    assign_ticket_id = st.text_input("Ticket ID to Assign", key="assign_ticket_id_input") # Added a key
    all_agent_names = [agent for agents in category_agents.values() for agent in agents]
    new_agent = st.selectbox("Assign Agent", all_agent_names, key="new_agent_select") # Added a key
    if st.button("Assign Ticket", key="assign_ticket_button"): # Added a key
        if assign_ticket_id and new_agent:
            success, message = admin_assign_ticket(assign_ticket_id, new_agent)
            if success:
                st.success(message)
            else:
                st.error(message)
        else:
            st.warning("Please provide Ticket ID and select an agent.")

    st.write("---")

    st.header("Agent Workload")
    st.text(admin_view_agent_workload()) # Directly display returned string


# --- Main App Logic ---
# Using a function to encapsulate the main logic for better rerun handling
def main_app():
    if st.session_state.get("page") == "login":
        login_page()
    elif st.session_state.get("page") == "user":
        user_page()
    elif st.session_state.get("page") == "admin":
        admin_page()
    else: # Default to login page if state is not set or invalid
        st.session_state["page"] = "login"
        st.rerun() # Changed from st.experimental_rerun() to st.rerun()

# Run the main app logic
if __name__ == "__main__":
    try:
        main_app()
    except Exception as e:
        st.error(f"An unexpected error occurred: {e}")
        # Optionally, log the full traceback if needed for debugging
        # import traceback
        # st.exception(e) # This will show the full traceback in the UI
