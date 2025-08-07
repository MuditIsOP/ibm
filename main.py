import streamlit as st

st.markdown(, unsafe_allow_html=True)

import streamlit as st

st.markdown(, unsafe_allow_html=True)

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

       
        
        cursor.execute()

        
        cursor.execute()

        
        cursor.execute()

        
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
                       (email, hashed_password, salt, True)) 
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
