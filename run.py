# run.py
import streamlit as st
from app import app, db  # Make sure 'app' is your Flask app and 'db' is SQLAlchemy instance
from app.models import User, File  # Import your models

# -------------------------------
# Initialize DB tables (once)
# -------------------------------
with app.app_context():
    db.create_all()

# -------------------------------
# Streamlit UI
# -------------------------------
st.set_page_config(page_title="SecureFileX", page_icon="🔒")

st.title("SecureFileX - Comprehensive File Security Application")

# File upload section
uploaded_file = st.file_uploader("Upload a file", type=["txt", "pdf", "png", "jpg", "docx"])
if uploaded_file:
    st.write("File uploaded:", uploaded_file.name)
    
    # Save file logic (optional)
    file_data = uploaded_file.read()
    file_name = uploaded_file.name

    # Example: Save file info to DB
    with app.app_context():
        new_file = File(filename=file_name, data=file_data)
        db.session.add(new_file)
        db.session.commit()
        st.success(f"{file_name} saved to database!")

# Optional: List uploaded files
with app.app_context():
    files = File.query.all()
    if files:
        st.subheader("Uploaded Files")
        for f in files:
            st.write(f"- {f.filename}")
