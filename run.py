import streamlit as st
from app import app, db
from app.models import User, File

with app.app_context():
    db.create_all()

st.title("SecureFileX - File Security App")

uploaded_file = st.file_uploader("Upload a file", type=["txt", "pdf", "png", "jpg", "docx"])
if uploaded_file:
    file_data = uploaded_file.read()
    file_name = uploaded_file.name

    with app.app_context():
        new_file = File(filename=file_name, data=file_data)
        db.session.add(new_file)
        db.session.commit()
        st.success(f"{file_name} saved to database!")

with app.app_context():
    files = File.query.all()
    if files:
        st.subheader("Uploaded Files")
        for f in files:
            st.write(f"- {f.filename}")
