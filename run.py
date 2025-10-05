# -----------------------------------------------
# DELETE THIS ENTIRE BLOCK FROM run.py
# -----------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True)
# -----------------------------------------------