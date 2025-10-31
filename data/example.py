
safe_api_key = os.getenv("OPENAI_API_KEY")
print("API Key loaded from environment.")

print(f"[DEBUG] User SSN: {user_ssn}, Account: {account_number}")

def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)

@app.route('/comment')
def show_comment():
    comment = request.args.get('text')
    return f"<div class='comment'>{comment}</div>"

html = f"<p>Welcome {user_name}!</p>"