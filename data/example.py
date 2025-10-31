safe_api_key = os.getenv("OPENAI_API_KEY")
print("API Key loaded from environment.")

user_ssn = '11126-45155'
account_number = 122012-21323

def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)

@app.route('/comment')
def show_comment():
    comment = request.args.get('text')
    return f"<div class='comment'>{comment}</div>"