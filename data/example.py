import os
from dotenv import load_dotenv
import db

safe_api_key = os.getenv("OPENAI_API_KEY", "<KEY_REDIRECT_TOKEN>")
print("API Key loaded from environment.")

api_key = 'aws-wdawd-dawdasdwd'

user_ssn = "900101-1234567"
account_number = "123-456-7890123"

print(f"[DEBUG] User SSN: {user_ssn}, Account: {account_number}")

def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)

@app.route('/comment')
def show_comment():
    comment = request.args.get('text')
    return f"<div class='comment'>{comment}</div>"

html = f"<p>Welcome {user_name}!</p>"