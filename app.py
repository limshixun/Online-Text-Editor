from flask import Flask, render_template, request, redirect, url_for, session
from datetime import timedelta
from flask_mysqldb import MySQL
from flask_session import Session
import bcrypt 

app = Flask(__name__)
# So that the session is stored under a folder, /flask_session
app.config["SESSION_TYPE"] = "filesystem"
# Allowing user to not login for 30days, sessio last 30days
app.permanent_session_lifetime = timedelta(days=30)
Session(app)

# Secret key to encrypt or decrypt session data
app.secret_key = "Secret_Key852"

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Mysql1475963!@#'
app.config['MYSQL_DB'] = 'text_editor'

mysql = MySQL(app)

@app.route('/signup', methods=["GET","POST"])
def signup():
    nameError = ""
    pwError = ""
    if request.method == 'POST':
        # Get user input
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm']
        
        user_row = getUserRow(username)

        # if username does not exist in db
        if (not user_row) and (password == confirm):
            addUser(username,password)
            return redirect(url_for('signup_success'))
        
        elif (user_row):
            nameError = "Username already exist. Please try another name"

        elif not (password == confirm):
            pwError = "Password does not match. Try Again"

    return render_template('signup.html', nameError=nameError, pwError = pwError)

@app.route('/signup_success',methods=["GET","POST"])
def signup_success():
    if request.method == 'POST':
        return redirect(url_for('login'))
    return render_template('signup_success.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Error message
    message = ""
    if request.method == 'POST':
        # Get user input from <form>
        username = request.form['username']
        # turn password into bytes
        pword = request.form['password'].encode('utf-8')
        remember = request.form.get('remember_me')

        if remember:
            session.permanent = True
        else:
            session.permanent = False

        # Get the row with the same username as entered
        user_row = getUserRow(username)

        # If username exist
        if user_row:

            # retrieve data from tuple
            db_user_id, _, db_pword = user_row

            # Check if user input password match the hashed pw in db
            if bcrypt.checkpw(pword,db_pword.encode('utf-8')):

                # Inside the login function after successful authentication
                session['user_id'] = db_user_id  # Store the user_id in the session

                # Password matches, redirect to manage page
                return redirect(url_for('manage'))
            
        # If there is no user_row or password does not match
        message="Invalid Username or Password"    
    
    # GET request
    return render_template('login.html', message=message)

@app.route('/', methods=['GET', 'POST'])
def manage():
    # If a session exist
    if "user_id" in session:

        # Get the user_id from session instead of parameter for security measurement
        user_id = session['user_id']

        if request.method == 'POST':

            if 'delete' in request.form:

                selectedDocs = getSelectedDocs(user_id)
                
                print(selectedDocs)
            elif 'create' in request.form:

                print(2)
            
            elif 'logout' in request.form:
                session.pop("user_id",None)
                return redirect(url_for("login"))
                

        
        return render_template('manage.html',documents=getDocRows(user_id))
    # If a session does not exist, redirect back to the login page.
    # Session can be closed by closing the browser, or manually using code.
    # This way, 
    return redirect(url_for("login"))


# Functions
def user_exist(users,name,pword):
    for user in users:
        if(user["username"] == name and user["pword"] == pword ):
            print("userExist")
            return True
        else: 
            print("NoUserExist")
            return False

def getDocRows(user_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM documents WHERE user_id=%s;", (user_id,))
    doc_rows = cursor.fetchall()
    cursor.close()
    return doc_rows

def getUserRow(username):
    # use cursor to execute sql query, get user and password
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username=%s;", (username,))
    user_row = cursor.fetchone()
    cursor.close()

    if not user_row:
        # Handle case when user doesn't exist
        return None
    return user_row

# Will hash the password, and insert the username and hashed password into the users table
def addUser(username,pword):
    cursor = mysql.connection.cursor()
    hashed = hash(pword)
    cursor.execute("INSERT INTO users (username, pword) VALUES (%s,%s)",(username,hashed))
    # Update the table
    mysql.connection.commit()
    cursor.close

def hash(pword):
    # generate salt
    s = bcrypt.gensalt()
    # turn the password into byte
    return bcrypt.hashpw(pword.encode('utf-8'), salt=s)

# Get all the selected docs from
def getSelectedDocs(user_id):
    documents = getDocRows(user_id)
    # Store id for selected documents
    selectedDocs = []
    for doc in documents:
        doc_name = doc[1]
        selectedDoc = request.form.get(doc_name)
        # Check if the currentDoc is selected or not, if not selected, will return nothing, else return the id
        if selectedDoc:
            selectedDocs = selectedDocs + [selectedDoc]

    return selectedDocs

if __name__ == '__main__':
    app.run(debug=True)
    #app.run(debug=True,host='localhost',port=5000)

