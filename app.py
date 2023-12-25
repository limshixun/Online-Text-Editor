from flask import Flask, render_template, request, redirect, url_for
from flask_mysqldb import MySQL
import bcrypt 

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Mysql1475963!@#'
app.config['MYSQL_DB'] = 'text_editor'

mysql = MySQL(app)

@app.route('/', methods=['GET', 'POST'])
def login():
    # Error message
    message = ""
    if request.method == 'POST':
        # Get user input from <form>
        username = request.form['username']
        # turn password into bytes
        pword = request.form['password'].encode('utf-8')

        # Get the row with the same username as entered
        user_row = getUserRow(username)

        # If username exist
        if user_row:

            # retrieve data from tuple
            db_user_id, _, db_pword = user_row

            # Check if user input password match the hashed pw in db
            if bcrypt.checkpw(pword,db_pword.encode('utf-8')):

                # Password matches, redirect to manage page
                return redirect(url_for('manage', user_id=db_user_id))
            
        # If there is no user_row or password does not match
        message="Invalid Username or Password"    
    
    # GET request
    return render_template('login.html', message=message)


@app.route('/manage/<user_id>', methods=['GET', 'POST'])
def manage(user_id):
    return render_template('manage.html',documents=getDocRows(user_id))

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

if __name__ == '__main__':
    app.run(debug=True)
    #app.run(debug=True,host='localhost',port=5000)

