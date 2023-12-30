from flask import Flask, render_template, request, redirect, url_for, session, send_file
from datetime import timedelta, datetime
from flask_mysqldb import MySQL
from flask_session import Session
import bcrypt 
from io import BytesIO
import os, time

app = Flask(__name__)
# Allowing user to not login for 30days, sessio last 30days
app.config["SESSION_PERMANENT"] = False
# Secret key to encrypt or decrypt session data
app.config["SESSION_TYPE"] = "filesystem"
app.secret_key = "Secret_Key852"

Session(app)

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
        
        '''
        remember = request.form.get('remember_me')

        if remember:
            session.permanent = True
        else:
            session.permanent = False
        '''
        
        # Get the row with the same username as entered
        user_row = getUserRow(username)

        # If username exist
        if user_row:

            # retrieve data from tuple
            _, _, db_pword = user_row

            # Check if user input password match the hashed pw in db
            if bcrypt.checkpw(pword,db_pword.encode('utf-8')):

                # Inside the login function after successful authentication
                session['user'] = user_row  # Store the user_row in the session

                # Password matches, redirect to manage page
                return redirect(url_for('manage'))
            
        # If there is no user_row or password does not match
        message="Invalid Username or Password"    
    
    # GET request
    return render_template('login.html', message=message)

@app.route('/', methods=['GET', 'POST'])
def manage():
    print(session)
    # If a session exist
    if "user" in session:

        # Get the user_id from session instead of parameter for security measurement
        user_row = session['user']
        user_id = user_row[0]
        username = user_row[1]
        if request.method == 'POST':
            
            if 'ConfirmDel' in request.form:
                # selectedDocs = getSelectedDocs(user_id)
                selectedDocs = request.form.get("doc_ids")
                docs = selectedDocs.split(",")
                delDoc(docs)

            elif 'logout' in request.form:
                session.pop("user_id",None)
                clearTempFiles()
                return redirect(url_for("login"))
            
            elif 'createDoc' in request.form:
                docName = request.form.get('DocName')
                addDoc(docName,user_id)

        return render_template('manage.html',documents=getDocRows("user_id",user_id), username=username)
    # If a session does not exist, redirect back to the login page.
    # Session can be closed by closing the browser, or manually using code.
    # This way, 
    return redirect(url_for("login"))

@app.route('/text_editor/<doc_id>',methods=['GET', 'POST'])
def text_editor(doc_id):
    # If a session exist
    if "user_id" in session:
        
        doc = getDocRows("doc_id",doc_id)[0]
        if request.method == 'POST':
            date_modified = getCurrentDateTime()
            content = request.form.get("content")
            size = KBOfString(content)

            if 'save' in request.form:
                saveDoc(date_modified,size,content,doc_id)
                # Get new updated doc
                doc = getDocRows("doc_id",doc_id)[0]

            elif 'logout' in request.form:
                session.pop("user_id",None)
                clearTempFiles()
                return redirect(url_for("login"))
            
            elif 'download' in request.form:
                saveDoc(date_modified,size,content,doc_id)
                filename = doc[1] + '.txt'
                filepath = f"./temp/{filename}"
                content = doc[5]

                # Open the file, write and then close the file in 2 line
                with open(filepath, "w") as fo:
                    fo.write(content)
                    fo.close()

                return redirect(url_for("download",filepath=filepath))
            
            elif "home" in request.form:
                return redirect(url_for(manage))
            elif "rename" in request.form:
                renameTitle(date_modified,size,content,,doc_id)

        return render_template("text_editor.html", doc=doc)
    # If a session does not exist, redirect back to the login page.
    # Session can be closed by closing the browser, or manually using code.
    # This way, 
    return redirect(url_for("login"))

# Downlaod the file in the temp dir
@app.route("/download/<path:filepath>", methods=['GET', 'POST'])
def download(filepath):
    print("Downloading: ", filepath)
    return send_file(filepath, as_attachment=True)

def saveDoc(date_modified,size,content,doc_id):
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE documents SET date_modified=%s,size=%s,content=%s WHERE doc_id=%s;", (date_modified,size,content,doc_id))
    mysql.connection.commit()
    cursor.close()

def renameTitle(date_modified,size,content,doc_id,doc_name):
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE documents SET date_modified=%s,size=%s,content=%s,doc_name=%s WHERE doc_id=%s;", (date_modified,size,content,doc_name,doc_id))
    mysql.connection.commit()
    cursor.close()

# Functions #
def user_exist(users,name,pword):
    for user in users:
        if(user["username"] == name and user["pword"] == pword ):
            print("userExist")
            return True
        else: 
            print("NoUserExist")
            return False

def getDocRows(type,id):
    if type != "user_id" and type != "doc_id":
        raise Exception("Please enter a valid id type, user_id or doc_id")

    cursor = mysql.connection.cursor()
    query = f"SELECT * FROM documents WHERE {type} = %s;"
    cursor.execute(query, (id,))
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
    documents = getDocRows("user_id",user_id)
    # Store id for selected documents
    result = []
    for doc in documents:
        doc_id = doc[0]
        selectedDoc = request.form.get(doc_id)
        # Check if the currentDoc is selected or not, if not selected, will return nothing, else return the id
        if selectedDoc:
            result = result + [selectedDoc]
    return result

def addDoc(doc_name,user_id):
    cursor = mysql.connection.cursor()
    content = ""
    size = KBOfString(content)
    date_modified = getCurrentDateTime()
    cursor.execute("INSERT INTO documents (doc_name, user_id, date_modified, size, content) VALUES (%s,%s,%s,%s,%s)",(doc_name,user_id,date_modified,size,content))
    # Update the table
    mysql.connection.commit()
    cursor.close

def delDoc(doc_ids):
    cursor = mysql.connection.cursor()
    print(doc_ids)
    # Build a query to delete multiple rows at the same time
    query = ""
    for id in doc_ids:
        query = query + "doc_id = " + id + " OR "

    # remove the last OR
    query = query.rstrip(" OR ")

    # Build the full query
    full_query = f"DELETE FROM documents documents WHERE {query}"
    print(full_query)
    cursor.execute(full_query)

    # Update the table
    mysql.connection.commit()
    cursor.close

# Return the size in byte of a string, use to calculate the size of content
def KBOfString(str):
    # Turn char into byte and calculate the lenght of it
    return (len(str.encode('utf-8'))/1024)

def clearTempFiles():
    dir = "./temp"
    files = os.listdir(dir)
    for f in files:
        filepath = dir + "/" + f
        os.remove(filepath)
        print(filepath + " removed")

def getCurrentDateTime():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

if __name__ == '__main__':
    app.run(debug=True)
    #app.run(debug=True,host='localhost',port=5000)