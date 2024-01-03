from flask import Flask, render_template, request, redirect, url_for, session, send_file
from datetime import datetime
from flask_session import Session
import os, mysql.connector, bcrypt

# Initialize flask
app = Flask(__name__)

# Allowing user to access without login unless loged out
app.config["SESSION_PERMANENT"] = False
# Secret key to encrypt or decrypt session data
app.config["SESSION_TYPE"] = "filesystem"
# Secret key for encrypt the session data
app.secret_key = "Secret_Key852"
# Initialize the session function for this app
Session(app)

# Sign up route to create a new user
@app.route('/signup', methods=["GET","POST"])
def signup():
    nameError = ""
    pwError = ""
    if request.method == 'POST':

        # Get user input from input in form after then from was submitted
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm']
        
        # get the user's information from the database
        user_row = getUserRow(username)

        # if username does not exist in db, add new user to the database
        if (not user_row) and (password == confirm):
            addUser(username,password)
            return redirect(url_for('signup_success'))
        
        # if username already exist
        elif (user_row):
            nameError = "Username already exist. Please try another name"

        # if password and confirm password does not match
        elif not (password == confirm):
            pwError = "Password does not match. Try Again"

    # render signup template for initial render, user already exist and password and confirm password does not match
    return render_template('signup.html', nameError=nameError, pwError = pwError)

# page after sign up successfully
@app.route('/signup_success',methods=["GET","POST"])
def signup_success():
    # Redirect user to login page
    if request.method == 'POST':
        return redirect(url_for('login'))
    return render_template('signup_success.html')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Error message
    message = ""

    if request.method == 'POST':
        
        # Get user input from <form>
        username = request.form['username']

        # turn password from string into bytes
        pword = request.form['password'].encode('utf-8')

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

# Home route, mainly for managing documents
@app.route('/', methods=['GET', 'POST'])
def manage():

    print(session)
    # If a session exist
    if "user" in session:

        # Get the user from session instead of parameter for security measurement, 
        # if pass it as param, user id and user password can leak easily through the URL
        user_row = session['user']
        user_id = user_row[0]
        username = user_row[1]

        if request.method == 'POST':
            
            # When submit button OR input with ConfirmDel is submitted
            if 'ConfirmDel' in request.form:
                # Get all the doc_ids that is selected
                selectedDocs = request.form.get("doc_ids")
                # Turn into array
                docs = selectedDocs.split(",")
                delDoc(docs)

            # When submit button OR input with logout is submitted
            elif 'logout' in request.form:
                logout()
                return redirect(url_for("login"))
            
            # When submit button OR input with createDoc is submitted
            elif 'createDoc' in request.form:
                docName = request.form.get('DocName')
                addDoc(docName,user_id)

        return render_template('manage.html',documents=getDocRows("user_id",user_id), username=username)
    
    # If a session does not exist, redirect back to the login page.
    return redirect(url_for("login"))

# Route for individual document
@app.route('/text_editor/<doc_id>',methods=['GET', 'POST'])
def text_editor(doc_id):
    # If user session does not exist, redirect back to login to prevent access from typing manually from URL
    if "user" in session:
        
        # Get the document's information, we get the first element because getDocRows uses fetchall that return more than one doc
        doc = getDocRows("doc_id",doc_id)[0]
        if request.method == 'POST':
            # Get all the document's related content
            date_modified = getCurrentDateTime()
            content = request.form.get("content")
            size = KBOfString(content)

            # When form is submitted by save input OR button
            if 'save' in request.form:
                saveDoc(date_modified,size,content,doc_id)
                # Get new updated doc
                doc = getDocRows("doc_id",doc_id)[0]
                # Redirect back to the same page so that we dont have to re render the whole page after saving, also retain the state of the page
                return redirect(url_for("text_editor", doc_id=doc_id))

            # When form is submitted by save input OR button
            elif 'logout' in request.form:
                logout()
                return redirect(url_for("login"))
            
            # When form is submitted by save input OR button
            elif 'download' in request.form:
                print("Starting download")
                saveDoc(date_modified,size,content,doc_id)

                # Create file path and get document's content 
                filename = doc[1] + '.txt'
                filepath = f"./temp/{filename}"
                content = doc[5]

                # Open the file, write and then close the file in 2 line
                with open(filepath, "w") as fo:
                    fo.write(content)
                    fo.close()

                return redirect(url_for("download",filepath=filepath))
            
            elif "home" in request.form:
                return redirect(url_for("manage"))
            
            elif "rename" in request.form:
                new_name = request.form.get("DocName")
                renameTitle(date_modified, size, content, doc_id, new_name)
                doc = getDocRows("doc_id",doc_id)[0]
                return redirect(url_for("text_editor", doc_id=doc_id))


        return render_template("text_editor.html", doc=doc)
    # If a session does not exist, redirect back to the login page.
    # Session can be closed by closing the browser, or manually using code.
    # This way, 
    return redirect(url_for("login"))

# Downlaod the file in the temp dir
@app.route("/download/<path:filepath>", methods=['GET', 'POST'])
def download(filepath):
    print("Downloading: ", filepath)

    # This will start the download
    return send_file(filepath, as_attachment=True)

# Function that checkif user name already exist in the database or not
def user_exist(users,name,pword):
    for user in users:
        if(user["username"] == name and user["pword"] == pword ):
            return True
        else: 
            return False

# Clear session and temporary file and prepare for log out
def logout():
    session.pop("user",None)
    clearTempFiles()

# Hash the password using bcrypt, hash is irreversible and salt provide randomness to the hash so that same password does not result in same hash string
def hash(pword):
    # generate salt
    s = bcrypt.gensalt()
    # turn the password into byte, and then hash it using salt
    return bcrypt.hashpw(pword.encode('utf-8'), salt=s)

def saveDoc(date_modified,size,content,doc_id):
    query = "UPDATE documents SET date_modified=%s,size=%s,content=%s WHERE doc_id=%s;"
    params = (date_modified,size,content,doc_id)
    executeQuery(query,params)

def renameTitle(date_modified,size,content,doc_id,doc_name):
    query = "UPDATE documents SET date_modified=%s,size=%s,content=%s,doc_name=%s WHERE doc_id=%s;"
    params = (date_modified,size,content,doc_name,doc_id)
    executeQuery(query,params)

# Will hash the password, and insert the username and hashed password into the users table
def addUser(username,pword):
    hashed = hash(pword)
    query = "INSERT INTO users (username, pword) VALUES (%s,%s)"
    params = (username,hashed)
    executeQuery(query, params)

def addDoc(doc_name,user_id):
    content = ""
    size = KBOfString(content)
    date_modified = getCurrentDateTime()
    query = "INSERT INTO documents (doc_name, user_id, date_modified, size, content) VALUES (%s,%s,%s,%s,%s)"
    params = (doc_name,user_id,date_modified,size,content)
    executeQuery(query,params)

# Remove document row based on the doc_ids
def delDoc(doc_ids):
        try:
            cnx = getConnection()
        
            if cnx.is_connected():
                cursor = cnx.cursor()
                print(doc_ids)
                # Build a query to delete multiple rows at the same time
                query = ""
                for id in doc_ids:
                    query = query + "doc_id = " + id + " OR "

                # remove the last OR
                query = query.rstrip(" OR ")

                # Build the full query
                full_query = f"DELETE FROM documents WHERE {query}"

                cursor.execute(full_query)

                # Update the table
                cnx.commit()
                cursor.close
            
            else:
                print("Connection Failed")
        except mysql.connector.Error as e:
            print("Database connection error: ", e)
            
        finally:
            closeConnection(cnx)

def executeQuery(query,params):
    # Start connection
    try:
        # Initiate connection
        cnx = getConnection()
        # If cnx connection success
        if cnx.is_connected():
            print("Connection Successful")
            # Create a cursor
            cursor = cnx.cursor()
            # Execute the query to update the database
            cursor.execute(query,params)
            # Commit the execution to update the table
            cnx.commit()
            # Close the cursor
            cursor.close()
        
        # If connection Failed
        else:
            print("Connection Failed")
    # Handle exception
    except mysql.connector.Error as e:
        print("Database connection error: ", e)

    # Close the connection at the end
    finally:
        closeConnection(cnx)

# We can get documents based on user_id or document id 
def getDocRows(type,id):
    try:
        # Get connection
        cnx = getConnection()

        if cnx.is_connected():
            print("Connection Successful")

            # Check if the type is correct or not, if not handle exception
            if type != "user_id" and type != "doc_id":
                raise Exception("Please enter a valid id type, user_id or doc_id")

            # Create a cursor
            cursor = cnx.cursor()
            # Create query
            query = f"SELECT * FROM documents WHERE {type} = %s;"
            # Execute the query
            cursor.execute(query, (id,))
            # Fetch all the results
            doc_rows = cursor.fetchall()
            # Close the cursor
            cursor.close()
            # Return the documents 
            return doc_rows
        
        else:
            print("Connection Failed")
    # Handle exception
    except mysql.connector.Error as e:
        print("Database connection error: ", e)
    finally:
        closeConnection(cnx)

# Get one single user row
def getUserRow(username):
    try:    
        cnx = getConnection()
    
        if cnx.is_connected():
            print("Connection Successful")
            # Create cursor
            cursor = cnx.cursor()
            # Execute query
            cursor.execute("SELECT * FROM users WHERE username=%s;", (username,))
            # Fetch the first instance of the result
            user_row = cursor.fetchone()
            # Close the cursor
            cursor.close()

            if not user_row:
                # Handle cases when user doesn't exist
                return None
            return user_row
        else:
            print("Connection Failed")
    except mysql.connector.Error as e:
        print("Database connection error: ", e)
        
    finally:
        closeConnection(cnx)

# Return the size in byte of a string, use to calculate the size of content
def KBOfString(str):
    # Turn char into byte and calculate the lenght of it
    return (len(str.encode('utf-8'))/1024)

# Remove all the temporary files generated when a file waas downloaded under temp dir 
def clearTempFiles():
    dir = './temp'
    # Get all the file name in the ./temp directory
    files = os.listdir(dir)

    # For all files under ./temp, remove all files that is not ignore.txt
    # ignore.txt exist so that the dir can be uploaded to git, it can be anything
    for f in files:
        if not (f == 'ignore.txt'):
            filepath = f"./temp/{f}"

            os.remove(filepath)
            print(filepath + " removed")

# Return current time in yyyy-mm-dd hh-mm-ss format
def getCurrentDateTime():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Connect the application to the database
def getConnection():
    # This connection function can be found under settings of Azure Database for Mysql server
    try:
        cnx = mysql.connector.connect(user="limshixun", password="Mysql1475963!@#", host="onlinete-db-server.mysql.database.azure.com",
                                      port=3306, database="text_editor", ssl_ca="./cert/DigiCertGlobalRootCA.crt.pem", ssl_disabled=False)
        return cnx
    # Handle exception
    except mysql.connector.Error as e:
        print("Database connection error: ", e)
        return None

# Close the connection to the database
def closeConnection(cnx):
    if cnx:
        cnx.close()

if __name__ == '__main__':
    app.run(debug=True  )
    #app.run(debug=True,host='localhost',port=5000)