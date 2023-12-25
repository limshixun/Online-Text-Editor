from flask import Flask, render_template, request, redirect, url_for
from os import listdir
from flask_mysqldb import MySQL

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Mysql1475963!@#'
app.config['MYSQL_DB'] = 'text_editor'

mysql = MySQL(app)

@app.route('/', methods=['GET', 'POST'])
def login():
    # IF post request
    if request.method == 'POST':
        # fetch the user input from html
        username = request.form['username']
        pword = request.form['password']

        # use cursor to execute sql query, get user and password
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username=%s;", (username,))
        user_row = cursor.fetchone()
        cursor.close()

        print(user_row)

        # If there is no row with the entered username
        if user_row:
            db_user_id = user_row[0]
            db_name = user_row[1]
            db_pword = user_row[2]

            if (username == db_name) & (pword == db_pword):
                # user redirect to send user to a different page, while use render_template to render content for a page, url will not change when render_template
                return redirect(url_for('manage', user_id=db_user_id))
        else:
            return render_template('login.html', message='Invalid Username')

    # IF Get request      
    return render_template('login.html', message='Login')

@app.route('/manage/<user_id>', methods=['GET', 'POST'])
def manage(user_id):
    return render_template('manage.html',documents=getDocRows(user_id))

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

if __name__ == '__main__':
    app.run(debug=True)
    #app.run(debug=True,host='localhost',port=5000)

