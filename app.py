from flask import Flask, render_template, request, redirect, url_for
from os import listdir
app = Flask(__name__)

user1 = {"user_id" : "1","username" : "asd" , "pword": "asd"}  # Store users {username: password}
user1 = {"user_id" : "2","username" : "qwe" , "pword": "qwe"} 
document1 = {"id" : "101", "title" : "testing1", "user_id" : "1"}  # Store documents {document_id: {title, content, comments}}
document2 = {"id" : "102", "title" : "testing2", "user_id" : "1"} 
document3 = {"id" : "103", "title" : "testing3", "user_id" : "2"} 

users = [user1]
documents = [document1,document2,document3]

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if user_exist(users,username,password):
            # Successful login, redirect to dashboard
            return redirect(url_for('manage', username=username))
        else:
            return render_template('login.html', message='Invalid credentials')
    return render_template('login.html', message='')


@app.route('/manage', methods=['GET', 'POST'])
def manage():
    return render_template('manage.html',documents=documents)

##@app.route('/text_editor/<username>', methods=['GET', 'POST'])
##def text_editor(username):
##    if request.method == 'POST':
##        title = request.form['title']
##        content = request.form['content']
##        document_id = len(documents) + 1
##        documents[document_id] = {'title': title, 'content': content, 'username': username, 'comments': []}
##        return redirect(url_for('text_editor', username=username))
##    return render_template('text_editor.html')




def user_exist(users,name,pword):
    for user in users:
        if(user["username"] == name and user["password"] == pword ):
            return True
        else: 
            return False
        

if __name__ == '__main__':
    app.run(debug=True)