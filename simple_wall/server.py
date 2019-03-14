from flask import Flask, render_template, request, redirect, flash, session
from mysqlconnection import connectToMySQL
import re 
from flask_bcrypt import Bcrypt
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
app = Flask (__name__)
bcrypt = Bcrypt(app)
mysql = connectToMySQL('wall')
app.secret_key = "Tugce"

@app.route ('/', methods=["GET"])
def index():
    if 'submitted' not in session:
        session['submitted'] = False 

    return render_template('loginandreg.html')

@app.route('/create_customers', methods=['POST'])
def create():
    print("this is the form", request.form)

    if len(request.form['first_name']) < 1 : 
        flash('first name can not be blank!')
    if (request.form['first_name'].isalpha()) == False:
        flash('first name can not contain numbers!')
    if (request.form['last_name'].isalpha()) == False:
        flash('last name can not contain numbers!')      
    if len(request.form['last_name']) < 1 :  
        flash('last name can not be blank!')
    else: 
        query = "SELECT * FROM users WHERE email = %(users_email)s;"
        data = { "users_email" : request.form['email'] }
        email = mysql.query_db(query, data)
        print("here's what we got back from the database", len(email))
        if len(email) > 0: 
            flash("Email already exists!")
    if len(request.form['email'])<1:
        flash ('email can not be blank!!')
    elif not EMAIL_REGEX.match(request.form['email']):
        flash('Invalid Email Adress!')
    if len(request.form['password']) < 8:
        flash ('password should be more than 8 characters')  
    if (request.form['password']) != (request.form['password_confirmation']):
        flash ('password and password confirmation should match')
    if '_flashes' not in session.keys():
        query = "INSERT INTO users (first_name, last_name, email, password) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s);"
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        data = {
                'first_name': request.form['first_name'],
                'last_name':  request.form['last_name'],
                'email':  request.form['email'],
                'password' : pw_hash
                }
        result = mysql.query_db(query, data)
        var1 = mysql.query_db(query, data)
        session['submitted'] = True
        session ['user_id'] = result
        session ['first_name'] = var1
        return redirect('/success')
    return redirect('/')

@app.route ('/login', methods=['POST'])
def login ():
    print("this is the form", request.form)
    if not EMAIL_REGEX.match(request.form['email']):
        flash('Invalid Email Adress!')
    if len(request.form['email'])<1:
        flash ('email can not be blank!!')   
    if len(request.form['password']) < 8:
        flash ('Invalid password!!')
    if '_flashes' not in session.keys():
        query = "SELECT * FROM users WHERE email = (%(email)s);"
        data = {'email': request.form['email']}
        result = mysql.query_db(query,data)
    
        if result:
            print ("this is the result", result)
            if bcrypt.check_password_hash(result[0]['password'], request.form['password']):
                session ['email'] = result[0]['email']
                session['submitted'] = True
                session ["user_id"] = result[0]['id']
                session ['first_name'] = result[0]['first_name']
                return redirect ('/success')
            else:
                flash ("password is not correct")
    
    return redirect("/")

@app.route ('/success')
def success():
    if 'submitted' in session and session['submitted'] == True:
        query = "SELECT * FROM users WHERE not id = %(userid)s;"
        data = {"userid": session ["user_id"]}
        result = mysql.query_db(query,data)
        print ("the users", result)
        query = "SELECT * FROM messages JOIN users on users.id = messages.user_id WHERE recipientid = %(userid)s "
        #data = {"userid": session ["user_id"]}
        x = mysql.query_db(query,data)
        return render_template("user.html", users = result, messages = x )
    else:
        flash("you are not allowed to see that page")
        return redirect('/')

@app.route ('/create_message', methods=['POST'])
def message ():
    print(request.form)
    message_text = request.form['message']
    query = "INSERT INTO messages (message, created_at, updated_at, user_id, recipientid) VALUES (%(message)s, Now(), Now(),%(user_id)s, %(recipientid)s)"
    data = {
        'message': request.form ['message'],
        'user_id':  session ['user_id'],
        'recipientid' : request.form ['recipientid']
    }
    mysql.query_db(query, data)
    #query = "SELECT * FROM users WHERE not in session ['user_id']"

    return redirect ('/success')

@app.route ('/delete/<id>')
def delete (id):
    query = "DELETE FROM messages WHERE id = %(id)s;"
    data = {
        'id' : id
    }
    result = mysql.query_db(query,data)
    flash ("your message deleted")
    return redirect("/success") 

@app.route("/logout")
def logout():
    session.clear()
    return redirect('/')

if __name__=="__main__":
    app.run(debug=True)   