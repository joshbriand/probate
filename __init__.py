from flask import (Flask, render_template, request, redirect, jsonify, url_for, flash)
from flask import session as login_session
from flask import make_response
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from database_setup import (Base, Users, Questions, Answers)
import random
import string
from datetime import datetime
import httplib2
import simplejson
import json
import ast
import requests
import re, hmac
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = Flask(__name__)

APPLICATION_NAME = "Josh Briand's website"

engine = create_engine('sqlite:////vagrant/probate.db')

Base.metadata.bind = engine

DBSession = scoped_session(sessionmaker(bind=engine))

# code for Regular Expression validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")

#start of code for hashing
secret = "1953"

def validate(input, validation):
    return validation.match(input)

def hash_str(s):
    return hmac.new(secret, s).hexdigest()

def make_secure_val(password):
    return "%s" % (hash_str(password))

def check_secure_val(password):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

def make_temp_password(password):
    return make_secure_val(password)

#end of code for hashing

#does user exist?
def UserExists(name):
    session = DBSession()
    z = session.query(Users).filter_by(username=name)
    print session.query(z.exists()).scalar()
    DBSession.remove()
    return session.query(z.exists()).scalar()

def createUser(login_session):
    '''function to create a new user to database if user's email does not exist
    in the user table'''
    session = DBSession()
    newUser = User(
        name=login_session['username'],
        email=login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    users = session.query(User).all()
    DBSession.remove()
    return user.id


def getUserID(email):
    '''function to look up and return user id from database'''
    try:
        session = DBSession()
        user = session.query(User).filter_by(email=email).first()
        DBSession.remove()
        return user.id
    except BaseException:
        return None


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
@app.route('/login/', methods=['GET', 'POST'])
def Login():
    '''Handler for landing page of website.'''
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        if request.form['login'] == "Log In":
            login_username = request.form['username']
            login_password = request.form['password']
            if login_username:
                if login_password:
                    session = DBSession()
                    users = session.query(Users).all()
                    DBSession.remove()
                    for user in users:
                        if user.username == login_username:
                            user = user
                            print "success"
                            break
                    if UserExists(login_username):
                        login_hashed_password = make_secure_val(login_password)
                        if user.username == login_password:
                            login_session['username'] = login_username
                            return redirect(url_for('changePassword'))
                        elif user.password == login_hashed_password:
                            login_session['username'] = login_username
                            if login_username == 'admin':
                                print "successful admin log in"
                                return redirect(url_for('Admin'))
                            else:
                                print "successful log in"
                                return redirect(url_for('Results'))
                        else:
                            flash('Incorrect Password')
                            return render_template('login.html')
                    else:
                        flash('Username Not Found')
                        return render_template('login.html')
                else:
                    flash('No Password Entered')
                    return render_template('login.html')
            elif login_password:
                flash('No Username Entered')
                return render_template('login.html')
        elif request.form['login'] == "Create User":
            session = DBSession()
            new_username = request.form['newUsername']
            new_password = request.form['newPassword']
            confirm_password = request.form['confirmPassword']
            new_hashed_password = make_secure_val(new_password)
            if new_username:
                if UserExists(new_username):
                    flash('Username Already Exists')
                    return render_template('login.html')
                elif validate(new_username, USER_RE) is None:
                    flash('That is Not a Valid Username')
                    return render_template('login.html')
                else:
                    if new_password == confirm_password:
                        if validate(new_password, PASSWORD_RE) is None:
                            flash('That is Not a Valid Password')
                            return render_template('login.html')
                        else:
                            newUser = Users(username=new_username,
                                            password=new_hashed_password)
                            session.add(newUser)
                            session.commit()
                            DBSession.remove()
                            print "new user added"
                            login_session['username'] = new_username
                            return redirect(url_for('Results'))
                    else:
                        flash('Passwords Do Not Match')
                        return render_template('login.html')
            else:
                flash('No Username Entered')
                return render_template('login.html')

@app.route('/logout/', methods=['GET'])
@app.route('/logout', methods=['GET'])
def Logout():
    login_session.pop('username', None)
    return redirect(url_for('Login'))

@app.route('/changepassword/', methods=['GET', 'POST'])
@app.route('/changepassword', methods=['GET', 'POST'])
def changePassword():
    if 'username' in login_session:
        print login_session['username']
        session = DBSession()
        users = session.query(Users)
        users = users.order_by(Users.username.asc())
        user = users.filter_by(username=login_session['username']).one()
        DBSession.remove()
        if user.username == 'admin':
            admin = True
        else:
            admin = False
        if request.method == 'GET':
            flash('Please Change Your Password')
            return render_template('changepassword.html',
                                    admin = admin,
                                    user = user.username)
        elif request.method == 'POST':
            current_password = user.password
            new_password = request.form['password']
            confirm_password = request.form['verify']
            new_secure_password = make_secure_val(new_password)
            if new_secure_password != current_password:
                if new_password == confirm_password:
                    user.password = new_secure_password
                    session.add(user)
                    session.commit()
                    DBSession.remove()
                    flash('Password Succesfully Changed!')
                    if admin:
                        return redirect(url_for('Admin'))
                    else:
                        return redirect(url_for('Results'))
                else:
                    flash('Password Do Not Match!')
                    return render_template(url_for('showChangePassword'))
            else:
                flash('New Password Must Be Different Than Current Password')
                return render_template(url_for('showChangePassword'))
    else:
        flash('Please Log In')
        return render_template(url_for('Login'))

@app.route('/addquestion/', methods=['GET', 'POST'])
@app.route('/addquestion', methods=['GET', 'POST'])
def Admin():
    if 'username' in login_session:
        session = DBSession()
        users = session.query(Users)
        users = users.order_by(Users.username.asc())
        user = users.filter_by(username=login_session['username']).one()
        DBSession.remove()
        if user.username == 'admin':
            admin = True
        else:
            flash('Access Restricted to Admin User Only')
            return redirect(url_for('Login'))
        if request.method == 'GET':
            return render_template('addquestion.html',
                                    admin = admin,
                                    user = user)
        elif request.method == 'POST':
            new_question = request.form['question']
            new_type = request.form.get('answertype')
            new_mandatory = request.form.get('mandatory')
            new_answer_1 = request.form['option1']
            new_answer_2 = request.form['option2']
            new_answer_3 = request.form['option3']
            new_answer_4 = request.form['option4']
            new_answer_5 = request.form['option5']
            if new_question:
                session = DBSession()
                if new_type == 'text':
                    newQuestion = Questions(question=new_question,
                                                    type=new_type,
                                                    mandatory=new_mandatory)
                    session.add(newQuestion)
                    session.commit()
                    DBSession.remove()
                    print "new question added"
                    flash('Question Added Seccessfully!')
                    return render_template('addquestion.html',
                                            admin = admin,
                                            user = user)
                else:
                    if new_answer_1 or new_answer_2 or new_answer_3 or new_answer_4 or new_answer_5:
                        newQuestion = Questions(question=new_question,
                                                        type=new_type,
                                                        mandatory=new_mandatory,
                                                        option1=new_answer_1,
                                                        option2=new_answer_2,
                                                        option3=new_answer_3,
                                                        option4=new_answer_4,
                                                        option5=new_answer_5)
                        session.add(newQuestion)
                        session.commit()
                        DBSession.remove()
                        print "new question added"
                        flash('Question Added Seccessfully!')
                        return render_template('addquestion.html',
                                                admin = admin,
                                                user = user)
                    else:
                        flash('You Must Enter An Answer')
                        return render_template('addquestion.html',
                                                admin = admin,
                                                user = user)
            else:
                flash('You Must Enter A Question')
                return render_template('addquestion.html',
                                        admin = admin,
                                        user = user)
    else:
        flash('You Must Be Logged In To Access This Page')
        return redirect(url_for('Login'))

@app.route('/deletequestion', methods=['GET', 'POST'])
@app.route('/deletequestion/', methods=['GET', 'POST'])
def showDeleteQuestion():
    '''Handler for landing page of website.'''
    if 'username' in login_session:
        session = DBSession()
        users = session.query(Users)
        users = users.order_by(Users.username.asc())
        user = users.filter_by(username=login_session['username']).one()
        questions = session.query(Questions)
        questions = questions.order_by(Questions.id.asc())
        DBSession.remove()
        if user.username == 'admin':
            admin = True
        else:
            flash('Access Restricted to Admin User Only')

            return redirect(url_for('Login'))
        if request.method == 'GET':
            return render_template('deletequestion.html',
                                    admin=admin,
                                    user=user,
                                    questions=questions)
        elif request.method == 'POST':
            delete_question = request.form['deletequestion']
            delete_question = int(delete_question)
            if delete_question:
                questionToDelete = session.query(
                    Questions).filter_by(id=delete_question).all()
                print delete_question
                if questionToDelete:
                    for question in questionToDelete:
                        session.delete(question)
                        session.commit()
                        DBSession.remove()
                        print "question deleted!"
                    flash ('Question Deleted Successfully!')
                    questions = session.query(Questions)
                    questions = questions.order_by(Questions.id.asc())
                    DBSession.remove()
                    return render_template('deletequestion.html',
                                            admin=admin,
                                            user=user,
                                            questions=questions)
                else:
                    flash('Question Not Found In Database')
                    return render_template('deletequestion.html',
                                            admin=admin,
                                            user=user,
                                            questions=questions)
            else:
                flash('You Must Select A Question To Delete')
                return render_template('deletequestion.html',
                                        admin=admin,
                                        user=user,
                                        questions=questions)

    else:
        flash('You Must Be Logged In To Access This Page')
        return redirect(url_for('Login'))

@app.route('/adduser', methods=['GET', 'POST'])
@app.route('/adduser/', methods=['GET', 'POST'])
def showAddUser():
    '''Handler for landing page of website.'''
    if 'username' in login_session:
        session = DBSession()
        users = session.query(Users)
        users = users.order_by(Users.username.asc())
        user = users.filter_by(username=login_session['username']).one()
        DBSession.remove()
        if user.username == 'admin':
            admin = True
        else:
            flash('Access Restricted to Admin User Only')
            return redirect(url_for('Login'))
        if request.method == 'GET':
            return render_template('adduser.html',
                                    admin = admin,
                                    user = user)
        elif request.method == 'POST':
            new_username = request.form['username']
            new_password = request.form['password']
            confirm_password = request.form['verify']
            new_hashed_password = make_secure_val(new_password)
            session = DBSession()
            if new_username:
                if UserExists(new_username):
                    flash('Username Already Exists')
                    return render_template('adduser.html',
                                            admin=admin,
                                            user=user)
                elif validate(new_username, USER_RE) is None:
                    flash('That is Not a Valid Username')
                    return render_template('adduser.html',
                                            admin=admin,
                                            user=user)
                else:
                    if new_password == confirm_password:
                        if validate(new_password, PASSWORD_RE) is None:
                            flash('That is Not a Valid Password')
                            return render_template('adduser.html',
                                                    admin=admin,
                                                    user=user)
                        else:
                            newUser = Users(username=new_username,
                                            password=new_hashed_password)
                            session.add(newUser)
                            session.commit()
                            DBSession.remove()
                            print "user added!!!"
                            flash('User Added Succesfully!')
                            return render_template('adduser.html',
                                                    admin=admin,
                                                    user=user)
                    else:
                        flash('Passwords Do Not Match')
                        return render_template('adduser.html',
                                                admin=admin,
                                                user=user)
            else:
                flash('No Username Entered')
                return render_template('adduser.html',
                                        admin=admin,
                                        user=user)
    else:
        flash('You Must Be Logged In To Access This Page')
        return redirect(url_for('Login'))

@app.route('/deleteuser', methods=['GET', 'POST'])
@app.route('/deleteuser/', methods=['GET', 'POST'])
def showDeleteUser():
    '''Handler for landing page of website.'''
    if 'username' in login_session:
        session = DBSession()
        users = session.query(Users)
        users = users.order_by(Users.username.asc())
        user = users.filter_by(username=login_session['username']).one()
        DBSession.remove()
        if user.username == 'admin':
            admin = True
        else:
            flash('Access Restricted to Admin User Only')
            return redirect(url_for('Login'))
        if request.method == 'GET':
            return render_template('deleteuser.html',
                                    admin=admin,
                                    user=user,
                                    users=users)
        elif request.method == 'POST':
            delete_user = request.form['deleteuser']
            delete_user = int(delete_user)
            session = DBSession()
            if delete_user:
                resultsToDelete = session.query(
                    Results).filter_by(user_id=delete_user).all()
                if resultsToDelete:
                    for delResult in resultsToDelete:
                        session.delete(delResult)
                        session.commit()
                        DBSession.remove()
                        print "result deleted!"
                userToDelete = session.query(
                    Users).filter_by(id=delete_user).all()
                if userToDelete:
                    for delUser in userToDelete:
                        session.delete(delUser)
                        session.commit()
                        DBSession.remove()
                        print "user deleted!"
                    flash ('User Deleted Successfully!')
                    users = session.query(Users)
                    users = users.order_by(Users.id.asc())
                    DBSession.remove()
                    return render_template('deleteuser.html',
                                            admin=admin,
                                            user=user,
                                            users=users)
                else:
                    flash('User Not Found In Database')
                    return render_template('deleteuser.html',
                                            admin=admin,
                                            user=user,
                                            users=users)
            else:
                flash('You Must Select A Question To Delete')
                return render_template('deleteuser.html',
                                        admin=admin,
                                        user=user,
                                        users=users)
    else:
        flash('You Must Be Logged In To Access This Page')
        return redirect(url_for('Login'))

@app.route('/form', methods=['GET', 'POST'])
@app.route('/form/', methods=['GET', 'POST'])
def showPoll():
    '''Handler for landing page of website.'''
    if 'username' in login_session:
        if login_session['username'] == 'admin':
            flash('You Must Be Logged In As A User')
            return redirect(url_for('Login'))
        else:
            if request.method == 'GET':
                session = DBSession()
                users = session.query(Users)
                users = users.order_by(Users.username.asc())
                user = users.filter_by(username=login_session['username']).one()
                questions = session.query(Questions)
                questions = questions.order_by(Questions.id.asc())
                results = session.query(Answers)
                print "all results"
                print results
                user_results = results.filter_by(user_id=user.id)
                print "user results"
                print user_results
                first = user_results.first()
                print "first?"
                print first
                DBSession.remove()
                return render_template('form.html',
                                        user=user.username,
                                        questions=questions,
                                        results=user_results,
                                        first=first)
            elif request.method == 'POST':
                session = DBSession()
                users = session.query(Users)
                users = users.order_by(Users.username.asc())
                user  = users.filter_by(username=login_session['username']).one()
                questions = session.query(Questions)
                for question in questions:
                    option_selected = request.form.get(str(question.id))
                    if option_selected:
                        results = session.query(Results)
                        user_results = results.filter_by(user_id=user.id)
                        for user_result in user_results:
                            if user_result.question.id == question.id:
                                session.delete(user_result)
                                session.commit()
                                print "result deleted!"
                        newResult = Results(choice = option_selected,
                                                question_id = question.id,
                                                user_id = user.id)
                        session.add(newResult)
                        session.commit()
                        print "result added!"
                DBSession.remove()
                flash('Thanks For Taking Visiting Probate Doctor!')
                return redirect(url_for('Results'))
    else:
        flash('You Must Be Logged In To Access This Page')
        return redirect(url_for('Login'))


@app.route('/results/', methods=['GET', 'POST'])
@app.route('/results', methods=['GET', 'POST'])
def Results():
    if request.method == 'GET':
        session = DBSession()
        users = session.query(Users)
        users = users.order_by(Users.username.asc())
        user = users.filter_by(username=login_session['username']).one()
        results = session.query(Answers)
        results = results.order_by(Answers.question_id.asc())
        questions = session.query(Questions)
        questions = questions.order_by(Questions.id.asc())
        DBSession.remove()
        resultsToHTML = []
        for question in questions:
            voters = [question,[],[],[],[],[]]
            for result in results:
                if result.question.id == question.id:
                    if result.choice == question.option1:
                        voters[1].append(result.user.username)
                    elif result.choice == question.option2:
                        voters[2].append(result.user.username)
                    elif result.choice == question.option3:
                        voters[3].append(result.user.username)
                    elif result.choice == question.option4:
                        voters[4].append(result.user.username)
                    elif result.choice == question.option5:
                        voters[5].append(result.user.username)
            resultsToHTML.append(voters)
        print resultsToHTML
        return render_template('results.html',
                                user=user.username,
                                results=resultsToHTML)






if __name__ == '__main__':
    app.secret_key = "Don't panic!"
    app.debug = True
    '''app.run()'''
    app.run("0.0.0.0", debug=True)
