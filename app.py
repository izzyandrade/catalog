from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from models import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
		open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Project"

#Connect to Database and create database session
engine = create_engine('sqlite:///catalogdatabase.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

#USER METHODS
def createUser(login_session):
	newUser = User(name = login_session['username'], email = login_session['email'], picture = login_session['picture'])
	session.add(newUser)
	session.commit()
	user = session.query(User).filter_by(email = login_session['email']).one()
	return user.id

def getUserInfo(user_id):
	user = session.query(User).filter_by(id = user_id).one()
	return user

def getUserId(email):
	try:
		user = session.query(User).filter_by(email = email).one()
		return user.id
	except:
		return None

@app.route('/gconnect', methods=['POST'])
def gconnect():
		if request.args.get('state') != login_session['state']:
				response = make_response(json.dumps('Invalid state parameter.'), 401)
				response.headers['Content-Type'] = 'application/json'
				return response
		code = request.data
		try:
				oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
				oauth_flow.redirect_uri = 'postmessage'
				credentials = oauth_flow.step2_exchange(code)
		except FlowExchangeError:
				response = make_response(
						json.dumps('Failed to upgrade the authorization code.'), 401)
				response.headers['Content-Type'] = 'application/json'
				return response
		access_token = credentials.access_token
		url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
					 % access_token)
		h = httplib2.Http()
		result = json.loads(h.request(url, 'GET')[1])
		if result.get('error') is not None:
				response = make_response(json.dumps(result.get('error')), 500)
				response.headers['Content-Type'] = 'application/json'
				return response
		gplus_id = credentials.id_token['sub']
		if result['user_id'] != gplus_id:
				response = make_response(
						json.dumps("Token's user ID doesn't match given user ID."), 401)
				response.headers['Content-Type'] = 'application/json'
				return response
		if result['issued_to'] != CLIENT_ID:
				response = make_response(
						json.dumps("Token's client ID does not match app's."), 401)
				print "Token's client ID does not match app's."
				response.headers['Content-Type'] = 'application/json'
				return response
		stored_access_token = login_session.get('access_token')
		stored_gplus_id = login_session.get('gplus_id')
		if stored_access_token is not None and gplus_id == stored_gplus_id:
				response = make_response(json.dumps('Current user is already connected.'),
																 200)
				response.headers['Content-Type'] = 'application/json'
				return response
		login_session['access_token'] = credentials.access_token
		login_session['gplus_id'] = gplus_id
		userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
		params = {'access_token': credentials.access_token, 'alt': 'json'}
		answer = requests.get(userinfo_url, params=params)
		data = answer.json()
		login_session['username'] = data['name']
		login_session['picture'] = data['picture']
		login_session['email'] = data['email']
		login_session['provider'] = 'google'
		user_id = getUserId(login_session['email'])
		if not user_id:
			user_id = createUser(login_session)
		login_session['user_id'] = user_id
		output = ''
		output += '<h1>Welcome, '
		output += login_session['username']
		output += '!</h1>'
		output += '<img src="'
		output += login_session['picture']
		output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
		flash("you are now logged in as %s" % login_session['username'])
		print "done!"
		return output

@app.route('/gdisconnect')
def gdisconnect():
		access_token = login_session.get('access_token')
		if access_token is None:
				print 'Access Token is None'
				response = make_response(json.dumps('Current user not connected.'), 401)
				response.headers['Content-Type'] = 'application/json'
				return response
		print 'In gdisconnect access token is %s', access_token
		print 'User name is: '
		print login_session['username']
		url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
		h = httplib2.Http()
		result = h.request(url, 'GET')[0]
		print 'result is '
		print result
		if result['status'] == '200':
				del login_session['access_token']
				del login_session['gplus_id']
				del login_session['username']
				del login_session['email']
				del login_session['picture']
				response = make_response(json.dumps('Successfully disconnected.'), 200)
				response.headers['Content-Type'] = 'application/json'
				return response
		else:
				response = make_response(json.dumps('Failed to revoke token for given user.', 400))
				response.headers['Content-Type'] = 'application/json'
				return response

@app.route('/login')
def showLogin():
	state = ''.join(random.choice(string.ascii_uppercase + string.digits)
										for x in xrange(32))
	login_session['state'] = state
	return render_template('login.html', STATE=state)

@app.route('/disconnect')
def disconnect():
	return "disconnect";

@app.route('/')
@app.route('/catalog')
def showMenu():
	categories = session.query(Category).all()
	return render_template('catalog.html', categories=categories)

@app.route('/catalog/new', methods=['GET', 'POST'])
def newCategory():
	if 'username' not in login_session:
		return redirect('/login')
	if request.method == 'POST':
		return "post request"
	else:
		return render_template('new_category.html')

if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.debug = True
	app.run(host = '0.0.0.0', port = 8000)
