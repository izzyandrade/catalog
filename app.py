from flask import Flask, render_template
from flask import request, redirect, jsonify, url_for, flash
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
    open('client_secrets.json', 'r').read()
    )['web']['client_id']
APPLICATION_NAME = "Catalog Project"

# Connect to Database and create database session
engine = create_engine('sqlite:///catalogdatabase.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# USER METHODS
def createUser(login_session):
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture']
        )
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserId(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# this is a function that calls the google login API
# gets the user data and uses it inside our app
# for authentication and authorization
# if the user has never logged in with that account, it also inserts
# the user data at the database, so that it will stay recorded
@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(
            json.dumps('Invalid state parameter.'), 401
            )
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401
            )
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = (
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
        % access_token
        )
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401
            )
        response.headers['Content-Type'] = 'application/json'
        return response
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401
            )
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200
            )
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
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# disconnects from google plus
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    url = 'https://accounts.google.com/o/oauth2/revoke?token={}'.format(
        access_token
        )
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        return "You have been logged out."
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400
            )
        response.headers['Content-Type'] = 'application/json'
        return response


# checks what auth provider the user is using and disconnects it
# as the system uses just google auth it will only check that
# but the route must be there in case there are other providers like facebook
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showMenu'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showMenu'))


# login route
@app.route('/login')
def showLogin():
    state = ''.join(
        random.choice(
            string.ascii_uppercase + string.digits
            )for x in xrange(32)
        )
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# For development purposes, clears the data inside the database.
@app.route('/cleardata')
def clear_data():
    meta = Base.metadata
    for table in reversed(meta.sorted_tables):
        print 'Clear table %s' % table
        session.execute(table.delete())
    session.commit()
    return "sucess"


# Homepage route
@app.route('/')
@app.route('/catalog')
def showMenu():
    categories = session.query(Category).all()
    items = session.query(Item).all()
    return render_template(
        'catalog.html', categories=categories,
        login_session=login_session, items=items
        )


# CRUD - Create category
@app.route('/catalog/new', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCategory = Category(
            name=request.form['name'],
            description=request.form['description'],
            user_id=login_session['user_id']
            )
        session.add(newCategory)
        session.commit()
        flash("The category was added!")
        return redirect(url_for('showMenu'))
    else:
        return render_template('new_category.html')


# CRUD - Edit category
@app.route('/catalog/<int:category_id>/edit', methods=['GET', 'POST'])
def editCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    if(creator.id != login_session['user_id']):
        flash("You did not create this category!")
        return redirect(url_for('showMenu'))
    if request.method == 'POST':
        category.name = request.form['name']
        category.description = request.form['description']
        session.add(category)
        session.commit()
        flash("The category was successfully edited!")
        return redirect(url_for('showMenu'))
    else:
        return render_template('edit_category.html', category=category)


# CRUD - DELETE category
@app.route('/catalog/<int:category_id>/delete', methods=['GET', 'POST'])
def deleteCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    if(creator.id != login_session['user_id']):
        flash("You did not create this category!")
        return redirect(url_for('showMenu'))
    if request.method == 'POST':
        session.delete(category)
        session.commit()
        flash("Category successfully deleted!")
        return redirect(url_for('showMenu'))
    else:
        return render_template('delete_category.html', category=category)


# CRUD - create new category item
@app.route('/catalog/<int:category_id>/new', methods=['GET', 'POST'])
def newItem(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    if(creator.id != login_session['user_id']):
        flash("You did not create this category!")
        return redirect(url_for('showMenu'))
    if request.method == 'POST':
        item = Item(
            name=request.form['name'],
            description=request.form['description'],
            user_id=login_session['user_id'],
            category_id=category.id
            )
        session.add(item)
        session.commit()
        flash("Item successfully created!")
        return redirect(url_for('showMenu'))
    else:
        return render_template('new_item.html', category=category)


# CRUD - Delete category item
@app.route(
    '/catalog/<int:category_id>/delete/<int:item_id>', methods=['GET', 'POST']
    )
def deleteItem(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    item = session.query(Item).filter_by(id=item_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    if(creator.id != login_session['user_id']):
        flash("You did not create this item!")
        return redirect(url_for('showMenu'))
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash('Item successfully deleted')
        return redirect(url_for('showMenu'))
    else:
        return render_template(
            'delete_item.html',
            item=item,
            category=category
            )


# CRUD - Edit category item
@app.route(
    '/catalog/<int:category_id>/edit/<int:item_id>',
    methods=['GET', 'POST']
    )
def editItem(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    item = session.query(Item).filter_by(id=item_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    if(creator.id != login_session['user_id']):
        flash("You did not create this item!")
        return redirect(url_for('showMenu'))
    if request.method == 'POST':
        item.name = request.form['name']
        item.description = request.form['description']
        session.add(item)
        session.commit()
        flash("Item successfully edited!")
        return redirect(url_for('showMenu'))
    else:
        return render_template(
            'edit_item.html',
            item=item,
            category=category
            )


# JSON APIs to view Catalog Information
@app.route('/catalog/<int:category_id>/items/JSON')
def categoryItemsJSON(category_id):
        category = session.query(Category).filter_by(id=category_id).one()
        items = session.query(Item).filter_by(category_id=category_id).all()
        return jsonify(Item=[i.serialize for i in items])


@app.route('/catalog/<int:category_id>/items/<int:item_id>/JSON')
def itemJSON(category_id, item_id):
        item = session.query(Item).filter_by(id=item_id).one()
        return jsonify(Item=item.serialize)


@app.route('/catalog/JSON')
def categoriesJSON():
        categories = session.query(Category).all()
        return jsonify(Category=[c.serialize for c in categories])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
