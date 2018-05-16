from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

from flask import session as login_session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "catalog app"


app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLogin():
	state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
	login_session['state'] = state
	return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
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

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    print login_session['email']

    user_id = getUserID(login_session['email'])
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
        #return response
        return redirect(url_for('showLatest'))
    print 'In gdisconnect access token is %s' % access_token
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
        #return response
        return redirect(url_for('showLatest'))
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        #return response
        return redirect(url_for('showLatest'))

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.uid


def getUserInfo(user_id):
    user = session.query(User).filter_by(uid=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.uid
    except:
        return None

#END OF LOGIN AND DISCONNECT ROUTES


@app.route('/')
@app.route('/catalog/')
def showLatest():
	print "in showlatest"
	categories = session.query(Category).all()
	#return "This is the showLatest page"
	latest = session.query(Item).order_by(Item.date.desc()).limit(10)
	return render_template('latest.html', categories = categories, latest = latest, login_session = login_session)
	

@app.route('/catalog/<string:category_name>/items/')
@app.route('/catalog/<string:category_name>/')
def showCategory(category_name):
	items = session.query(Item).filter_by(category_name = category_name).all()
	categories = session.query(Category).all()
	#return "This is the category page which should list all items in category %s" % category_name
	return render_template('items-cat.html', categories = categories, category_name = category_name, items = items, login_session = login_session)

@app.route('/catalog/new/', methods=['GET', 'POST'])
def addCategory():
	if 'username' not in login_session:
		return redirect('/login')
	if request.method == 'POST':
		user_id = login_session['user_id']
		newCategory = Category(name=request.form['name'])
		session.add(newCategory)
		session.commit()
		return redirect(url_for('showCategory', category_name = newCategory.name, login_session = login_session))
	else:
		return render_template('new-category.html', login_session = login_session)

@app.route('/catalog/<string:category_name>/edit/')
def editCategory(category_name):
	
	return "This is the edit category page"

@app.route('/catalog/<string:category_name>/delete/')
def deleteCategory(category_name):
	
	return "This is the delete category page"

@app.route('/catalog/<string:category_name>/<string:item_name>/')
def showItem(category_name, item_name):

	item = session.query(Item).filter_by(name = item_name).one()
	creator = getUserInfo(item.uid)
	if 'username' not in login_session or creator.uid != login_session['user_id']:
		return render_template('public-item-desc.html', item = item, login_session = login_session)
	else:
		return render_template('item-desc.html', item = item, login_session = login_session)
	#return "This is the description page for %s" % item_name

@app.route('/catalog/<string:category_name>/new/', methods=['GET', 'POST'])
def addItem(category_name):
	if 'username' not in login_session:
		return redirect('/login')
	if request.method == 'POST':
		user_id = login_session['user_id']
		newItem = Item(name=request.form['name'],
						description=request.form['description'],
						category_name=category_name,
						uid=user_id)
		session.add(newItem)
		session.commit()
		return redirect(url_for('showItem', category_name = category_name, item_name = newItem.name, login_session = login_session))
	else:
		return render_template('new-item.html', category_name = category_name, login_session = login_session)
	

@app.route('/catalog/<string:category_name>/<string:item_name>/edit/', methods=['GET', 'POST'])
def editItem(category_name, item_name):
	if 'username' not in login_session:
		return redirect('/login')
	editItem = session.query(Item).filter_by(name = item_name).one()
	if editItem.uid != login_session['user_id']:
		return "<script>function myFunction() {alert('You are not authorized to edit this item');}</script><body onload='myFunction()''>"
	if request.method == 'POST':
		if request.form['name']:
			editItem.name = request.form['name']
		if request.form['description']:
			editItem.description = request.form['description']
		session.add(editItem)
		session.commit()
		return redirect(url_for('showItem', category_name = category_name, item_name = editItem.name, login_session = login_session))
	else:
		return render_template('edit-item.html', item = editItem, login_session = login_session)

@app.route('/catalog/<string:category_name>/<string:item_name>/delete/', methods=['GET', 'POST'])
def deleteItem(category_name, item_name):
	if 'username' not in login_session:
		return redirect('/login')
	delItem = session.query(Item).filter_by(name = item_name).one()
	if delItem.uid != login_session['user_id']:
		return "<script>function myFunction() {alert('You are not authorized to delete this item');}</script><body onload='myFunction()''>"
	if request.method == 'POST':		
		session.delete(delItem)
		session.commit()
		return redirect(url_for('showCategory', category_name = category_name, login_session = login_session))
	else:
		return render_template('delete-item.html', item = delItem, login_session = login_session)


if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.debug = True
	app.run(host='0.0.0.0', port=5000)
