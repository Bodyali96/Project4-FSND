"""
This code represents the backend of Category Item Project
All the code in one file, this is not the best practice,
but I had to do this to avoid import problems
The code uses Flask micro-framework and its extentions,
in addtion to OAuth extention to add a third-party authentication
NOTE: to run this app correctly, first:
python run.py --setup
to initialize the database and configuration,
and then:
python run.py
"""
import sys  # to configure env arguments
import os  # to change the cwd
from flask import (
    Flask, render_template, url_for,
    flash, redirect, request, abort
)
from flask_sqlalchemy import SQLAlchemy  # installed
from flask_bcrypt import Bcrypt  # installed, to hash the password
from flask_wtf import FlaskForm  # installed, to create forms and validate it
from flask import jsonify
# the forms fields and validators
from wtforms import (
    StringField, PasswordField, SubmitField,
    BooleanField, SelectField, DecimalField
)
from wtforms.validators import (
    DataRequired, Length,
    Email, EqualTo, ValidationError
)

from sqlalchemy.orm.exc import NoResultFound
# the following imports are to handle authorization and login
from flask_dance.contrib.github import (
    make_github_blueprint, github
)
from flask_dance.consumer.backend.sqla import (
    OAuthConsumerMixin, SQLAlchemyBackend
)
from flask_dance.consumer import (
    oauth_authorized, oauth_error
)
from flask_login import (
    LoginManager, UserMixin, current_user,
    login_required, login_user, logout_user
)

# setup Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = '669cb1481ecf76427f625b5233b0ca'
blueprint = make_github_blueprint(
    # showing these info is not the best practice,
    # but since this project is just for edu purposes,
    # I wrote the clint_id and client_secrets to ease the
    # process of running the file
    client_id="1568a5199334b2604837",
    client_secret="35dbc7f21f1e80b8f5304b46b1bed52fb408dce9",
)
app.register_blueprint(blueprint, url_prefix="/login")
bcrypt = Bcrypt(app)

# setup database models
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
# categories are just an array because we don't want the users
# to be able to add new categories,
# they are only able to add items
categories = ['Soccer', 'Basketball', 'Baseball', 'Frisbee',
              'Snowboarding', 'Rock Climbing', 'Foosball', 'Skating', 'Hockey']

# creating models

# since we are using SQLAlchemy, the fields in the following
# represent the columns in the tables in db with thier datatypes


class User(db.Model, UserMixin):
    """
    Registered user information is stored in db
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(256), unique=True)
    email = db.Column(db.String(256), unique=True)
    password = db.Column(db.String(60))
    items = db.relationship('Item', backref='Owner', lazy=True)


class Category(db.Model):
    """
    Categories that hold items are stored in db
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    items = db.relationship('Item', backref='Category', lazy=True)


class Item(db.Model):
    """
    items that exist in each category stored in db
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    desc = db.Column(db.String(300), nullable=False)
    owner_username = db.Column(
        db.String(50), db.ForeignKey('user.username'), nullable=False)
    category_name = db.Column(db.String(20), db.ForeignKey(
        'category.name'), nullable=False)


class OAuth(OAuthConsumerMixin, db.Model):
    """
    OAuth class that is connected to User class
    to register github users localy in the db
    """
    provider_user_id = db.Column(db.String(256), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    user = db.relationship(User)


# creating forms

class RegistrationForm(FlaskForm):
    """
    The registration form that will appear to users
    in registration page '/register'
    """
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(),
                                                 EqualTo('password')])
    submit = SubmitField('Sign Up')

    # the following methods ensure that either the username
    # or the email does not already exist in the db
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(
                'That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(
                'That email is taken. Please choose a different one.')


class LoginForm(FlaskForm):
    """
    The Login form that will appear to users
    in Login page '/login'
    """
    username = StringField('Username',
                           validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class ItemForm(FlaskForm):
    """
    This ItemForm has two different uses:
    - adding new item to the db
    - editing an existing item in the db
    """
    name = StringField('Item Name', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired()])
    desc = StringField('Description', validators=[DataRequired()])
    categories_list = []
    for c in categories:
        categories_list.append((c, c))
    category = SelectField(u'Category', validators=[
                           DataRequired()], choices=categories_list)
    submit = SubmitField('Update')


# setup login manager
login_manager = LoginManager(app)
login_manager.login_view = 'github.login'
login_manager.login_message_category = 'info'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# setup SQLAlchemy backend
blueprint.backend = SQLAlchemyBackend(OAuth, db.session, user=current_user)


# create/login local user on successful OAuth login
# the following 2 functions are taken from
# the homepage of flask-dance extention
# with some edits to fit the project
@oauth_authorized.connect_via(blueprint)
def github_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with GitHub.", category="error")
        return False

    resp = blueprint.session.get("/user")
    if not resp.ok:
        msg = "Failed to fetch user info from GitHub."
        flash(msg, category="error")
        return False

    github_info = resp.json()
    github_user_id = str(github_info["id"])

    # Find this OAuth token in the database, or create it
    query = OAuth.query.filter_by(
        provider=blueprint.name,
        provider_user_id=github_user_id,
    )
    try:
        oauth = query.one()
    except NoResultFound:
        oauth = OAuth(
            provider=blueprint.name,
            provider_user_id=github_user_id,
            token=token,
        )

    if oauth.user:
        login_user(oauth.user)
        flash("Successfully signed in with GitHub.", category='success')

    else:
        # Create a new local user account for this user
        user = User(
            # Remember that `email` can be None, if the user declines
            # to publish their email address on GitHub!
            email=github_info.get("email"),
            username=github_info.get("login").lower()
        )
        # Associate the new local user account with the OAuth token
        oauth.user = user
        # Save and commit our database models
        db.session.add_all([user, oauth])
        db.session.commit()
        # Log in the new local user account
        login_user(user)
        flash("Successfully signed in with GitHub.")

    # Disable Flask-Dance's default behavior for saving the OAuth token
    return False


# notify on OAuth provider error

@oauth_error.connect_via(blueprint)
def github_error(blueprint, error, error_description=None, error_uri=None):
    msg = (
        "OAuth error from {name}! "
        "error={error} description={description} uri={uri}"
    ).format(
        name=blueprint.name,
        error=error,
        description=error_description,
        uri=error_uri,
    )
    flash(msg, category="error")


# method to return categories or items when needed
def wanted(wanted):
    if wanted is 'categories':
        categories = Category.query.all()
        return categories
    elif wanted is 'items':
        items = Item.query.order_by(Item.id.desc()).all()
        return items
    else:
        return None

# routes

# provide json endpoint


def items_json(category):
    items = Item.query.filter_by(category_name=category)
    items_list = []
    for i in items:
        items_list.append(
            {'id': i.id, 'name': i.name, 'price': i.price,
             'description': i.desc, 'owner': i.owner_username}
        )
    return (items_list)


@app.route("/catalog/JSON")
def catalog_json():
    categories_list = []
    for c in Category.query.all():
        categories_list.append(
            {'id': c.id, 'name': c.name,
             'items': items_json(c.name)}
        )
    return jsonify({'Categories': categories_list})


@app.route('/catalog/<category_name>/<item_name>/JSON')
def ItemJSON(category_name, item_name):
    try:
        category = Category.query.filter_by(name=category_name).one()
        item = Item.query.filter_by(name=item_name, category_name=category.name).one()
        return jsonify(
            item=[
                {'name': item.name,
                 'price': item.price,
                 'description': item.desc,
                 'category_name': item.category_name,
                 'owner_username': item.owner_username
                 }
            ]
        )
    except NoResultFound:
        return jsonify(None)

# creating routes


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # prevent user from login if he is already logged in
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(
            username=form.username.data.lower()).first()
        # decrypt the hashed password to compare it with original pass
        if user and bcrypt.check_password_hash(
            user.password, form.password.data
        ):
            login_user(user, remember=form.remember.data)
            # the next two lines are to redirect us to account page
            # if we signed in after trying to
            # access it without an active session
            next_page = request.args.get('next')
            return redirect(next_page)\
                if next_page else redirect(url_for('home'))
        else:
            flash(
                'Login Unsuccessful.' +
                ' Please check username and password', 'danger'
            )

    return render_template(
        'login.html', title='Login',
        form=form, items=wanted('items')
    )


@app.route("/logout")
@login_required
def logout():
    # using logout_user from flask to end the active session
    logout_user()
    flash("You have logged out", category='success')
    return redirect(url_for("home"))


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        # same as login, user can't register if he is already signed in
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        # hashing the password and adding the user to db
        hashed_password =\
            bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = \
            User(username=form.username.data.lower(), email=form.email.data,
                 password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.username.data}!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register',
                           items=wanted('items'), form=form)


@app.route("/")
def home():
    return render_template(
        "home.html",
        categories=wanted('categories'),
        items=wanted('items')
    )


@app.route("/account")
@login_required
def account():
    return render_template(
        'account.html', title='Account',
        items=wanted('items'), user=current_user,
        count=len(current_user.items)
    )


@app.route("/new_item", methods=['GET', 'POST'])
@login_required
def new_item():
    """
    adding new item to the db
    this is a feature for signed in users only
    that is why we include @login_required
    in the top and included the owner_username as
    a column in the database
    """
    form = ItemForm()
    if form.validate_on_submit():
        item = Item(
            name=form.name.data,
            price=form.price.data,
            desc=form.desc.data,
            category_name=form.category.data,
            owner_username=current_user.username
        )
        db.session.add(item)
        db.session.commit()
        flash('Your Item has been created!', 'success')
        return redirect(url_for('home'))
    return render_template(
        'new_item.html',
        title='Create New Item',
        form=form, items=wanted('items')
    )


@app.route("/category/<category_name>")
def category(category_name):
    """
    showing the category specefied by the url with its items
    """
    cat = Category.query.filter_by(name=category_name).first()
    return render_template(
        'category.html',
        title='category_name',
        user=current_user,
        category=cat, items=wanted('items')
    )


@app.route("/item/<int:item_id>/edit", methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.owner_username != current_user.username:
        # to prevent the user from editing other users items
        abort(403)
    form = ItemForm()
    if form.validate_on_submit():
        item.name = form.name.data
        item.price = form.price.data
        item.desc = form.desc.data
        item.category_name = form.category.data
        db.session.commit()
        flash('Your item has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        # to show the itemd info by default when user loads the form
        form.name.data = item.name
        form.price.data = item.price
        form.desc.data = item.desc
        form.category.data = item.category_name
    return render_template('new_item.html', title='Edit Item',
                           form=form, items=wanted('items'))


@app.route("/item/<int:item_id>/delete", methods=['POST'])
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.owner_username != current_user.username:
        abort(403)
    db.session.delete(item)
    db.session.commit()
    flash('Your item has been deleted!', 'success')
    return redirect(url_for('home'))


if __name__ == "__main__":
    """
    when running the file,
    you should first run the command:
    python run.py --setup
    to initialize the db and configure categories
    then you can run the file in the normal way:
    python run.py
    and open your website and go to the link:
    http://localhost:5000
    be sure that there is no application on your
    device using the port 5000 on the localhost
    """
    if "--setup" in sys.argv:
        with app.app_context():
            db.create_all()
            for c in categories:
                db.session.add(Category(name=c))
            db.session.commit()
            print("Database tables created")
    else:
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
        app.run(debug=True)
