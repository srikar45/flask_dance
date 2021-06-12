from flask import Flask
from flask import flash
import requests
from flask_dance.contrib.github import make_github_blueprint, github
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_dance.contrib.github import make_github_blueprint
from flask_login import UserMixin, current_user, LoginManager, login_required, login_user, logout_user
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin, SQLAlchemyStorage
from flask_dance.consumer import oauth_authorized
from sqlalchemy.orm.exc import NoResultFound

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:////Users/srikar_reddy/Downloads/ksr4599_Hapi/flask-dance/login.db'


github_blueprint = make_github_blueprint(client_id='afb4cb9b88d7c6ede452', client_secret='671bb9b1abed8036a29072a0951961c67237292c')

app.register_blueprint(github_blueprint, url_prefix='/github_login')

db = SQLAlchemy(app)
login_manager = LoginManager(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(256), unique=True)

class OAuth(OAuthConsumerMixin, db.Model):
    provider_user_id = db.Column(db.String(256), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    user = db.relationship(User)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

github_blueprint.backend = make_github_blueprint(
    storage=SQLAlchemyStorage(OAuth, db.session, user=current_user)
)


@app.route('/github')
def github_login():
    if not github.authorized:
        return redirect(url_for('github.login'))

    account_info = github.get('/user')
    account_info_json = account_info.json()

    return '<h1>Your Github name is {}'.format(account_info_json['login'])


@oauth_authorized.connect_via(github_blueprint)
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
        user_data = OAuth.query.get(int(oauth.user.id))
        print("user_oauth_token")
        user_oauth_token = user_data.token["access_token"]
        print(user_oauth_token)
        
        print("Successfully signed in with GitHub.")

    else:
        user = User(
            username=github_info["login"]
        )
        oauth.user = user
        db.session.add_all([user, oauth])
        db.session.commit()
        login_user(user)
        print("Successfully signed in with GitHub.")

    return False

@app.route('/')
@login_required
def index():
    return '<h1>You are logged in as {} <h1>'.format(current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))



if __name__ == '__main__':
    app.run(debug=True)
