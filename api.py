from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash # This enables us to hash passwords in the DB

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'

db = SQLAlchemy(app)

class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	public_id = db.Column(db.String(50), unique=True)
	name = db.Column(db.String(50))
	password = db.Column(db.String(80))
	admin = db.Column(db.Boolean)

class Todo(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	text = db.Column(db.String(50))
	complete = db.Column(db.Boolean)
	user_id = db.Column(db.Integer)

@app.route('/user', methods=['GET'])
def get_all_users():

	users = User.query.all()

	output = []

	for user in users:
		user_data = {}
		user_data['public_id'] = user.public_id
		user_data['name'] = user.name
		user_data['password'] = user.password
		user_data['admin'] = user.admin
		output.append(user_data)
	
	return jsonify({'users': output})

@app.route('/user/<public_id>', methods=['GET'])
def get_one_user(public_id):

	user = User.query.filter_by(public_id=public_id).first()

	if not user:
		return jsonify({'message' : 'That user could not be found.'})

	user_data = {}
	user_data['public_id'] = user.public_id
	user_data['name'] = user.name
	user_data['password'] = user.password
	user_data['admin'] = user.admin

	return jsonify({'user': user_data})

@app.route('/user', methods=['POST'])
def create_user():
	data = request.get_json()

	hashed_password = generate_password_hash(data['password'], method='sha256')
	
	new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
	db.session.add(new_user)
	db.session.commit()

	return jsonify({'message' : 'New user created!'})

@app.route('/user/<public_id>', methods=['PUT'])
def promote_user(public_id):
	'''Promotes a user to admin status'''
	user = User.query.filter_by(public_id=public_id).first()

	if not user:
		return jsonify({'message' : 'That user could not be found.'})

	user.admin = True
	db.session.commit()

	return jsonify({'message': 'The user has been promoted to admin'})

@app.route('/user/<public_id>', methods=['DELETE'])
def delete_user(public_id):
	user = User.query.filter_by(public_id=public_id).first()

	if not user:
		return jsonify({'message' : 'That user could not be found.'})

	db.session.delete(user)
	db.session.commit()

	return jsonify({'message': f"The user {public_id} has been deleted"})

if __name__ == '__main__':
	app.run(debug=True)