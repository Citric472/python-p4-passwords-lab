#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from werkzeug.security import generate_password_hash, check_password_hash

from config import app, db, api
from models import User

class ClearSession(Resource):
    def delete(self):
        # Clear session data
        session.clear()
        return {}, 204

class Signup(Resource):
    def post(self):
        # Get JSON data
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        # Create a new user
        user = User(username=username)
        user.password_hash = generate_password_hash(password)

        # Add and commit to the database
        db.session.add(user)
        db.session.commit()

        # Return user data in JSON format
        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return jsonify(user.to_dict())
        return jsonify({})

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        # Find the user
        user = User.query.filter_by(username=username).first()

        # Authenticate the user
        if user and check_password_hash(user.password_hash, password):
            # Set user_id in session
            session['user_id'] = user.id
            # Return user data in JSON format
            return jsonify({
                'user_id': user.id,
                'username': user.username  # Return the username as part of the response
            })
        
        # If authentication fails, return an error
        return jsonify({'error': 'Invalid credentials'}), 401

class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)
        return {}, 204

# Add resources to the API
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
