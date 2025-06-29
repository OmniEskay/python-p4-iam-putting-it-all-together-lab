#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        """
        Handles user signup. Creates a new user and logs them in.
        Relies on model validations to catch errors.
        """
        data = request.get_json()
        
        try:
            new_user = User(
                username=data.get('username'),
                image_url=data.get('image_url'),
                bio=data.get('bio')
            )

            # Set password using the password_hash setter, which has validation
            new_user.password_hash = data.get('password')

            db.session.add(new_user)
            db.session.commit()
            
            # Set session user_id after successful creation
            session['user_id'] = new_user.id
            return make_response(new_user.to_dict(rules=('-recipes', '-_password_hash')), 201)
        except (IntegrityError, ValueError) as e:
            # Handle unique constraint violation for username or other validation errors
            db.session.rollback()
            
            error_message = str(e)
            # Customize message for unique username constraint
            if isinstance(e, IntegrityError):
                 error_message = "Username already exists."

            return make_response({"errors": [error_message]}, 422)

class CheckSession(Resource):
    def get(self):
        """
        Checks if a user is logged in by verifying the session.
        """
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return make_response(user.to_dict(rules=('-recipes', '-_password_hash')), 200)
        return make_response({'error': 'Unauthorized'}, 401)

class Login(Resource):
    def post(self):
        """
        Logs a user in by authenticating their credentials.
        """
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return make_response(user.to_dict(rules=('-recipes', '-_password_hash')), 200)
        
        return make_response({'error': 'Invalid username or password'}, 401)

class Logout(Resource):
    def delete(self):
        """
        Logs a user out by clearing their session.
        """
        if session.get('user_id'):
            session.pop('user_id', None)
            return make_response('', 204)
        
        return make_response({'error': 'Unauthorized'}, 401)

class RecipeIndex(Resource):
    def get(self):
        """
        Returns all recipes if the user is logged in.
        """
        if session.get('user_id'):
            recipes = Recipe.query.all()
            # Use serialization rules to include the nested user object
            recipes_dict = [recipe.to_dict() for recipe in recipes]
            return make_response(recipes_dict, 200)
        
        return make_response({'error': 'Unauthorized'}, 401)

    def post(self):
        """
        Creates a new recipe if the user is logged in.
        """
        user_id = session.get('user_id')
        if not user_id:
            return make_response({'error': 'Unauthorized'}, 401)

        data = request.get_json()
        try:
            new_recipe = Recipe(
                title=data.get('title'),
                instructions=data.get('instructions'),
                minutes_to_complete=data.get('minutes_to_complete'),
                user_id=user_id
            )
            db.session.add(new_recipe)
            db.session.commit()
            return make_response(new_recipe.to_dict(), 201)
        except ValueError as e:
            db.session.rollback()
            return make_response({"errors": [str(e)]}, 422)


# Add resources to the API
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
