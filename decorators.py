import jwt
from flask import request, abort

from constants import JWT_SECRET, JWT_ALGORITHMS


def auth_requires(func):
    def wrapper(*args, **kwargs):
        if "Authorization" not in request.headers:
            abort(401)

        data = request.headers["Authorization"]
        token = data.split("Bearer ")[-1]

        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHMS])
        except Exception as e:
            print("JWT Decode Exception", e)
            abort(401)

        return func(*args, **kwargs)

    return wrapper


def admin_requires(func):
    def wrapper(*args, **kwargs):
        if "Authorization" not in request.headers:
            abort(401)

        data = request.headers["Authorization"]
        token = data.split("Bearer ")[-1]
        role = None

        try:
            user = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHMS])
            role = user.get('role', 'user')
        except Exception as e:
            print("JWT Decode Exception", e)
            abort(401)

        if role != 'admin':
            abort(403)

        return func(*args, **kwargs)
    return wrapper
