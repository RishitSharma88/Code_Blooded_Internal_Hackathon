from pymongo import MongoClient
from flask import session

client = MongoClient('mongodb://localhost:27017/')
db = client['zepto_clone']
cart_collection = db['cart']

def add_to_cart(username, product):
    cart_collection.update_one(
        {'username': username},
        {'$push': {'items': product}},
        upsert=True
    )

def get_cart(username):
    cart = cart_collection.find_one({'username': username})
    return cart['items'] if cart and 'items' in cart else []

def remove_from_cart(username, code=None, name=None):
    if code:
        cart_collection.update_one(
            {'username': username},
            {'$pull': {'items': {'code': code}}}
        )
    elif name:
        cart_collection.update_one(
            {'username': username},
            {'$pull': {'items': {'name': name}}}
        )

def clear_cart(username):
    cart_collection.delete_one({'username': username}) 