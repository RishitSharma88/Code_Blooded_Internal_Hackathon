from pymongo import MongoClient
from flask import session

client = MongoClient('mongodb://localhost:27017/')
db = client['zepto_clone']
cart_collection = db['cart']

def mongo_to_dict(doc):
    if not doc:
        return doc
    doc = dict(doc)
    if '_id' in doc:
        doc['_id'] = str(doc['_id'])
    return doc

def add_to_cart(username, product):
    cart_collection.update_one(
        {'username': username},
        {'$push': {'items': product}},
        upsert=True
    )

def get_cart(username):
    cart = cart_collection.find_one({'username': username})
    if cart and 'items' in cart:
        # Convert all items if they have _id fields (paranoia)
        items = [mongo_to_dict(item) for item in cart['items']]
        return items
    return []

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