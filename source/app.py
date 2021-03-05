from flask import Flask, make_response, render_template
import redis

from crypt import encrypt, decrypt

application = Flask(__name__)

@application.route('/')
def main():
    response = make_response('Hello World!',200)
    return response

@application.route('/dyn')
def dyninfo():
    # ipauditor status
    r = redis.Redis(host='redis', port=6379, db=0)
    try:
        json = decrypt(r.get('dynrecords'))
        return json
    except TypeError:
        response = make_response("No Data Populated Yet...",200)
        return response

@application.route('/danglers')
def dyndang():
    # ipauditor status
    r = redis.Redis(host='redis', port=6379, db=0)
    try:
        json = decrypt(r.get('danglers'))
        return json
    except TypeError:
        response = make_response("No Data Populated Yet...",200)
        return response

@application.route('/ips')
def ipinfo():
    # ipauditor status
    r = redis.Redis(host='redis', port=6379, db=0)
    try:
        json = decrypt(r.get('ipauditor'))
        return json
    except TypeError:
        response = make_response("No Data Populated Yet...",200)
        return response

@application.route('/s3')
def s3info():
    # ipauditor status
    r = redis.Redis(host='redis', port=6379, db=0)
    try:
        json = decrypt(r.get('s3auditor'))
        return json
    except TypeError:
        response = make_response("No Data Populated Yet...",200)
        return response
