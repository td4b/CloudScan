from flask import Flask, make_response, render_template
import redis, pickle

application = Flask(__name__)

@application.route('/')
def main():
    response = make_response('Hello World!',200)
    return response

@application.route('/ips')
def ipinfo():
    # ipauditor status
    r = redis.Redis(host='redis', port=6379, db=0)
    try:
        json = pickle.loads(r.get('ipauditor'))
        return json
    except TypeError:
        response = make_response("No Data Populated Yet...",200)
        return response

@application.route('/s3')
def s3info():
    # ipauditor status
    r = redis.Redis(host='redis', port=6379, db=0)
    try:
        json = pickle.loads(r.get('s3auditor'))
        return json
    except TypeError:
        response = make_response("No Data Populated Yet...",200)
        return response
