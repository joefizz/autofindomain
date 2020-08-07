#!/usr/bin/env python3

import hmac
import hashlib
import time
import requests
from flask import Flask, request

app = Flask(__name__)
@app.route('/', methods=['POST'])
def result():
	print(request.form['X-Slack-Request-Timestamp']) # should display 'bar'
	return 'Received !' # response to your request.


def verify_request(request):
	SIGNING_SECRET = "4a7ab5fd678c1d138b002ed0daea375c"
	# Convert your signing secret to bytes
	slack_signing_secret = bytes(SIGNING_SECRET, "utf-8")
	request_body = request.get_data().decode()
	slack_request_timestamp = request.headers["X-Slack-Request-Timestamp"]
	slack_signature = request.headers["X-Slack-Signature"]
	# Check that the request is no more than 60 seconds old
	if (int(time.time()) - int(slack_request_timestamp)) > 60:
		print("Verification failed. Request is out of date.")
		return False
	# Create a basestring by concatenating the version, the request timestamp, and the request body
	basestring = f"v0:{slack_request_timestamp}:{request_body}".encode("utf-8")
	# Hash the basestring using your signing secret, take the hex digest, and prefix with the version number
	my_signature = (
		"v0=" + hmac.new(slack_signing_secret, basestring, hashlib.sha256).hexdigest()
	)
	# Compare the resulting signature with the signature on the request to verify the request
	if hmac.compare_digest(my_signature, slack_signature):
		return True
	else:
		print("Verification failed. Signature invalid.")
		return False