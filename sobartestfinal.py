import pyhibp
from pyhibp import pwnedpasswords as pw
# Required: A descriptive user agent must be set describing the application consuming
#   the HIBP API
pyhibp.set_user_agent(ua="Awesome application/0.0.1 (An awesome description)")
# Check a password to see if it has been disclosed in a public breach corpus
resp = pw.is_password_breached(password="secret")
if resp:
    print("Password breached!")
    print("This password was used {0} time(s) before.".format(resp))

# Get data classes in the HIBP system
resp = pyhibp.get_data_classes()
# Get all breach information
resp = pyhibp.get_all_breaches()
# Get a single breach
resp = pyhibp.get_single_breach(breach_name="Adobe")
# An API key is required for calls which search by email address
#   (so get_pastes/get_account_breaches)
# See <https://haveibeenpwned.com/API/Key>
HIBP_API_KEY = None

if HIBP_API_KEY:
    # Set the API key prior to using the functions which require it.
    pyhibp.set_api_key(key=HIBP_API_KEY)

    # Get pastes affecting a given email address
    resp = pyhibp.get_pastes(email_address="test@example.com")

    # Get breaches that affect a given account
    resp = pyhibp.get_account_breaches(account="test@example.com", truncate_response=True)

    import random
password_len = int(input("Enter the length of the password: "))
UPPERCASE = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'M', 'N', 'O', 'p', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
LOWERCASE = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',  'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
SPECIAL = ['@', '#', '$', '=', ':', '?', '.', '/', '|', '~', '>', '*', '<']
COMBINED_LIST = DIGITS + UPPERCASE + LOWERCASE + SPECIAL
password = "".join(random.sample(COMBINED_LIST, password_len))
print(password)


import random
import string
print("please inter password lenght (8-12 digits)")
a=input()

a=int(a)

def get_random_password():

    random_source = string.ascii_letters + string.digits + string.punctuation

    password = random.choice(string.ascii_lowercase)

    password += random.choice(string.ascii_uppercase)

    password += random.choice(string.digits)

    password += random.choice(string.punctuation)

    for i in range(a-4):

        password += random.choice(random_source)

    password_list = list(password)

    random.SystemRandom().shuffle(password_list)

    password = ''.join(password_list)

    return password

print("First Random Password is ", get_random_password())

print("Second Random Password is ", get_random_password())
import hashlib
import os

users = {} # A simple demo storage

# Add a user
username = 'Brent' # The users username
password = 'mypassword' # The users password

salt = os.urandom(32) # A new salt for this user
key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
users[username] = { # Store the salt and key
    'salt': salt,
    'key': key
}

# Verification attempt 1 (incorrect password)
username = 'Brent'
password = 'notmypassword'

salt = users[username]['salt'] # Get the salt
key = users[username]['key'] # Get the correct key
new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

assert key != new_key # The keys are not the same thus the passwords were not the same

# Verification attempt 2 (correct password)
username = 'Brent'
password = 'mypassword'

salt = users[username]['salt']
key = users[username]['key']
new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

assert key == new_key # The keys are the same thus the passwords were the same

# Adding a different user
username = 'Jarrod'
password = 'my$ecur3p@$$w0rd'

salt = os.urandom(32) # A new salt for this user
key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
users[username] = {
    'salt': salt,
    'key': key
}

# Checking the other users password
username = 'Jarrod'
password = 'my$ecur3p@$$w0rd'

salt = users[username]['salt']
key = users[username]['key']
new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

assert key == new_key # The keys are the same thus the passwords were the same for this user also

import requests
payload = '{"ticket":{"requester":{"name":"Admin", "email":"asharghi@stud.hs-offenburg.de"}}}'
s = requests.Session()
s.headers.update({'Content-Type': 'application/json'})
s.auth = ('{username}','{password}')
#r = s.post("https://haveibeenpwned.com/", data=payload)
for x in range (0,11999):
    try:
        r = s.post("https://haveibeenpwned.com/api/v2/imports/tickets.json", data=payload)
        print("finished with request number:" + str(x))
    except requests.exceptions.ConnectionError as e:
        print("There was a connection error: %s" % (e))
    except requests.exceptions.Timeout as e:
        print("There was a timeout!!!")
from typing import Text
import unittest
import random
import string
from unittest.case import TestCase
from getpass import getpass
#my conceptual unittests are in the following
class testget_random_password(unittest.TestCase):
    def test_function(self):
      self.assertalmostequal (testget_random_password,"234%&/mwjs")
#my goal here is to see that  is a generated pass equal to an amount that I have defiend in advance or not

class Testgetingpassword(unittest.TestCase):
    password = getpass()
#the objective of this unit test is for the time that attackers try to hack the password by reversing the password
#the idea of this unittest is adopted from "falsetru"
class test_B(unittest,TestCase):
    def test_b(self):
        reversed_password = self.password[::-1]
        self.assertEqual(reversed_password, 'sjwm/&432')
#adopted form the lecture pdf, this unittest is a good way to see that the function is working correct (VERIFICATION)
def testpassitself(self):
     pass = generated_password
     self.asserttrue(pass.TestCase)

#credits to the lecture pdf, this unittest is adopted from lecture the idea is returning the text and calling the web service
def pwncheck(generated_pass):
    password_N = generated_pass[:5]
    answer = requests.get (https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange)
    return answer.Text
