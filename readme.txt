THIS IS A CLIENT SERVER MESSAGING SERVICE BASED ON AN IMPROVED OLAF/NEIGHBOURHOOD PROTOCOL

BOTH CLIENT AND SERVER FILES CONTAIN THE VULNERABILITY

Each client (max 5, change line 172 of server.py to allow for more/less) is prompted to enter a username. The username must be unique, which the server will validate and then attach a UUID to.
All messages are set to broadcast by default. Simply send a message in the terminal and it will be shown in the server as a JSON object with connection, type, data, counter and signature, and as a normal plaintext message to other clients.
Private messages are end to end encrypted.

FUNCTIONS:

listclients - a client may send "listclients" and be returned with a list of connected users with their usernames and IDs.

message - a client may privately message another user by sending "message {user} {message}", where {user} is the chosen recipient, and {message} is the message they want to send.

Required Libraries:
  - pycryptodome


To run the server (RUN SERVER BEFORE CLIENTS)
$ python server.py

To run the client
$ python client.py

NOTE: when entering name in terminal running client.py, sometimes you may recieve the following output: 
         " Enter your name: abh
          Server (JSON): {
            "type": "name_response",
            "available": true
          }"
In this instance, just CTRL C and run the client.py again and it should work. This is just a bug with the current version of the code and will be fixed before final submission.


TODO:
  -Inter server connections
  -User Interface