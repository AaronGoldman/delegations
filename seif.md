https://www.crockford.com/seif.html

* ed25519-AAAAC3NzaC1lZDI1NTE5AAAAIG3eGI9F0idpD2rTO9bQ5Qj0dvyZJnxEGrM5LOP14CNB@10.0.0.48:8080
  * if a DNS name is provided then resolve the DNS to a public_key@ip:port TXT record. (yes I am puting the port in DNS. Why the hell not?)
* -> {"seif": 1,"handshake": encrypt_pk(bob_public_key, handshake_key),"payload": encrypt(handshake_key, alice_public_key)}
* <- encrypt(handshake_key, {"session": encrypt_pk(alice_public_key, session_key)})
* <- encrypt(session_key, json_payload)
* <- encrypt(session_key, json_payload)
* <- ...
* -> encrypt(session_key, json_payload)
* -> encrypt(session_key, json_payload)
* -> ...

server can start sending data affter sending the session_key to the client
the client need to RTT to get the session_key to send the request
this adds a RTT to the request time to first byte.

Note: alice_public_key may be efemeral
encrypt_pk 
