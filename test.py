from hashlib import sha256

msg = input()
print(sha256(msg.encode()).hexdigest())