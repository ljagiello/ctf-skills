from Crypto.Util.number import bytes_to_long, getPrime

FLAG = open("flag.txt", "rb").read().strip()
m = bytes_to_long(FLAG)
e = 3

# The same message goes out to three different recipients.
with open("output.txt", "w") as out:
    out.write(f"e = {e}\n")
    for i in range(3):
        n = getPrime(512) * getPrime(512)
        out.write(f"n{i + 1} = {n}\n")
        out.write(f"c{i + 1} = {pow(m, e, n)}\n")
