cry = []
with open("Shellcode.bak","rb") as f:
    yeety = f.read()
    for i in range(len(yeety)):
        cry.append(yeety[i] ^ 0x66)

print(cry)
print(len(cry))