import hashlib
import os
import time
import sys

def main():
    file = '../db/commandhash.txt'
    command_list = []

    new_command = {}
    if not os.path.exists(file):
        print(f"[-] 找不到文件 {file}")
        sys.exit(-1)
    f = open(file,'r',encoding="utf-8")
    for line in f.readlines():
        command_list.append(line.split('||')[0])
    f.close()
    os.unlink(file)
    for command in command_list:
        if not os.path.exists(command):
            continue
        new_hash = get_hash(command)
        new_command[command] = new_hash
    f = open(file,'w')
    for key,value in new_command.items():
        new_line = key+"||"+value+"||"+str(time.time())+"\n"
        f.write(new_line)
    f.close()

def get_hash(file):
    m = hashlib.md5()
    size = 102400
    f = open(file, 'rb')
    while True:
        content = f.read(size)
        if not content:
            break
        m.update(content)
    f.close()
    return m.hexdigest()


if __name__ == '__main__':
    main()