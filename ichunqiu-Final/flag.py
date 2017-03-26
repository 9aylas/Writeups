import requests
def send(flag):
    err=0
    while err<5:
        try:
            print '[+] Submitting flag {} ,try {}'.format(flag,err+1)
            r=requests.post('http://172.16.4.1/Common/submitAnswer',data={'answer':flag,'token':'6bdd21c24573ce9f344b12b462555212'})
            r.close()
            return r.content
        except Exception as e:
            err+=1
            print e.message
    print '[-] Flag {} submit FAIL!!'.format(flag)
    return None


if __name__=="__main__":
    s=send('test')
    print s['status'],s['msg']