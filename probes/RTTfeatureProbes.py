import socket, sys, time, random, ssl, string, traceback
from struct import *
from networking.tcp.TCPSegment import TCPSYNSegment
from networking.tls.messages import *
from networking.tls.extensions import *
from networking.tls.cipherSuites import CIPHER_SUITES, SIGNATURE_ALGORITHMS
from urllib.parse import urlparse
from tldextract import extract
from binascii import  unhexlify
from RDP_structs import build_mcs_initial

class TimingProbe:

    def __init__(self, rdp_ip, rdp_port = 3389):
        self.rdp_ip = rdp_ip
        self.rawSocket = False
        self.sslSocket = False
        self.rdp_port = rdp_port
        self.dest_ip = rdp_ip
        self.dest_port = rdp_port
       # self.https_port = https_port
        #
        # if('//' not in domain):
        #     self.site = 'https://' + domain
        # else:
        #     self.site = domain
        # self.fullDomain, self.primaryDomain, self.port, self.path = TimingProbe.parseURL(self.site)
        #
        # try:
        #     self.dest_ip = socket.gethostbyname(self.fullDomain)
        # except:
        #     self.dest_ip = None

    @staticmethod
    def parseURL(url):
        parts = urlparse(url)

        fullDomain = parts.netloc
        if(':' in fullDomain):
            fullDomain = fullDomain.split(':')[0]
        port = parts.port
        path = parts.path

        tsd, td, tsu = extract(fullDomain)
        primaryDomain = td + '.' + tsu

        return fullDomain, primaryDomain, port, path

    def connect(self, rawSocket=False, sslSocket=False, timeout=5):
        self.socket = None

        if(rawSocket):
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.socket.settimeout(timeout)
            self.rawSocket = True
            # tell kernel not to put in headers, since we are providing it
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        elif(sslSocket):
            self.sslSocket = True
            context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
            context.verify_mode = ssl.CERT_NONE # disable cert. validation
            context.check_hostname = False  # disable host name checking
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create socket
            self.socket = context.wrap_socket(s, server_hostname = self.rdp_ip, do_handshake_on_connect=False) # wrap socket into TLS context
            self.socket.settimeout(timeout)
            startTime = time.time()
            self.socket.connect((self.dest_ip, self.dest_port)) # TLS socket connection
            connect_rtt = time.time() - startTime

        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(timeout)
            startTime = time.time()
            self.socket.connect((self.dest_ip, self.dest_port))
            print("tcp three handshake",end='')
            print(time.time() - startTime)


    def disconnect(self):
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except:
            pass
        self.socket.close()

    def getRandomString(self, stringLength=10):
        """Generate a random string of fixed length """
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(stringLength))

    def test(self, payload, rawSocket=False, sslSocket=False, n=10, timeout=4):
        results = []

        for i in range(0, n):
            try:
                self.connect(rawSocket=rawSocket, sslSocket=sslSocket, timeout=timeout)
            except:
                results.append(None)
                print('RTTProbe connect error')
                continue

            perf = None
            try:
                if(self.rawSocket):
                    startTime = time.time()
                    self.socket.sendto(payload, (self.dest_ip , self.dest_port))
                    msg , addr = self.socket.recvfrom(1024,1)
                    print(msg)
                    print(addr)
                    perf = time.time() - startTime
                elif(self.sslSocket and payload==None):
                    startTime = time.time()
                    self.socket.do_handshake()
                    perf = time.time() - startTime
                else:
                    startTime = time.time()
                    self.socket.send(payload)
                    msg = self.socket.recv(1024)
                    print(msg)
                    perf = time.time() - startTime
            except (TimeoutError, ConnectionResetError, socket.gaierror, socket.timeout, ConnectionRefusedError, OSError) as e:
                print("RTTprobe error")
                print(e)
                perf = time.time() - startTime
                pass
            finally:
                self.disconnect()
                results.append(perf)
                
        print(results) # add by srh
        results = [result for result in results if result != None]
        if(len(results) == 0):
            return -1
        return min(results)

    def test_ssl(self, payload, rawSocket=False, sslSocket=False, n=10, timeout=5):
        results = []

        for i in range(0, n):
            try:
                self.connect(rawSocket=rawSocket, sslSocket=sslSocket, timeout=timeout)
            except:
                results.append(None)
                print('RTTProbe connect error')
                continue
            startTime = time.time()
            x224ConnReqPDU = unhexlify(b"030000130ee00000000000010008000b000000")
            self.socket.send(x224ConnReqPDU)
            x224msg = self.socket.recv(1024)
            perf2 = time.time() - startTime
            print(perf2)
            perf = None
            try:
                if(self.rawSocket):
                    startTime = time.time()
                    self.socket.sendto(payload, (self.dest_ip , self.dest_port))
                    msg = self.socket.recv(1024)
                    #print(msg)
                    perf = time.time() - startTime
                elif(self.sslSocket and payload==None):
                    startTime = time.time()
                    self.socket.do_handshake()
                    perf = time.time() - startTime
                else:
                    startTime = time.time()
                    self.socket.send(payload)
                    msg = self.socket.recv(1024)
                    perf = time.time() - startTime
            except (TimeoutError, ConnectionResetError, socket.gaierror, socket.timeout, ConnectionRefusedError, OSError) as e:
                print("RTTprobe error")
                print(e)
                pass
            finally:
                self.disconnect()
                results.append(perf) 
                print("results") # add by srh

        results = [result for result in results if result != None]
        if(len(results) == 0):
            return -1
        return min(results)

    def rdp_connect(self, rawSocket=False, sec_grade=1 , sslSocket=False, n=3, timeout=10):
        conrtt_results = []
        x224rtt_results = []
        MCSrtt_results = []

        for i in range(0, n):
            x224rtt = None 
            self.sslSocket = True
            context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
            context.verify_mode = ssl.CERT_NONE # disable cert. validation
            context.check_hostname = False  # disable host name checking
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create socket
            s.settimeout(timeout)
            try: 
                startTime = time.time()
                s.connect((self.dest_ip, self.dest_port)) # TLS socket connection
                connectrtt = time.time() - startTime
            except:
                conrtt_results.append(None)
                x224rtt_results.append(None)
                MCSrtt_results.append(None)
                continue
            conrtt_results.append(connectrtt)

            if sec_grade == 1:
                x224ConnReqPDU = unhexlify(b"030000130ee000000000000100080001000000")#SSL
            else :
                x224ConnReqPDU = unhexlify(b"030000130ee000000000000100080002000000")#CredSSP
            try:
                startTime = time.time()
                s.send(x224ConnReqPDU)
                x224msg = s.recv(1024)
                #print(x224msg)
                x224rtt = time.time() - startTime
                x224rtt_results.append(x224rtt)
            except:
                x224rtt_results.append(None)
                MCSrtt_results.append(None)
                #traceback.print_exc()
                continue
            
            try:
                self.socket = context.wrap_socket(s, server_hostname = self.rdp_ip, do_handshake_on_connect=False) # wrap socket into TLS context
                self.socket.do_handshake()
                PDU =None
                if sec_grade == 1: #MCSConnInitPDU
                    PDU = build_mcs_initial()
                else :#ntlm
                    PDU = unhexlify(b"3037a003020106a130302e302ca02a04284e544c4d5353500001000000b78208e2000000000000000000000000000000000a00614a0000000f")#
                startTime = time.time()            
                self.socket.send(PDU)
                msg = self.socket.recv(4096) 
                #print(msg)       
                MCSrtt = time.time() - startTime
                MCSrtt_results.append(MCSrtt)
            except (TimeoutError, ConnectionResetError, socket.gaierror, socket.timeout, ConnectionRefusedError, OSError) as e:
                #print("RTTprobe error")
                #print(e)
                #traceback.print_exc()  
                MCSrtt_results.append(None)                              
                pass
            finally:
                self.disconnect()
                #print("results") # add by srh
        
        conrtt_results = [result for result in conrtt_results if result != None]
        x224rtt_results = [result for result in x224rtt_results if result != None]
        MCSrtt_results = [result for result in MCSrtt_results if result != None]
        # print(conrtt_results)
        # print(x224rtt_results)
        # print(MCSrtt_results)
        min_conrtt = -1; min_x244rtt = -1; min_mcsrtt = -1
        if len(conrtt_results) != 0 :
            min_conrtt = min(conrtt_results)
        if len(x224rtt_results) != 0 :
            min_x244rtt = min(x224rtt_results)
        if len(MCSrtt_results) != 0 :
            min_mcsrtt = min(MCSrtt_results)        

        return [min_conrtt, min_x244rtt, min_mcsrtt]

class tcpSYNTiming(TimingProbe):

    def test(self, n=1):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            self.source_ip, self.source_port = s.getsockname()
            #self.dest_port = self.https_port
        except Exception as e:
            return -1
        finally:
            s.close()

        try:
            tcpSynPacket = TCPSYNSegment(self.source_ip, self.source_port, self.dest_ip, self.dest_port).create()
        except:
            return -1
        return super().test(tcpSynPacket, rawSocket=True, n=n)

class RdpConnectTiming_SSL(TimingProbe):

    def test(self,n=2):
        x224ConnReqPDU = unhexlify(b"030000130ee000000000000100080001000000")
        return super().rdp_connect(sec_grade=1, sslSocket=True, n=n)

class RdpConnectTiming_Cred(TimingProbe):

    def test(self,n=2):
        x224ConnReqPDU = unhexlify(b"030000130ee000000000000100080001000000")
        return super().rdp_connect(sec_grade=2, sslSocket=True, n=n)

class x224ConnReqTiming_RDP(TimingProbe):

    def test(self,n=5):
        x224ConnReqPDU = unhexlify(b"030000130ee000000000000100080000000000")
        return super().test(x224ConnReqPDU, n=n)

class x224ConnReqTiming_SSL(TimingProbe):

    def test(self,n=3):
        x224ConnReqPDU = unhexlify(b"030000130ee000000000000100080001000000")
        return super().test(x224ConnReqPDU, n=n)

class x224ConnReqTiming_HYBRID(TimingProbe):

    def test(self,n=1):
        x224ConnReqPDU = unhexlify(b"030000130ee000000000000100080003000000")
        return super().test(x224ConnReqPDU, n=n)

class x224ConnReqTiming_HYBRID_EX(TimingProbe):

    def test(self,n=3):
        x224ConnReqPDU = unhexlify(b"030000130ee00000000000010008000d000000")
        return super().test(x224ConnReqPDU, n=n)

class tlsClientHelloTiming(TimingProbe):

    def make_client_hello(self):
        extensions = [SignatureAlgorithms.create(SIGNATURE_ALGORITHMS),
                    SupportedVersionsExtension.create(), ECPointFormatsExtension.create(),
                    SupportedGroupsExtension.create(), SessionTicketExtension.create(),
                    EncryptThenMacExtension.create(), ExtendedMasterSecretExtension.create(),
                    PSKKeyExchangeModesExtension.create(), KeyShareExtension.create()]
        # if(self.fullDomain != None):
        #     extensions.append(ServerNameExtension.create(self.fullDomain))

        hello = ClientHelloMessage.create(TLSRecord.TLS1_2,
                                          bytearray(random.getrandbits(8) for _ in range(32)),
                                          CIPHER_SUITES,
                                          extensions=extensions,
                                          session_id=bytearray(random.getrandbits(8) for _ in range(32)))

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=TLSRecord.TLS1_0,
                                  message=hello.bytes)

        return record.bytes

    def test(self, n=3):
        clientHelloMessage = self.make_client_hello()
        return super().test_ssl(clientHelloMessage, n=n)

class tlsClientHelloErrorTiming(TimingProbe):

    def test(self, n=1):
        clientHelloMessage = b'\xcfU"\xf1\';\x8c\xd8\xb0W)7+\xbc\xedN\x07\xc9*\xc9d\xdb\x19@M\x81-\x980P%\x8a'
        return super().test(clientHelloMessage, timeout=2, n=n)

# https://stackoverflow.com/questions/52697613/measuring-tls-handshake-performance-time-in-python
class tlsHandshakeTiming(TimingProbe):

    def test(self, n=1):
        return super().test(None, sslSocket=True, n=n)


