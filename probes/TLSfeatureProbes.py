import sys, requests, json, os, ssl, socket, asyncio
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse
from tldextract import extract

sys.path.insert(1, os.path.join(os.path.dirname(__file__), 'tls_prober'))
# print(os.path.dirname(__file__))
# print(sys.path)
from tls_prober import prober


# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class FeatureProbe:

    def __init__(self, ip, rdp_port = 3389):
        self.ip = ip

        self.rdp_port = rdp_port

"""    @staticmethod
    def parseURL(url):
        parts = urlparse(url)

        fullDomain = parts.netloc
        if(':' in fullDomain):
            fullDomain = fullDomain.split(':')[0]
        port = parts.port
        path = parts.path

        tsd, td, tsu = extract(fullDomain)
        primaryDomain = td + '.' + tsu

        return fullDomain, primaryDomain, port, path"""

class TLSVersions(FeatureProbe):

    def test(self):
        results = {"SSLv2" : None, "SSLv3" : None, "TLSv1" : None, "TLSv1.1" : None, "TLSv1.2" : None,
                    "TLSv1.3" : None}

        for tlsVersion in results.keys():
            results[tlsVersion] = self.testTLSVersion(tlsVersion)

        return results

    def testTLSVersion(self, version):
        versionFlags = {"SSLv2" : ssl.OP_NO_SSLv2, "SSLv3" : ssl.OP_NO_SSLv3, "TLSv1" : ssl.OP_NO_TLSv1,
                "TLSv1.1" : ssl.OP_NO_TLSv1_1, "TLSv1.2" : ssl.OP_NO_TLSv1_2, "TLSv1.3" : ssl.OP_NO_TLSv1_3}

        context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
        context.verify_mode = ssl.CERT_NONE # disable cert. validation
        context.check_hostname = False  # disable host name checking
        context.options &= ~ssl.OP_NO_SSLv3

        # Disable all TLS versions and reenable the one that we do want
        blackListVersions = ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2
        blackListVersions &= ~versionFlags[version]
        context.options |= blackListVersions

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create socket
        s.connect((self.ip, self.rdp_port))
        #x224
        from binascii import  unhexlify
        x224ConnReqPDU = unhexlify(b"030000130ee000000000000100080008000000")
        s.send(x224ConnReqPDU)
        msg = s.recv(1024)


        try:
            wrappedSocket = context.wrap_socket(s, server_hostname=self.ip, do_handshake_on_connect=True) # wrap socket into TLS context
            wrappedSocket.settimeout(2)
            #wrappedSocket.connect((self.ip, self.rdp_port)) # TLS socket connection #only tcp connect
            # #x224
            # from binascii import  unhexlify
            # x224ConnReqPDU = unhexlify(b"030000130ee000000000000100080008000000")
            # wrappedSocket.send(x224ConnReqPDU)
            # msg = wrappedSocket.recv(1024)
            #wrappedSocket.do_handshake()
            acceptedVersion = wrappedSocket.version()
            wrappedSocket.close()
            print(acceptedVersion)
            return acceptedVersion == version
        except ssl.SSLError as e:
            print(e)
            return False
        except (ConnectionResetError, socket.gaierror, Exception) as e:
            print(e)
            return None
        finally:
            s.close()

class TLSLibrary(FeatureProbe):

    def test(self):        
        # results = prober.quick_probe(self.ip, self.rdp_port, 'auto', db)
        record_num = prober.probe(self.ip, self.rdp_port, 'auto', None) #prober.py中的probe函数
        #print(record_num)
        
        #results = prober.run_one_probe(self.ip, self.rdp_port, 'auto', NormalHandshake)
        # matches = probe_db.find_matches(results)
        # results = {key:value for (key,value) in matches}
        return {"TLS_recordNum":record_num}
