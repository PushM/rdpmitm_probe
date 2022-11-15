import argparse, sys, os, time, concurrent.futures, csv, io, json, socket, random
import pickle
#from sklearn.ensemble import RandomForestClassifier
from pandas import DataFrame, read_csv, concat
import traceback
#from probes.RTTfeatureProbes import x224ConnReqTiming_HYBRID, x224ConnReqTiming_HYBRID_EX, x224ConnReqTiming_SSL

sys.path.insert(1, os.path.join(os.path.dirname(__file__), 'probes'))
import warnings
warnings.filterwarnings("ignore", category=FutureWarning, module="sklearn", lineno=484)
from RTTfeatureProbes import *
from TLSfeatureProbes import *

class Detector:

    RTTfeatureProbes = [
        #tcpSYNTiming,
        #x224ConnReqTiming_RDP,
        #x224ConnReqTiming_SSL,
        #x224ConnReqTiming_HYBRID,
        #x224ConnReqTiming_HYBRID_EX,
        #tlsClientHelloTiming,
        #tcpSYNTiming,
        #tlsHandshakeTiming
        RdpConnectTiming_SSL,
        RdpConnectTiming_Cred
    ]

    TLSfeatureProbes = [
        TLSLibrary,
        #TLSVersions,
    ]

    def __init__(self, rdp_port=3389, numIterations=3,
                modelFile="./rdpmitm_rfc.pickle", rawData=True,
                outputFile=None, outputFormat="csv",source_ip = None):

        self.rdp_port = rdp_port
        self.numIterations = numIterations
        self.modelFile = modelFile
        self.outputFile = outputFile
        self.outputFormat = outputFormat
        self.rawData = rawData
        self.source_ip = source_ip
#        self.model = pickle.load(open(self.modelFile, 'rb'))


    def crawl(self, ips):
        crawlResults = {}
        result = {}

        for ip in ips :
            if ip == source_ip:
                continue
            #print("probing: {}".format(ip))
            try:
                # 检测目标ip
                result = self.testSite(ip)
            except Exception as e:
                print("{} probe error".format(ip))
                print(e)
                traceback.print_exc()

           # print(f"{result['ip']}: {result['data']}")
            crawlResults[result['ip']] = {'data' : result['data']}
            #if(self.outputFile == None and not self.rawData):
            print(f"{result['ip']}: {result['data']}")

        output = self.writeResultsToFile(crawlResults)
        if(output and self.rawData):
            print(output)#所有ip探测完后，最后做一个输出


    def testSite(self, ip):
        result = {'ip' : ip}
        #提取目标RDP服务端的RTT和TLS特征
        result['data'] = self.probeSite(ip)
        #特征输入分类器得到分类结果
        # result['classification'] = self.classifySite(result['data'])
        return result

    def classifySite(self, recordings):
        classification = None

        recordingsDataFrame = DataFrame([recordings])
        #columnsToDrop = [column for column in recordingsDataFrame if column not in self.model.feature_names]
        #recordingsDataFrame = recordingsDataFrame.drop(columnsToDrop, axis=1)
        if(recordingsDataFrame.isna().sum().sum() > 0):
            return classification

        recordingsDataFrame = recordingsDataFrame.reindex(sorted(recordingsDataFrame.columns), axis=1)

        try:
            classification = self.model.predict(recordingsDataFrame)[0]
        except Exception as e:
            print(e)
        if classification == 0:
            result = "no rdp-mitm"
        else:
            result = "yes rdp-mitm!"
        return result

    def probeSite(self, ip):
        probeResults = {}
        #TLS特征提取
        for probe in Detector.TLSfeatureProbes:
            TLSlibResults = probe(ip, self.rdp_port).test()

        #RTT特征提取
        for probe in Detector.RTTfeatureProbes:
            currentProbeResults = probe(ip, self.rdp_port).test()
            probeResults[probe.__name__] = currentProbeResults
        #计算RTT之比
        #probeResults['x224ReqTCPSynRatio_RDP'] = probeResults['x224ConnReqTiming_RDP'] / probeResults['tcpSYNTiming']
        #probeResults['x224ReqTCPSynRatio_SSL'] = probeResults['x224ConnReqTiming_SSL'] / probeResults['tcpSYNTiming']
        #probeResults['x224ReqTCPSynRatio_HYBRID'] = probeResults['x224ConnReqTiming_HYBRID'] / probeResults['tcpSYNTiming']
        #probeResults['x224ReqTCPSynRatio_HYBRID_EX'] = probeResults['x224ConnReqTiming_HYBRID_EX'] / probeResults['tcpSYNTiming']


        probeResults.update(TLSlibResults)
        return probeResults

    def writeResultsToFile(self, siteResults):
        if(self.outputFile != None):
            f = open(self.outputFile, 'a')
        else:
            f = io.StringIO()

        if(self.outputFormat == 'csv'):
            resultsToFile = []

            for key,value in siteResults.items():
                currentResults = {}
                if(self.rawData):
                    currentResults.update(value['data'])#value['data'] 是一个字典 ，字典update字典
                #currentResults['classification'] = value['classification']
                currentResults['ip'] = key

                resultsToFile.append(currentResults)

            writer = csv.DictWriter(f, fieldnames=resultsToFile[0].keys())
            #writer.writeheader()
            for row in resultsToFile:
                writer.writerow(row)
        elif(self.outputFormat == 'json'):
            for key in siteResults.keys():
                if(not self.rawData):#如果不保存rawdata，删除字典里的data键值
                    del siteResults[key]['data']

            json.dump(siteResults, f)

        if(self.outputFile == None):#如果指定了ourputfile->output=None，因为已经写入文件，就不再打印；如果没指定，就打印出来
            output = f.getvalue()
        else:
            output = None
        f.close()
        return output 



def process_args():
    ######################################
    programDescription = "RDP_MITM_PROBER：Detect RDP MITM Attack"

    parser = argparse.ArgumentParser(description=programDescription, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("ip",
                        nargs="?",
                        help="ip to classify as a RDP MITM . Not required if input file specified with -r argument.")
    parser.add_argument("-R", "--raw-data",
                        action="store_true",
                        default=True,
                        help="Record and output raw classification data about site(s).")
    parser.add_argument("-w", "--output-file",
                        type=str,
                        help="File to write probe outputs to. This argument is required if in record mode.",
                        default=None)
    parser.add_argument("-r", "--input-file",
                        type=str,
                        help="File containing  IP addresses . Each line should contain only the IP.")
    parser.add_argument("--rdp-port", type=int, default=3389,
                        help="Set the port to scan rdp servers. Defaults to 3389.")
    parser.add_argument("--output-format", help="Format to produce output if in \"Record\" mode. Options include: csv, json. Default format is csv.", default="csv")

    args = vars(parser.parse_args())

    if(args["ip"] == None and args["input_file"] == None):
        parser.print_help(sys.stderr)
        sys.exit(1)
    # elif(os.geteuid() != 0):
    #     print("Root permissions not granted. Run program as root to enable TCP SYN/ACK timing probe.")
    #     sys.exit(1)
    # 不用raw socket了，有点bug
    return args

def test_source_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        source_ip, source_port = s.getsockname()
        #self.dest_port = self.https_port
        return source_ip
    except Exception as e:
        return -1
    finally:
        s.close()

if(__name__ == '__main__'):
    args = process_args()

    if(args['input_file'] != None):
        with open(args['input_file'], "r") as f:
            ips = [ip.strip() for ip in f.readlines()]
    else:
        ips = [args["ip"]]

    source_ip = test_source_ip()
    #print(source_ip)
    detector = Detector( rawData=args['raw_data'],
                        outputFile=args['output_file'],
                        outputFormat=args['output_format'],
                        source_ip = source_ip)
    #打乱ips，防止rdp server高并发
    index = [i for i in range(len(ips))] 
    random.shuffle(index)
    #print(index)
    random_ips =[]
    for i in range(len(ips)):
        random_ips.append(ips[index[i]])
    
    detector.crawl(random_ips)
