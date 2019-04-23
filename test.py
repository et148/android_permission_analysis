#!/usr/bin/python
import os
import sys
import time

print "hello"
androguard_module_path = os.path.join(os.path.dirname(os.path.abspath("test.py")))
if not androguard_module_path in sys.path:
	sys.path.append(androguard_module_path)

from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis

def get_androguard_obj(apkfile):
    a=apk.APK(apkfile,False,"r",None,2)
    d=dvm.DalvikVMFormat(a.get_dex())
    x=analysis.VMAnalysis(d)
    return (a,d,x)

def get_file_dir(file_dir):
	apk_dirs=[]
	for root,dirs,files in os.walk(file_dir):
		apk_dirs.append(dirs)
	return apk_dirs

def get_file(file_dir):
	apk_files=[]
	for root,dirs,files in os.walk(file_dir):
		apk_files.append(files)
	return apk_files

sp="apk/1.apk"

if __name__=='__main__':    
    root_file="malware_family"
    apk_dirs=get_file_dir(root_file)
    fo=open('time.txt','a+')
    print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))
    fo.write(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))
    for apk_dir in apk_dirs[0]:
	apk_files=get_file(root_file+"/"+apk_dir)
	os.makedirs(os.path.dirname(os.path.abspath("test.py"))+"/androdd/"+apk_dir)
	for apk in apk_files[0]:
	    n=apk.find(".apk")
	    apk_name=apk[0:n]    
	    os.system("androdd.py -i "+root_file+"/"+apk_dir+"/"+apk+" -o androdd/"+apk_dir+"/"+apk_name+" -f png")
    fo.write(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))
    print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))
