import json
import os

filepath = "..//5 - Cuckoo Reports"
filelist = os.listdir(filepath)
filelist.sort()
#print(filelist)

for i in range(len(filelist)):
    with open(filepath + "//" + filelist[i], "r") as f:
        file = json.loads(f.read())
    #print(file["info"]["id"], " => ", str(len(file["debug"]["log"])))

    for strings in file["debug"]["log"]:
        if "DECRYPT FILE" in strings:                   #[modules.auxiliary.human] INFO: Found button u'DECRYPT FILE', clicking it
            print(filelist[i])
            break



