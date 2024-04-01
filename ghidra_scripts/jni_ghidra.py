#TODO write a description for this script

#@Nicolas Janis 
#@category JNI_Analysis
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Program
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.util import ProgramLocation
from ghidra.util import Msg
from jni_ghidra.ndjsec.data import JNIUtils
from jni_ghidra.ndjsec.jadx_decomp import JadxDecomp
from jni_ghidra.ndjsec.ghidra import GhidraStatic
import ghidra

import time

jniUtils = JNIUtils(state, FlatProgramAPI(currentProgram))
print("[ + ] Importing APK")
manager = jniUtils.getDataTypeManageFromArchiveFile()

apk_file = askFile("Select APK File", "Open")
out_file = askString("Native Method Log File", "Please Enter Log File:")

if not out_file:
    Msg.showWarn(None, "Invalid Input", "No input provided. Exiting script.")
    exit()

native_class = askString("Native Method Class", "Please Enter Native Method Class to Parse:")

if not native_class:
    Msg.showWarn(None, "Invalid Input", "No input provided. Exiting script.")
    exit()

jadx_analyzer = JadxDecomp(apk_file, out_file, native_class)
method_list = jadx_analyzer.getMethodList()

program = currentProgram
ghidra_static = GhidraStatic(program, manager)
function = ghidra_static.testStaticLink()

if not function:
    print("ERROR: JNI_OnLoad Not Found... Exiting")
    exit()
    

print("[ * ] JNI_OnLoad Found")

current_location = currentLocation
if not current_location:
    Msg.showWarn(None, "Current Location Null", "Failed to obtain current location.")
    

JNIEnv_ptr = askChoices("Choose JNIEnv Pointer", "Please choose the 2nd variable of the GetEnv function pointer below. (Ex. (*(*vm)->GetEnv)(vm,&local_50,0x10006);, choose local_50)", ghidra_static.getLocalVariable())

ghidra_static.fixJNIEnvPointer(JNIEnv_ptr)
#ghidra_static.fixFunctionTable(current_location.getToken())

