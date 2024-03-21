//TODO write a description for this script

//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 


import java.io.File;
import java.io.StringWriter;
import java.util.ArrayList;

import org.python.util.PythonInterpreter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.ISF.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.address.*;

import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import jni_ghidra.ndjsec.data.JNIUtils;
import jni_ghidra.ndjsec.data.NativeMethod;
import jni_ghidra.ndjsec.jadx_decomp.JadxDecomp;
import jni_ghidra.ndjsec.ghidra.GhidraStatic;

public class JNI_Ghidra extends GhidraScript {

	DataTypeManager manager;
	JNIUtils jniUtils;
	Program program;
	ProgramLocation currentLocation;

	@Override
	protected void run() throws Exception {
		this.jniUtils = new JNIUtils(state, this);
		println("[ + ] Importing APK");
		this.manager = this.jniUtils.getDataTypeManageFromArchiveFile();
		
		File apkFile = this.askFile("Select APK File", "Open");
		String outFile = this.askString("Native Method Log File", "Please Enter Log File:");
		
		// Check if the user entered a valid input
        if (outFile == null || outFile.isEmpty()) {
            Msg.showWarn(this, null, "Invalid Input", "No input provided. Exiting script.");
            return;
        }

		String nativeClass = this.askString("Native Method Class", "Please Enter Native Method Class to Parse:");
		
		// Check if the user entered a valid input
        if (nativeClass == null || nativeClass.isEmpty()) {
            Msg.showWarn(this, null, "Invalid Input", "No input provided. Exiting script.");
            return;
        }
        
        JadxDecomp jadxAnalyzer = new JadxDecomp(apkFile, outFile, nativeClass);
        ArrayList<NativeMethod> methodList = jadxAnalyzer.getMethodList();
        
        this.program = currentProgram;
        GhidraStatic ghidraStatic = new GhidraStatic(program, this.manager);
        boolean function = ghidraStatic.testStaticLink();
        

        if (!function) {
        	println("ERROR: JNI_OnLoad Not Found... Exiting");
        	return;
        }
		println("[ * ] JNI_OnLoad Found");
		
		try (PythonInterpreter pyInterp = new PythonInterpreter()) {
			StringWriter output = new StringWriter();
			pyInterp.setOut(output);
			
			pyInterp.exec("print(currentLocation.getToken())");
			output.toString().trim();
		} 
        ghidraStatic.fixFunctionTable(currentLocation);
		
	}
	

}
