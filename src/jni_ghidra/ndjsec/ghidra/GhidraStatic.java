package jni_ghidra.ndjsec.ghidra;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class GhidraStatic {
	private Program program;
	private DataTypeManager dtm;
	private Function jni_onload_function;
	
	public GhidraStatic(Program program, DataTypeManager dtm) {
		this.program = program;
		this.dtm = dtm;
		
	}
	
	public boolean testStaticLink() {
		return findJNIOnLoad();
	}
	
	private boolean findJNIOnLoad() {
        // Get an iterator over all functions in the program
        FunctionIterator functionIterator = program.getFunctionManager().getFunctions(true);
        String JNI_OnLoadSig = "JNI_OnLoad";
        
        // Iterate over the functions and check if any match the given name
        while (functionIterator.hasNext()) {
            Function function = functionIterator.next();
            if (function.getName().equals(JNI_OnLoadSig)) {
            	this.jni_onload_function = function;
                fixJNIOnLoadSig(function);
            	return true;
            }
        }

        return false; // Function not found
    }
	
	private void fixJNIOnLoadSig(Function jni_onload) {
		Parameter[] params = new Parameter[2];
		Parameter returnType;
		DataType vmType;
		DataType reservedType;
		try {
			returnType = new ReturnParameterImpl(dtm.getDataType("/jni_all.h/jint"), this.program);
			vmType = dtm.getDataType("/jni_all.h/JavaVM *");
			reservedType = dtm.getDataType("/void *");

			params[0] = new ParameterImpl("vm", vmType, this.program, SourceType.USER_DEFINED);
			params[1] = new ParameterImpl("reserved", reservedType, this.program, SourceType.USER_DEFINED);
			
			jni_onload.updateFunction(null, returnType, Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED, params);
		} catch (InvalidInputException e) {
			e.printStackTrace();
		} catch (DuplicateNameException e) {
			e.printStackTrace();
		}

	}
	
	public void fixJNIEnvPointer(ClangToken env_token) {
		Variable[] local_vars = this.jni_onload_function.getLocalVariables();
		Variable env_var = null;
		DataType envType;
		for (Variable local_var: local_vars) {
			if (local_var.getName().equals(env_token.getText())) {
				env_var = local_var;
			}
		}
		
		try {
			envType = dtm.getDataType("/jni_all.h/JNIEnv *");
			env_var.setName("env", env_var.getSource());
			env_var.setDataType(envType, env_var.getSource());
		} catch (DuplicateNameException | InvalidInputException e) {
			e.printStackTrace();
		}
	}
	
	public void fixFunctionTable() {
		Parameter vmParam = this.jni_onload_function.getParameters()[0];
		
	}
	
}
