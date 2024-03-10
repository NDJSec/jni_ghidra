package jni_ghidra.ndjsec.data;

import java.util.ArrayList;

public class NativeMethod {
	private String methodName;
	private ArrayList<String> methodParams;
	private String returnType;
	
	public NativeMethod(String methodName, ArrayList<String> methodParams, String returnType) {
		this.methodName = methodName;
		this.methodParams = methodParams;
		this.returnType = returnType;
	}

}
