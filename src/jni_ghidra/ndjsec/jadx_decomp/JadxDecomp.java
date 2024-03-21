package jni_ghidra.ndjsec.jadx_decomp;

import com.google.gson.Gson;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;
import jadx.core.dex.instructions.args.ArgType;
import jni_ghidra.ndjsec.data.NativeMethod;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

public class JadxDecomp {
	private ArrayList<NativeMethod> methodList;
	
	public JadxDecomp(File apk, String logFile, String className) {
        JadxArgs jadxArgs = new JadxArgs();
        jadxArgs.setDebugInfo(false);
        jadxArgs.getInputFiles().add(apk);

        try (JadxDecompiler jadx = new JadxDecompiler(jadxArgs)) {
            jadx.load();
            this.methodList = extractNativeMethods(jadx, className);

            Gson gson = new Gson();
            writeToJsonFile(logFile, methodList, gson);

        } catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	public ArrayList<NativeMethod> getMethodList() {
		return this.methodList;
	}

    private static ArrayList<NativeMethod> extractNativeMethods(JadxDecompiler jadx, String className) {
        ArrayList<NativeMethod> methodList = new ArrayList<>();

        for (JavaClass jcls : jadx.getClasses()) {
            if (jcls.toString().contains(className)) {
                System.out.format("[ * ] Class found -> %s\n", jcls.toString());
                System.out.println("[ * ] Enumerating Methods");

                for (JavaMethod method : jcls.getMethods()) {
                    if (method.getAccessFlags().isNative()) {
                        methodList.add(createNativeMethod(method));
                    }
                }
            }
        }
        System.out.format("[ * ] %d Native Methods Found\n", methodList.size());
        return methodList;
    }

    private static NativeMethod createNativeMethod(JavaMethod nativeMethod) {
        ArrayList<String> methodParams = new ArrayList<>();
        for (ArgType arg : nativeMethod.getArguments()) {
            methodParams.add(parseArgument(arg));
        }
        String retType = parseArgument(nativeMethod.getReturnType());
        return new NativeMethod(parseNativeMethodName(nativeMethod.getFullName()), methodParams, retType);
    }

    private static String parseNativeMethodName(String nativeMethodFullName) {
        return "Java_" + nativeMethodFullName.replace(".", "_");
    }

    private static String parseArgument(ArgType arg) {
        if (arg.isPrimitive()) {
            return convertPrimitive(arg);
        } else if (arg.isArray()) {
            return convertArray(arg);
        } else {
            return arg.toString().equals("java.lang.String") ? "jstring" : "jobject";
        }
    }

    private static String convertPrimitive(ArgType arg) {
        switch (arg.getPrimitiveType().getLongName()) {
            case "boolean":
                return "jboolean";
            case "byte":
                return "jbyte";
            case "char":
                return "jchar";
            case "short":
                return "jshort";
            case "int":
                return "jint";
            case "long":
                return "jlong";
            case "float":
                return "jfloat";
            case "double":
                return "jdouble";
            default:
                return "void";
        }
    }

    private static String convertArray(ArgType arg) {
        switch (arg.getArrayRootElement().getPrimitiveType().getLongName()) {
            case "boolean":
                return "jbooleanArray";
            case "byte":
                return "jbyteArray";
            case "char":
                return "jcharArray";
            case "short":
                return "jshortArray";
            case "int":
                return "jintArray";
            case "long":
                return "jlongArray";
            case "float":
                return "jfloatArray";
            case "double":
                return "jdoubleArray";
            default:
                return "jobjectArray";
        }
    }

    private static void writeToJsonFile(String fileName, ArrayList<NativeMethod> methodList, Gson gson) {
        try (FileWriter outFile = new FileWriter(fileName)) {
            outFile.append(gson.toJson(methodList));
            outFile.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
