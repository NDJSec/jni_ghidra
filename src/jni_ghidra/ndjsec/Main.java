package jni_ghidra.ndjsec;

import java.io.File;

import jni_ghidra.ndjsec.jadx_decomp.JadxDecomp;

public class Main {
	
	public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: analyze.apk outfile.json AnalyzeClass");
            return;
        }
        
        new JadxDecomp(new File(args[0]), args[1], args[2]);

    }


}
