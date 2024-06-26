package jni_ghidra.ndjsec.data;

import java.io.IOException;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.script.GhidraState;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.Application;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

public class JNIUtils {

	GhidraState state;
	FlatProgramAPI api;

	public JNIUtils(GhidraState state, FlatProgramAPI api) {
		this.state = state;
		this.api = api;
	}

	public DataTypeManager getDataTypeManageFromArchiveFile() throws IOException, DuplicateIdException {
		DataTypeManagerService service = this.state.getTool().getService(DataTypeManagerService.class);

		// Look for an already open "jni_all" archive.
		DataTypeManager[] managers = service.getDataTypeManagers();
		for (DataTypeManager m : managers) {
			if (m.getName().equals("jni_all")) {
				return m;
			}
		}

		// If an existing archive isn't found, open it from the file.
		ResourceFile jniArchiveFile = Application.getModuleDataFile("JNIAnalyzer", "jni_all.gdt");
		Archive jniArchive = service.openArchive(jniArchiveFile.getFile(true), false);
		return jniArchive.getDataTypeManager();
	}

	public void applyJNINativeMethodType(Address methods, long nMethods) throws Exception {
		DataTypeManager manager = this.getDataTypeManageFromArchiveFile();
		DataType jniNativeMethodType = manager.getDataType("/jni_all.h/JNINativeMethod");

		long offset = (jniNativeMethodType.getLength() * nMethods)
				- this.api.getCurrentProgram().getDefaultPointerSize();
		this.api.clearListing(methods, methods.add(offset));

		this.api.createData(methods,
				new ArrayDataType(jniNativeMethodType, (int) nMethods, jniNativeMethodType.getLength()));
	}

}
