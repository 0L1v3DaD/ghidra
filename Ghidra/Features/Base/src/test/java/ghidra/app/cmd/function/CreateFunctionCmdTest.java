/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.cmd.function;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;

/**
 * Test for the {@link CreateMultipleFunctionsCmd}.
 */
public class CreateFunctionCmdTest extends AbstractGenericTest {

	private Program program;
	private ProgramBuilder builder;

	@Before
	public void setUp() throws Exception {

		builder = new ProgramBuilder("notepad.exe", ProgramBuilder._X86);
		builder.createMemory("test", "0x1000", 1024);
		program = builder.getProgram();

		//
		// Create some functions (byte patterns, not Ghidra objects) with varying separation
		//
		// single function
		builder.setBytes("0x1000", "55 8b ec 51 67 c9 c3");
		builder.disassemble("0x1000", 7);

		// Thunk to above single function
		builder.setBytes("0x1007", "e9 25 f7 ff fe");
		builder.disassemble("0x1007", 1);
	}

	@Test
	public void testCreateFunction() {

		int transactionID = program.startTransaction("Perform the TEST");

		CreateFunctionCmd createCmd = new CreateFunctionCmd(addr(0x1000));
		createCmd.applyTo(program);

		createCmd = new CreateFunctionCmd(addr(0x1007));
		createCmd.applyTo(program);

		program.endTransaction(transactionID, true);

		Function func1000 = func(addr(0x1000));
		assertNotNull("Created normal function", func1000);

		assertEquals("Normal function body size", 7, func1000.getBody().getNumAddresses());

		Function func1007 = func(addr(0x1007));
		assertNotNull("Created thunk function", func1007);

		assertEquals("Thunk body length", true, func1007.isThunk());
	}

	@Test
	public void testReCreateFunction() {
		int transactionID = program.startTransaction("Perform the TEST");

		CreateFunctionCmd createCmd = new CreateFunctionCmd(addr(0x1000));
		createCmd.applyTo(program);

		createCmd =
			new CreateFunctionCmd("bob", addr(0x1000), null, SourceType.USER_DEFINED, true, true);
		boolean result = createCmd.applyTo(program);

		program.endTransaction(transactionID, true);

		assertTrue("Recreate with no error", result);
	}

	@Test
	public void testReCreateFunctionWithBody() {
		int transactionID = program.startTransaction("Perform the TEST");

		CreateFunctionCmd createCmd = new CreateFunctionCmd(addr(0x1000));
		createCmd.applyTo(program);

		createCmd = new CreateFunctionCmd("bob", addr(0x1000),
			new AddressSet(addr(0x1000), addr(0x1003)), SourceType.USER_DEFINED, true, true);
		boolean result = createCmd.applyTo(program);

		assertTrue("Recreate set body", result);

		Function func1000 = func(addr(0x1000));

		assertEquals("Created function body length", 4, func1000.getBody().getNumAddresses());

		createCmd =
			new CreateFunctionCmd(null, addr(0x1000), null, SourceType.USER_DEFINED, true, true);
		result = createCmd.applyTo(program);

		assertTrue("Recreate figuring out function body", result);

		func1000 = func(addr(0x1000));

		assertEquals("Recreated function body size", 7, func1000.getBody().getNumAddresses());

		program.endTransaction(transactionID, true);
	}

	@Test
	public void testCreateFunctionFindEntryBodyError() {
		int transactionID = program.startTransaction("Perform the TEST");

		CreateFunctionCmd createCmd = new CreateFunctionCmd("bob", addr(0x1003),
			new AddressSet(addr(0x1003), addr(0x1007)), SourceType.USER_DEFINED, true, true);
		boolean result = createCmd.applyTo(program);

		assertFalse("Create Function", result);

		Function func1000 = func(addr(0x1000));
		Function func1003 = func(addr(0x1003));

		assertNull("No function at 1000", func1000);
		assertNull("No function at 10003", func1003);

		program.endTransaction(transactionID, true);
	}

	@Test
	public void testCreateFunctionEntryBodyError() {
		int transactionID = program.startTransaction("Perform the TEST");

		CreateFunctionCmd createCmd = new CreateFunctionCmd("bob", addr(0x1000),
			new AddressSet(addr(0x1003), addr(0x1007)), SourceType.USER_DEFINED, false, true);
		boolean result = createCmd.applyTo(program);

		assertFalse("Create Function", result);

		Function func1000 = func(addr(0x1000));
		Function func1003 = func(addr(0x1003));

		assertNull("No function at 1000", func1000);
		assertNull("No function at 10003", func1003);

		program.endTransaction(transactionID, true);
	}

	@Test
	public void testFunctionFindEntry() {
		int transactionID = program.startTransaction("Perform the TEST");

		CreateFunctionCmd createCmd = new CreateFunctionCmd(addr(0x1000));
		createCmd.applyTo(program);

		createCmd =
			new CreateFunctionCmd("bob", addr(0x1003), null, SourceType.USER_DEFINED, true, true);
		boolean result = createCmd.applyTo(program);

		assertTrue("Create Function", result);

		Function func1003 = func(addr(0x1003));
		assertNull("Function should not be at 0x10003", func1003);

		Function func1000 = func(addr(0x1000));
		assertNotNull("Function entry found and created at 0x10000", func1000);
		assertEquals("Created function body length", 7, func1000.getBody().getNumAddresses());

		program.endTransaction(transactionID, true);
	}

	@Test
	public void testCreateOverlappingTruncated() {
		int transactionID = program.startTransaction("Perform the TEST");

		CreateFunctionCmd createCmd =
			new CreateFunctionCmd("bob", addr(0x1003), null, SourceType.USER_DEFINED, false, true);
		boolean result = createCmd.applyTo(program);

		assertTrue("Create Function", result);

		Function func1003 = func(addr(0x1003));
		assertEquals("Function body length", 4, func1003.getBody().getNumAddresses());

		createCmd =
			new CreateFunctionCmd(null, addr(0x1000), null, SourceType.USER_DEFINED, true, true);
		result = createCmd.applyTo(program);

		Function func1000 = createCmd.getFunction(); // test result function available from cmd
		assertEquals("Create truncated function", func1000.getEntryPoint(), addr(0x1000));
		assertEquals("Function body length", 3, func1000.getBody().getNumAddresses());

		func1003 = func(addr(0x1003));
		assertEquals("Created function body length", 4, func1003.getBody().getNumAddresses());

		program.endTransaction(transactionID, true);
	}

	@Test
	public void testCreateOverlapping() {
		int transactionID = program.startTransaction("Perform the TEST");

		CreateFunctionCmd createCmd = new CreateFunctionCmd(addr(0x1000));
		createCmd.applyTo(program);

		createCmd =
			new CreateFunctionCmd("bob", addr(0x1003), null, SourceType.USER_DEFINED, false, true);
		boolean result = createCmd.applyTo(program);

		assertTrue("Create Function", result);

		Function func1003 = func(addr(0x1003));
		assertEquals("Created function body length", 4, func1003.getBody().getNumAddresses());

		Function func1000 = func(addr(0x1000));
		assertEquals("Function start", func1000.getEntryPoint(), addr(0x1000));
		assertEquals("Created function body length", 3, func1000.getBody().getNumAddresses());

		func1003 = func(addr(0x1003));
		assertEquals("Created function body length", 4, func1003.getBody().getNumAddresses());

		program.endTransaction(transactionID, true);
	}

	@Test
	public void testCreateThunkFunction() {

		int transactionID = program.startTransaction("Perform the TEST");

		CreateFunctionCmd createCmd = new CreateFunctionCmd(addr(0x1000));
		createCmd.applyTo(program);

		createCmd = new CreateFunctionCmd("thunky", addr(0x1007),
			new AddressSet(addr(0x1007), addr(0x1008)), SourceType.USER_DEFINED);
		createCmd.applyTo(program);

		Function func1007 = func(addr(0x1007));
		assertNotNull("Thunk function created", func1007);

		assertEquals("Function is a thunk", true, func1007.isThunk());

		assertEquals("Thunk function body size", 2, func1007.getBody().getNumAddresses());

		createCmd =
			new CreateFunctionCmd(null, addr(0x1007), null, SourceType.USER_DEFINED, true, true);
		boolean result = createCmd.applyTo(program);

		assertTrue("Recreate Thunk figure out body", result);

		func1007 = func(addr(0x1007));
		assertNotNull("Recreated thunk function", func1007);

		assertEquals("Recreated thunk function body length", 5,
			func1007.getBody().getNumAddresses());

		program.endTransaction(transactionID, true);
	}

	@Test
	public void testApplyFunctionDataTypesOverloadConflict() throws Exception {
		int transactionID = program.startTransaction("testOverloadConflict");
		try {
			Namespace ns1 = program.getSymbolTable()
					.createNameSpace(null, "NS1", SourceType.USER_DEFINED);
			Namespace ns2 = program.getSymbolTable()
					.createNameSpace(null, "NS2", SourceType.USER_DEFINED);

			CreateFunctionCmd cmd1 = new CreateFunctionCmd("move", addr(0x1000),
				new AddressSet(addr(0x1000), addr(0x1005)), SourceType.USER_DEFINED);
			cmd1.applyTo(program);
			Function f1 = func(addr(0x1000));
			f1.setParentNamespace(ns1);

			CreateFunctionCmd cmd2 = new CreateFunctionCmd("move", addr(0x1010),
				new AddressSet(addr(0x1010), addr(0x1015)), SourceType.USER_DEFINED);
			cmd2.applyTo(program);
			Function f2 = func(addr(0x1010));
			f2.setParentNamespace(ns2);

			DataTypeManager dtm = program.getDataTypeManager();
			FunctionDefinitionDataType fdef1 =
				new FunctionDefinitionDataType(new CategoryPath("/DWARF"), "move", dtm);
			fdef1.setArguments(new ParameterDefinition[] {
				new ParameterDefinitionImpl("a", IntegerDataType.dataType, null) });
			FunctionDefinitionDataType fdef2 =
				new FunctionDefinitionDataType(new CategoryPath("/DWARF"), "move", dtm);
			fdef2.setArguments(new ParameterDefinition[] {
				new ParameterDefinitionImpl("a", IntegerDataType.dataType, null),
				new ParameterDefinitionImpl("b", IntegerDataType.dataType, null) });

			DataType resolved1 = dtm.addDataType(fdef1, DataTypeConflictHandler.DEFAULT_HANDLER);
			DataType resolved2 = dtm.addDataType(fdef2, DataTypeConflictHandler.DEFAULT_HANDLER);
			assertEquals("move", resolved1.getName());
			assertEquals("move.conflict", resolved2.getName());

			ApplyFunctionDataTypesCmd applyCmd = new ApplyFunctionDataTypesCmd(
				List.of(dtm), new AddressSet(addr(0x1000), addr(0x1020)),
				SourceType.USER_DEFINED, true, false);
			applyCmd.applyTo(program);

			assertEquals(0, f1.getParameterCount());
			assertEquals(0, f2.getParameterCount());
		}
		finally {
			program.endTransaction(transactionID, false);
		}
	}

	private Address addr(long l) {
		AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		return addressSpace.getAddress(l);
	}

	private Function func(Address a) {
		FunctionManager fm = program.getFunctionManager();
		return fm.getFunctionAt(a);
	}

}
