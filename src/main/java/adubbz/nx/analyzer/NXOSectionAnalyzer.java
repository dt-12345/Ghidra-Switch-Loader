/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package adubbz.nx.analyzer;

import static ghidra.app.util.bin.StructConverter.*;

import adubbz.nx.loader.SwitchLoader;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.format.elf.info.NoteGnuBuildId;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.*;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.task.TaskMonitor;
import java.util.*;

public class NXOSectionAnalyzer extends AbstractAnalyzer
{
    public static final String NAME = "(Switch) NXO Section Analyzer";
    public static final String DESCRIPTION = "Identifies and labels NXO sections missed during the initial import process";
    
    protected static final String OPTION_NAME_APPLY_DATATYPES = "Apply Known Datatypes";
    protected static final String OPTION_DESCRIPTION_APPLY_DATATYPES = "Add and apply datatypes for known structures associated with sections";
    
    private static final boolean OPTION_DEFAULT_APPLY_DATATYPES = true;
    private boolean applyDataTypes = OPTION_DEFAULT_APPLY_DATATYPES;
    
    private static final CategoryPath ROCRT_PATH = new CategoryPath("/nn/rocrt");
    private static final CategoryPath DEFAULT_PATH = new CategoryPath("/nn/rocrt");

    private static final byte[] GNU_BUILD_ID_PATTERN1 = HexFormat.of().parseHex("040000001400000003000000474E5500"); // used in newer binaries
    private static final byte[] GNU_BUILD_ID_PATTERN2 = HexFormat.of().parseHex("040000001000000003000000474E5500"); // used in older binaries

    private static final String REFER_SYMBOL_MANGLED_NAME = "_ZN2nn4util11ReferSymbolEPKv";
    private static final String REFER_SYMBOL_NAME = "nn::util::ReferSymbol";

    public NXOSectionAnalyzer()
    {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        // idk when exactly to put this, but preferably before the demangler and that has 3x before()
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before().before().before().before());
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean getDefaultEnablement(Program program) 
    {
        return true;
    }

    @Override
    public boolean canAnalyze(Program program) 
    {
        return program.getExecutableFormat().equals(SwitchLoader.SWITCH_NAME);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException
    {
        monitor.setIndeterminate(true);
        
        monitor.setMessage("Analyzing .note.gnu.build-id");
        MemoryBlock buildIdSection = program.getMemory().getBlock(".note.gnu.build-id");
        if (buildIdSection != null)
        {
            NoteGnuBuildId buildId = NoteGnuBuildId.fromProgram(program);
            if (buildId != null)
                buildId.markupProgram(program, buildIdSection.getStart());
        }
        else
        {
            searchAndLabelGnuBuildId(program, monitor, log);
        }

        try
        {
            analyzeRocrtSections(program, monitor, log);
        }
        catch (InvalidInputException | CodeUnitInsertionException | MemoryAccessException e)
        {
            log.appendMsg("Error analyzing __rocrt sections");
            log.appendException(e);
        }

        if (applyDataTypes)
        {
            try
            {
                analyzeNxDebugLink(program, monitor);
            }
            catch (CodeUnitInsertionException | MemoryAccessException e)
            {
                log.appendMsg("Error analyzing __rocrt sections");
                log.appendException(e);
            }
        }

        analyzeApiInfo(program, monitor, log);

        // other sections to identify (most of these would be easier to do post-load rather than right now):
        // - .atexit => _fini -> CxaFinalizeImpl or something
        // - .tdata => does this exist?
        // - .tbss => parse __nnmusl_init_dso() arguments
        // - .rocrt.align.bssend => only on newer versions, presumably padding .bss to 0x1000? kinda unnecessary though

        return true;
    }

    private void searchAndLabelGnuBuildId(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException
    {
        monitor.checkCancelled();
        
        long size = 0x24;
        Address addr = program.getMemory().findBytes(program.getImageBase(), GNU_BUILD_ID_PATTERN1, null, true, monitor);
        if (addr == null)
        {
            size = 0x20;
            addr = program.getMemory().findBytes(program.getImageBase(), GNU_BUILD_ID_PATTERN2, null, true, monitor);
        }

        if (addr == null)
            return;

        MemoryBlock containingBlock = program.getMemory().getBlock(addr);
        try
        {
            if (addr.equals(containingBlock.getStart()))
            {
                if (containingBlock.getSize() == size)
                {
                    containingBlock.setName(".note.gnu.build-id");
                    NoteGnuBuildId buildId = NoteGnuBuildId.fromProgram(program);
                    if (buildId != null)
                        buildId.markupProgram(program, containingBlock.getStart());
                }
                else
                {
                    program.getMemory().split(containingBlock, addr.add(size));
                    MemoryBlock gnuBuildIdSection = program.getMemory().getBlock(addr);
                    gnuBuildIdSection.setName(".note.gnu.build-id");
                    NoteGnuBuildId buildId = NoteGnuBuildId.fromProgram(program);
                    if (buildId != null)
                        buildId.markupProgram(program, gnuBuildIdSection.getStart());
                }
            }
            else
            {
                program.getMemory().split(containingBlock, addr);
                MemoryBlock gnuBuildIdSection = program.getMemory().getBlock(addr);
                gnuBuildIdSection.setName(".note.gnu.build-id");
                NoteGnuBuildId buildId = NoteGnuBuildId.fromProgram(program);
                if (buildId != null)
                    buildId.markupProgram(program, gnuBuildIdSection.getStart());
            }
        }
        catch (Exception e)
        {
            log.appendMsg("Failed to create GNU Build Id section");
            log.appendException(e);
        }
    }

    private void analyzeRocrtSections(Program program, TaskMonitor monitor, MessageLog log)
        throws CancelledException, InvalidInputException, CodeUnitInsertionException, MemoryAccessException
    {
        monitor.checkCancelled();

        DataTypeManager dtm = program.getDataTypeManager();
        SymbolTable symTable = program.getSymbolTable();
        Memory memory = program.getMemory();

        monitor.setMessage("Analyzing .rocrt sections");
        MemoryBlock rocrtInit = memory.getBlock(".rocrt.init");
        if (rocrtInit != null)
        {
            symTable.createLabel(rocrtInit.getStart(), "__rocrt_init", null, SourceType.ANALYSIS);
            int entryInst = memory.getInt(rocrtInit.getStart());
            boolean isOldVersion = entryInst == 0xea000000 || entryInst == 0 || entryInst == 0x14000002;

            MemoryBlock rocrtInitRo = isOldVersion ? null : memory.getBlock(".rocrt.initro");
            if (rocrtInitRo != null)
                symTable.createLabel(rocrtInitRo.getStart(), "__rocrt_initro", null, SourceType.ANALYSIS);

            MemoryBlock rocrt = memory.getBlock(".rocrt.info");
            if (rocrt != null)
            {
                symTable.createLabel(rocrt.getStart(), "__rocrt", null, SourceType.ANALYSIS);
                if (!isOldVersion)
                    symTable.createLabel(rocrt.getStart().add(0x34), "__rocrt_ver", null, SourceType.ANALYSIS);

                int rocrtModuleOffset = memory.getInt(rocrt.getStart().add(0x18));
                symTable.createLabel(rocrt.getStart().add(rocrtModuleOffset), "_ZN2nn5rocrt10g_RoModuleE", null, SourceType.ANALYSIS);
            }

            if (applyDataTypes)
            {
                StructureDataType rocrtInitDt = new StructureDataType(ROCRT_PATH, "__rocrt_init", 0, dtm);
                rocrtInitDt.add(DWORD, "entryInstruction", "Entry Instruction or Version");
                rocrtInitDt.add(DWORD, "headerOffset", "Offset to __rocrt relative to the start of this structure");
                if (!isOldVersion)
                    rocrtInitDt.add(DWORD, "versionOffset", "Offset to __rocrt_ver relative to the start of this structure");
                applyDataType(program, monitor, log, rocrtInitDt, rocrtInit.getStart());
                if (rocrtInitRo != null)
                    applyDataType(program, monitor, log, rocrtInitDt, rocrtInitRo.getStart());

                StructureDataType rocrtHeader = new StructureDataType(ROCRT_PATH, "ModuleHeader", 0, dtm);
                rocrtHeader.add(DWORD, "signature", "ROCRT module header signature (MOD0)");
                rocrtHeader.add(DWORD, "dynamicOffset", "Offset to .dynamic relative to start of this structure");
                rocrtHeader.add(DWORD, "bssStartOffset", "Offset to start of .bss relative to start of this structure");
                rocrtHeader.add(DWORD, "bssEndOffset", "Offset to end of .bss relative to start of this structure");
                rocrtHeader.add(DWORD, "ehFrameHdrStartOffset", "Offset to start of .eh_frame_hdr relative to start of this structure");
                rocrtHeader.add(DWORD, "ehFrameHdrEndOffset", "Offset to end of .eh_frame_hdr relative to start of this structure");
                rocrtHeader.add(DWORD, "runtimeModuleObjectOffset", "Offset to nn::rocrt::g_RoModule relative to start of this structure");
                if (!isOldVersion)
                {
                    rocrtHeader.add(DWORD, "relroStartOffset", "Offset to start of region protected by RELRO relative to start of this structure");
                    rocrtHeader.add(DWORD, "fullRelroEndOffset", "Offset to end of region protected by RELRO relative to start of this structure");
                    rocrtHeader.add(DWORD, "nxDebugLinkStartOffset", "Offset to start of .nx_debuglink relative to start of this structure");
                    rocrtHeader.add(DWORD, "nxDebugLinkEndOffset", "Offset to end of .nx_debuglink relative to start of this structure");
                    rocrtHeader.add(DWORD, "gnuBuildIdStartOffset", "Offset to start of .note.gnu.build-id relative to start of this structure");
                    rocrtHeader.add(DWORD, "gnuBuildIdEndOffset", "Offset to end of .note.gnu.build-id relative to start of this structure");
                }
                if (rocrt != null)
                {
                    applyDataType(program, monitor, log, rocrtHeader, rocrt.getStart());
                    if (!isOldVersion)
                    {
                        StructureDataType rocrtVer = new StructureDataType(ROCRT_PATH, "ModuleVersion", 0, dtm);
                        rocrtVer.add(DWORD, "major", "Major version");
                        rocrtVer.add(DWORD, "minor", "Minor version");
                        rocrtVer.add(DWORD, "patch", "Patch version");
                        DataUtilities.createData(program, rocrt.getStart().add(0x34), rocrtVer, -1, false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                    }
                }
            }
        }
    }

    private void applyDataType(Program program, TaskMonitor monitor, MessageLog log, StructureDataType dt, Address start) throws CancelledException, CodeUnitInsertionException
    {
        Data data = DataUtilities.createData(program, start, dt, -1, false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        if (data == null)
            return;

        Memory memory = program.getMemory();
        ReferenceManager refMgr = program.getReferenceManager();
        for (DataTypeComponent component : dt.getComponents())
        {
            monitor.checkCancelled();
            if (component == null)
                continue;

            String fieldName = component.getFieldName();
            if (fieldName == null || !fieldName.endsWith("_offset"))
                continue;

            try
            {
                refMgr.addMemoryReference(start.add(component.getOffset()), start.add(memory.getInt(start.add(component.getOffset()))), RefType.DATA, SourceType.ANALYSIS, 0);
            }
            catch (IllegalArgumentException | MemoryAccessException e)
            {
                log.appendMsg("Failed to create memory reference");
                log.appendException(e);
            }
        }
    }

    private void analyzeNxDebugLink(Program program, TaskMonitor monitor) throws CancelledException, CodeUnitInsertionException, MemoryAccessException
    {
        monitor.checkCancelled();

        monitor.setMessage("Analyzing .nx_debuglink");
        MemoryBlock nxDebugLink = program.getMemory().getBlock(".nx_debuglink");
        if (nxDebugLink == null)
            return;

        int nameLen = program.getMemory().getInt(nxDebugLink.getStart().add(4));
        StructureDataType dt = new StructureDataType(DEFAULT_PATH, "nx_debuglink", 0, program.getDataTypeManager());
        dt.add(DWORD, "", "");
        dt.add(DWORD, "module_name_len", "Length of module name");
        if (nameLen > 0)
            dt.add(StringDataType.dataType, nameLen, "module_name", "Module name");

        DataUtilities.createData(program, nxDebugLink.getStart(), dt, -1, false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
    }

    private void analyzeApiInfo(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException
    {
        HashMap<MemoryBlock, Long> candidates = findApiInfoCandidates(program, monitor, log);
        if (candidates.size() == 0)
            return;

        MemoryBlock block = Collections.max(candidates.entrySet(), Map.Entry.comparingByValue()).getKey();
        if (!block.getName().startsWith(".rodata"))
            return;

        try
        {
            block.setName(".api_info");
        }
        catch (Exception e)
        {
            log.appendMsg("Failed to set name for .api_info section");
            log.appendException(e);
        }
    }

    private HashMap<MemoryBlock, Long> findApiInfoCandidates(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException
    {
        monitor.checkCancelled();
        
        HashMap<MemoryBlock, Long> candidates = new HashMap<>();

        MemoryBlock apiInfo = program.getMemory().getBlock(".api_info");
        if (apiInfo != null)
        {
            candidates.put(apiInfo, new Long(1));
            return candidates;
        }

        MemoryBlock plt = program.getMemory().getBlock(".plt");
        if (plt == null)
            return candidates;

        Function referSymbol = null;
        for (Function f : program.getFunctionManager().getFunctions(new AddressSet(plt.getAddressRange()), true))
        {
            if (f.getName(true).equals(REFER_SYMBOL_MANGLED_NAME) || f.getName(true).endsWith(REFER_SYMBOL_NAME))
            {
                if (referSymbol == null)
                {
                    referSymbol = f;
                    continue;
                }
                else if (referSymbol != f)
                {
                    log.appendMsg("Multiple functions named nn::util::ReferSymbol - using first match");
                }
            }
        }

        if (referSymbol == null)
            return candidates;

        for (Reference ref : program.getReferenceManager().getReferencesTo(referSymbol.getEntryPoint()))
        {
            monitor.checkCancelled();
            Address addr = tryFindInputAddress(program, monitor, ref);
            if (addr == null)
                continue;
            MemoryBlock containingBlock = program.getMemory().getBlock(addr);
            if (containingBlock != null)
            {
                if (candidates.containsKey(containingBlock))
                {
                    candidates.put(containingBlock, candidates.get(containingBlock) + 1);
                }
                else
                {
                    candidates.put(containingBlock, new Long(1));
                }
            }
        }

        return candidates;
    }

    private Address tryFindInputAddress(Program program, TaskMonitor monitor, Reference ref) throws CancelledException
    {
        // this is very primitive but I think it should suffice
        Function containingFunction = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
        if (containingFunction == null)
            return null;

        for (Instruction inst : program.getListing().getInstructions(ref.getFromAddress(), false))
        {
            monitor.checkCancelled();
            if (!containingFunction.getBody().contains(inst.getAddress()))
                break;

            if (!inst.getMnemonicString().equals("add"))
                continue;

            Register reg = inst.getRegister(0);
            if (reg == null || !reg.getName().equals("x0"))
                continue;

            for (Reference opRef : inst.getOperandReferences(0))
            {
                if (opRef.getReferenceType() != RefType.PARAM)
                    continue;

                return opRef.getToAddress();
            }
        }

        return null;
    }

    @Override
    public void registerOptions(Options options, Program program) 
    {
        options.registerOption(OPTION_NAME_APPLY_DATATYPES, applyDataTypes, null, OPTION_DESCRIPTION_APPLY_DATATYPES);
    }

    @Override
	public void optionsChanged(Options options, Program program)
    {
		applyDataTypes = options.getBoolean(OPTION_NAME_APPLY_DATATYPES, applyDataTypes);
	}
}
