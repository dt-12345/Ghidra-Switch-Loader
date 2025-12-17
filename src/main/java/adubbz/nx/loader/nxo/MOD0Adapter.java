/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nxo;

import adubbz.nx.common.ElfCompatibilityProvider;
import adubbz.nx.common.InvalidMagicException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfDynamic;
import ghidra.app.util.bin.format.elf.ElfDynamicType;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.LEB128Info;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

import java.io.IOException;
import java.util.List;

/*
 * An adapter implementation for binaries with a MOD0 section.
 */
public abstract class MOD0Adapter extends NXOAdapter
{
    protected Program program;
    protected MOD0Header mod0;
    
    public MOD0Adapter(Program program, ByteProvider fileProvider)
    {
        super(fileProvider);
        this.program = program;
    }
    
    @Override
    public long getDynamicOffset()
    {
        MOD0Header mod0 = this.getMOD0();
        
        if (mod0 == null)
            return 0;
        
        return mod0.getDynamicOffset();
    }
    
    @Override
    public long getDynamicSize()
    {
        assert this.program != null;
        
        if (this.getElfProvider(this.program).getDynamicTable() != null)
            return this.getElfProvider(this.program).getDynamicTable().getLength();
        
        long dtSize = 0;
        var reader = new BinaryReader(this.getMemoryProvider(), true);
        reader.setPointerIndex(this.getDynamicOffset());
        
        try
        {
            while (true) 
            {
                ElfDynamic dyn = new ElfDynamic(reader, new ElfCompatibilityProvider.DummyElfHeader(this.isAarch32()));
                dtSize += dyn.sizeof();
                if (dyn.getTag() == ElfDynamicType.DT_NULL.value) 
                {
                    break;
                }
            }
        }
        catch (IOException e)
        {
            Msg.error(this, "Failed to get dynamic size", e);
        } catch (ElfException e) {
            Msg.error(this, "Can't construct DummyElfHeader", e);
        }

        return dtSize;
    }
    
    @Override
    public long getBssOffset()
    {
        MOD0Header mod0 = this.getMOD0();
        
        if (mod0 == null)
            return 0;
        
        return mod0.getBssStartOffset();
    }
    
    @Override
    public long getBssSize()
    {
        MOD0Header mod0 = this.getMOD0();
        
        if (mod0 == null)
            return 0;
        
        return mod0.getBssSize();
    }

    private long gotOffset = 0;
    private long gotSize = 0;

    private boolean findGot() {
        assert this.program != null;

        if (this.gotOffset > 0 && this.gotSize > 0) {
            return true;
        }

        MOD0Header mod0 = this.getMOD0();

        if (mod0 == null) {
            return false;
        }

        if (mod0.hasLibnxExtension()) {
            this.gotOffset = mod0.getLibnxGotStart() + this.program.getImageBase().getOffset();
            this.gotSize = mod0.getLibnxGotEnd() - mod0.getLibnxGotStart();
            return true;
        }

        boolean good = false;
        List<Long> relocationOffsets = this.getRelocations(program).stream().map(reloc -> reloc.offset).toList();
        MemoryBlock gotPlt = this.program.getMemory().getBlock(".got.plt");
        long gotStart, gotEnd;
        if (gotPlt != null) {
            gotStart = gotPlt.getEnd().getOffset() + 1 - this.program.getImageBase().getOffset();
            gotEnd = gotStart + this.getOffsetSize();

            // in newer binaries, .got.plt and .got are flipped
            if (!relocationOffsets.contains(gotEnd)) {
                gotStart = this.getDynamicOffset() + this.getDynamicSize();

                if (relocationOffsets.contains(gotStart)) {
                    gotStart += this.program.getImageBase().getOffset();
                    this.gotOffset = gotStart;
                    this.gotSize = gotPlt.getStart().getOffset() - gotStart;
                    return true;
                }
            }
        } else {
            gotStart = this.getDynamicOffset() + this.getDynamicSize();
            gotEnd = gotStart + this.getOffsetSize();
        }
        long initArrayValue;

        try {
            initArrayValue = this.getDynamicTable(program).getDynamicValue(ElfDynamicType.DT_INIT_ARRAY);
        } catch (NotFoundException ignored) {
            initArrayValue = -1;
        }

        while ((relocationOffsets.contains(gotEnd) || (gotPlt == null && initArrayValue != -1 && gotEnd < initArrayValue))
                && (initArrayValue == -1 || gotEnd < initArrayValue || gotStart > initArrayValue)) {
            good = true;
            gotEnd += this.getOffsetSize();
        }

        if (good) {
            this.gotOffset = this.program.getImageBase().getOffset() + gotStart;
            this.gotSize = gotEnd - gotStart;
            return true;
        }

        Msg.error(this, "Failed to find .got section.");
        return false;
    }
    
    @Override
    public long getGotOffset()
    {
        if (this.findGot()) {
            return this.gotOffset;
        }

        return 0;
    }
    
    @Override
    public long getGotSize()
    {
        if (this.findGot()) {
            return this.gotSize;
        }

        return 0;
    }
    
    public MOD0Header getMOD0()
    {
        if (this.mod0 != null)
            return this.mod0;
        
        try 
        {
            long entryInst = this.getMemoryReader().readUnsignedInt(this.getSection(NXOSectionType.TEXT).getOffset());
            // b #0x8 (arm) or 0 or b #0x8 (aarch64)
            boolean isOldVersion = entryInst == 0xea000000 || entryInst == 0 || entryInst == 0x14000002;
            int mod0Offset = this.getMemoryReader().readInt(this.getSection(NXOSectionType.TEXT).getOffset() + 4);
        
            if (Integer.toUnsignedLong(mod0Offset) >= this.getMemoryProvider().length())
                throw new IllegalArgumentException("Mod0 offset is outside the binary!");
            
            this.mod0 = new MOD0Header(this.getMemoryReader(), mod0Offset, mod0Offset, !isOldVersion);
            return this.mod0;
        }
        catch (InvalidMagicException e)
        {
            Msg.error(this, "Invalid MOD0 magic.", e);
        }
        catch (IOException e) 
        {
            Msg.error(this, "Failed to read MOD0.", e);
        }
        
        return null;
    }

    public long getEhFrameStartOffset()
    {
        try
        {
            long ehFrameHdrOffset = this.getMOD0().getEhFrameHdrStartOffset();
            if (ehFrameHdrOffset == 0)
                return 0;
    
            byte ehFramePtrEnc = this.getMemoryReader().readByte(ehFrameHdrOffset + 1);
            if (ehFramePtrEnc == 0xff) // DW_EH_PE_omit
                return 0;
    
            // ghidra provides utilities for this but they require the section to already exist first
            int valueFormat = ehFramePtrEnc & 0xf;
            int applicationType = (ehFramePtrEnc & 0xf0) >> 4;
    
            long baseOffset = 0;
            switch (applicationType)
            {
                case 0: // DW_EH_PE_absptr
                    break;
                case 1: // DW_EH_PE_pcrel
                    baseOffset = ehFrameHdrOffset + 4;
                    break;
                case 3: // DW_EH_PE_datarel
                    baseOffset = ehFrameHdrOffset;
                    break;
            }
    
            long offset = 0;
            switch (valueFormat)
            {
                case 1: // DW_EH_PE_uleb128
                {
                    long prevPointerIndex = this.getMemoryReader().getPointerIndex();
                    this.getMemoryReader().setPointerIndex(ehFrameHdrOffset + 4);
                    LEB128Info info = LEB128Info.unsigned(this.getMemoryReader());
                    this.getMemoryReader().setPointerIndex(prevPointerIndex);
                    offset = info.asLong();
                    break;
                }
                case 2: // DW_EH_PE_udata2
                    offset = (long) this.getMemoryReader().readUnsignedShort(ehFrameHdrOffset + 4);
                    break;
                case 3: // DW_EH_PE_udata4
                    offset = (long) this.getMemoryReader().readUnsignedInt(ehFrameHdrOffset + 4);
                    break;
                case 4: // DW_EH_PE_udata8
                    offset = this.getMemoryReader().readUnsignedValue(ehFrameHdrOffset + 4, 8);
                    break;
                case 9: // DW_EH_PE_sleb128
                {
                    long prevPointerIndex = this.getMemoryReader().getPointerIndex();
                    this.getMemoryReader().setPointerIndex(ehFrameHdrOffset + 4);
                    LEB128Info info = LEB128Info.signed(this.getMemoryReader());
                    this.getMemoryReader().setPointerIndex(prevPointerIndex);
                    offset = info.asLong();
                    break;
                }
                case 10: // DW_EH_PE_sdata2
                    offset = (long) this.getMemoryReader().readShort(ehFrameHdrOffset + 4);
                    break;
                case 11: // DW_EH_PE_sdata4
                    offset = (long) this.getMemoryReader().readInt(ehFrameHdrOffset + 4);
                    break;
                case 12: // DW_EH_PE_sdata8
                    offset = this.getMemoryReader().readLong(ehFrameHdrOffset + 4);
                    break;
            }
    
            return baseOffset + offset;
        }
        catch (IOException e)
        {
            Msg.error(this, "Failed to get exception handling frame pointer", e);
            return 0;
        }
    }

    public long getEhFrameEndOffset(long startOffset)
    {
        if (startOffset == 0)
            return 0;

        try
        {
            long endOffset = startOffset;
            while (true)
            {
                long entryLength = this.getMemoryReader().readInt(endOffset);
                if (entryLength == 0)
                {
                    endOffset += 4;
                    break;
                }
                else if (entryLength != -1)
                {
                    endOffset += entryLength + 4;
                }
                else
                {
                    entryLength = this.getMemoryReader().readLong(endOffset + 4);
                    endOffset += entryLength + 12;
                }
            }
            return endOffset;
        }
        catch (IOException e)
        {
            Msg.error(this, "Failed to find end of exception handling frame", e);
            return 0;
        }
    }
}
