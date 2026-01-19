/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nxo;

import java.io.IOException;

import adubbz.nx.common.InvalidMagicException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class MOD0Header 
{
    private long thisOffset;
    
    private String magic;
    private int dynamicOffset;
    private int bssStartOffset;
    private int bssEndOffset;
    private int ehFrameHdrStartOffset;
    private int ehFrameHdrEndOffset;
    private int runtimeModuleOffset;

    // added in newer versions (starting around SDK version 20)
    private int relroStartOffset;
    private int fullRelroEndOffset;
    private int nxDebugLinkStartOffset;
    private int nxDebugLinkEndOffset;
    private int gnuBuildIdStartOffset;
    private int gnuBuildIdEndOffset;

    private boolean isNewVersion;
    
    // libnx extensions
    private String lnxMagic;
    private int lnxGotStart;
    private int lnxGotEnd;
    
    public MOD0Header(BinaryReader reader, int readerOffset, int mod0StartOffset, boolean isNewVersion) throws InvalidMagicException, IOException
    {
        this.isNewVersion = isNewVersion;
        this.thisOffset = mod0StartOffset;
        
        long prevPointerIndex = reader.getPointerIndex();
        
        reader.setPointerIndex(readerOffset);
        this.readHeader(reader);
        
        // Restore the previous pointer index
        reader.setPointerIndex(prevPointerIndex);
    }
    
    private void readHeader(BinaryReader reader) throws InvalidMagicException, IOException
    {
        this.magic = reader.readNextAsciiString(4);
        
        if (!this.magic.equals("MOD0"))
            throw new InvalidMagicException("MOD0");
        
        this.dynamicOffset = (int) this.thisOffset + reader.readNextInt();
        this.bssStartOffset = (int) this.thisOffset + reader.readNextInt();
        this.bssEndOffset = (int) this.thisOffset + reader.readNextInt();
        this.ehFrameHdrStartOffset = (int) this.thisOffset + reader.readNextInt();
        this.ehFrameHdrEndOffset = (int) this.thisOffset + reader.readNextInt();
        this.runtimeModuleOffset = (int) this.thisOffset + reader.readNextInt();

        if (isNewVersion)
        {
            this.relroStartOffset = (int) this.thisOffset + reader.readNextInt();
            this.fullRelroEndOffset = (int) this.thisOffset + reader.readNextInt();
            this.nxDebugLinkStartOffset = (int) this.thisOffset + reader.readNextInt();
            this.nxDebugLinkEndOffset = (int) this.thisOffset + reader.readNextInt();
            this.gnuBuildIdStartOffset = (int) this.thisOffset + reader.readNextInt();
            this.gnuBuildIdEndOffset = (int) this.thisOffset + reader.readNextInt();

            this.lnxMagic = "";

            int majorVer = reader.readNextInt();
            int minorVer = reader.readNextInt();
            int patchVer = reader.readNextInt();
            Msg.info(this, String.format("SDK Version: %d.%d.%d", majorVer, minorVer, patchVer));
        }
        else
        {
            this.lnxMagic = reader.readNextAsciiString(4);
            
            if (this.lnxMagic.equals("LNY0"))
            {
                Msg.info(this, "Detected Libnx MOD0 extension");
                this.lnxGotStart = (int) this.thisOffset + reader.readNextInt();
                this.lnxGotEnd = (int) this.thisOffset + reader.readNextInt();
            }

            this.relroStartOffset = 0;
            this.fullRelroEndOffset = 0;
            this.nxDebugLinkStartOffset = 0;
            this.nxDebugLinkEndOffset = 0;
            this.gnuBuildIdStartOffset = 0;
            this.gnuBuildIdEndOffset = 0;
        }
        
    }

    public long getHeaderOffset()
    {
        return this.thisOffset;
    }

    public long getHeaderSize()
    {
        if (isNewVersion())
            return 0x34 + 0xc; // the header is only 0x34, but the SDK version comes directly afterwards

        if (hasLibnxExtension())
            return 0x28;

        return 0x1c;
    }
    
    public int getDynamicOffset() 
    {
        return this.dynamicOffset;
    }

    public int getBssStartOffset()
    {
        return this.bssStartOffset;
    }
    
    public int getBssEndOffset()
    {
        return this.bssEndOffset;
    }
    
    public int getBssSize()
    {
        return this.bssEndOffset - this.bssStartOffset;
    }
    
    public int getEhFrameHdrStartOffset()
    {
        return this.ehFrameHdrStartOffset;
    }
    
    public int getEhFrameHdrEndOffset()
    {
        return this.ehFrameHdrEndOffset;
    }
    
    public int getRuntimeModuleOffset()
    {
        return this.runtimeModuleOffset;
    }

    public boolean isNewVersion()
    {
        return this.isNewVersion;
    }

    public int getRelroStartOffset()
    {
        return this.relroStartOffset;
    }

    public int getFullRelroEndOffset()
    {
        return this.fullRelroEndOffset;
    }
    
    public int getNxDebugLinkStartOffset()
    {
        return this.nxDebugLinkStartOffset;
    }

    public int getNxDebugLinkEndOffset()
    {
        return this.nxDebugLinkEndOffset;
    }

    public int getGnuBuildIdStartOffset()
    {
        return this.gnuBuildIdStartOffset;
    }

    public int getGnuBuildIdEndOffset()
    {
        return this.gnuBuildIdEndOffset;
    }
    
    // libnx extensions
    public boolean hasLibnxExtension()
    {
        return this.lnxMagic.equals("LNY0");
    }
    
    public int getLibnxGotStart()
    {
        return this.lnxGotStart;
    }
    
    public int getLibnxGotEnd()
    {
        return this.lnxGotEnd;
    }
}
