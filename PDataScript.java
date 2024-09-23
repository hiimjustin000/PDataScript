// A Ghidra script that uses the .pdata section of Windows PE files to create functions.
// @author hiimjustin000
// @category Functions

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.pe.FileHeader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class PDataScript extends GhidraScript
{
    @Override
    public void run() throws Exception
    {
        println("Starting PDataScript...");

        // Check if the current program is a PE file
        if (!currentProgram.getExecutableFormat().equals(PeLoader.PE_NAME))
        {
            printerr("Error: Not a PE file.");
            return;
        }

        // Get the .pdata section
        MemoryBlock pdataBlock = currentProgram.getMemory().getBlock(".pdata");

        // Check if the .pdata section exists
        if (pdataBlock == null)
        {
            printerr("Error: .pdata section not found.");
            return;
        }

        // Print the start address of the .pdata section
        println("Found .pdata section at 0x" + pdataBlock.getStart());

        // Get the machine type from the PE header
        Memory memory = currentProgram.getMemory();
        Address imageBase = currentProgram.getImageBase();
        int programMachine = Short.toUnsignedInt(memory.getShort(imageBase.add(memory.getInt(imageBase.add(0x3c)) + 4)));

        // Get the size of the .pdata section
        long pdataSize = pdataBlock.getSize();
        int entrySize = 0;
        switch (programMachine)
        {
            case FileHeader.IMAGE_FILE_MACHINE_I386:
            case FileHeader.IMAGE_FILE_MACHINE_IA64:
            case FileHeader.IMAGE_FILE_MACHINE_AMD64:
                entrySize = 12;
                break;
            case FileHeader.IMAGE_FILE_MACHINE_ARM:
            case FileHeader.IMAGE_FILE_MACHINE_ARM64:
            case FileHeader.IMAGE_FILE_MACHINE_ARMNT:
                entrySize = 8;
                break;
            default:
                printerr("Error: Unsupported machine type " + programMachine + ".");
                return;
        }

        // Print the number of entries in the .pdata section
        println("Found " + pdataSize / entrySize + " entries in the .pdata section.");

        // Iterate through the .pdata section and create functions
        Listing listing = currentProgram.getListing();
        for (long i = 0; i < pdataSize; i += entrySize)
        {
            // Get the start address of the function
            long functionStartOffset = memory.getInt(pdataBlock.getStart().add(i));
            if (functionStartOffset == 0)
                continue;
            Address functionStart = imageBase.add(functionStartOffset);

            // Check if the function already exists
            if (listing.getFunctionAt(functionStart) == null)
            {
                // Disassemble the instruction at the start of the function
                if (listing.getInstructionAt(functionStart) == null)
                    println((disassemble(functionStart) ? "Disassembled instruction at 0x" : "Failed to disassemble instruction at 0x") + functionStart);

                // Create the function
                println((
                    createFunction(functionStart, "FUN_" + functionStart.toString()) != null ?
                        "Created function at 0x" :
                        "Failed to create function at 0x"
                ) + functionStart);
            }
        }

        println("PDataScript finished.");
    }
}
