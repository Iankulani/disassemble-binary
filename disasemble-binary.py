import capstone
import sys
import os

# Function to disassemble the binary and detect loops
def disassemble_and_analyze(binary_path):
    if not os.path.exists(binary_path):
        print(f"Error: The binary file at {binary_path} does not exist.")
        return
    
    # Read the binary file
    with open(binary_path, "rb") as f:
        binary_data = f.read()

    # Initialize Capstone disassembler for 64-bit architecture (x86_64)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    
    # Disassemble the binary code
    disassembled_code = list(md.disasm(binary_data, 0x1000))

    # Variables to store loop and switch detection info
    loop_patterns = ["jmp", "je", "jne", "loop", "jz", "jnz", "call"]
    switch_patterns = ["jmp", "cmp", "je", "jne"]
    
    print(f"Disassembling binary {binary_path}...\n")

    # Iterate through disassembled code and search for loop/switch patterns
    loops_found = []
    switches_found = []

    for insn in disassembled_code:
        # Detecting loop-like structures (conditional jumps, loops, etc.)
        if any(pattern in insn.mnemonic for pattern in loop_patterns):
            loops_found.append(insn)

        # Detecting switch-like structures (jump tables, conditional branches)
        if any(pattern in insn.mnemonic for pattern in switch_patterns):
            switches_found.append(insn)
        
        # Print disassembled instruction
        print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")

    print("\nLoop detection results:")
    if loops_found:
        for loop in loops_found:
            print(f"Loop detected at 0x{loop.address:x}: {loop.mnemonic} {loop.op_str}")
    else:
        print("No loops detected.")

    print("\nSwitch/Case detection results:")
    if switches_found:
        for switch in switches_found:
            print(f"Switch/case pattern detected at 0x{switch.address:x}: {switch.mnemonic} {switch.op_str}")
    else:
        print("No switch/case patterns detected.")

# Main function to prompt the user and run the analysis
def main():
    print("Welcome to the Cybersecurity Binary Dynamic Analysis Tool!")
    binary_path = input("Enter the path to the binary file to analyze: ")

    # Disassemble and analyze the binary
    disassemble_and_analyze(binary_path)

if __name__ == "__main__":
    main()
