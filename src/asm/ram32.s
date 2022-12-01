.section .text32, "ax"
.global ram32_start
.code32

ram32_start:
    # Tracepoint for Cloud Hypervisor
    movl $0x31, %eax
    outb $0x80

# begin SEV code
check_sev_feature:
    # clear ebx to be safe because it will be used to get C bit position
    xor  %ebx, %ebx
    # Check if we have a valid (0x8000_001F) CPUID leaf
    movl $0x80000000, %eax
    cpuid

    # This should fail on non SEV CPUs
    cmpl $0x8000001f, %eax 
    jl   no_sev

    # Check for memory encryption feature:
    # CPUID Fn8000_001F[EAX] - Bit 1
    movl $0x8000001f, %eax
    cpuid
    btl  $1, %eax
    jnc  no_sev

    # Check if memory encryption is enabled
    # MSR+0xC0010131 - Bit 0 (SEV enabled)
    movl $0xc0010131, %ecx
    rdmsr
    btl  $0, %eax 
    jnc  no_sev

    # Get pte bit position to enable memory encryption
    # CPUID Fn8000_001F[EBX] - Bits 5:0
    movl %ebx, %eax
    and  $0x3f, %eax

    xor  %edx, %edx
    test %eax, %eax
    jz   setup_page_tables

    subl $32, %eax
    bts  %eax, %edx
    # Clear lower 32 bits of C bit
    movl $0, (SEV_ENC_BIT)
    # Set upper 32 bits of C bit
    movl %edx, (SEV_ENC_BIT + 4)
    jmp  setup_page_tables

no_sev:
    xor  %eax, %eax

setup_page_tables:
    # First L2 entry identity maps [0, 2 MiB)
    movl $0b10000011, (L2_TABLES) # huge (bit 7), writable (bit 1), present (bit 0)
    movl %edx, (L2_TABLES+4)
    # First L3 entry points to L2 table
    movl $L2_TABLES, %eax
    orb  $0b00000011, %al # writable (bit 1), present (bit 0)
    movl %eax, (L3_TABLE)
    movl %edx, (L3_TABLE+4)
    # First L4 entry points to L3 table
    movl $L3_TABLE, %eax
    orb  $0b00000011, %al # writable (bit 1), present (bit 0)
    movl %eax, (L4_TABLE)
    movl %edx, (L4_TABLE+4)

enable_paging:
    # Load page table root into CR3
    movl $L4_TABLE, %eax
    movl %eax, %cr3

    # Set CR4.PAE (Physical Address Extension)
    movl %cr4, %eax
    orb  $0b00100000, %al # Set bit 5
    movl %eax, %cr4
    # Set EFER.LME (Long Mode Enable)
    movl $0xC0000080, %ecx
    rdmsr
    orb  $0b00000001, %ah # Set bit 8
    wrmsr
    # Set CRO.PG (Paging)
    movl %cr0, %eax
    orl  $(1 << 31), %eax
    movl %eax, %cr0

jump_to_64bit:
    # We are now in 32-bit compatibility mode. To enter 64-bit mode, we need to
    # load a 64-bit code segment into our GDT.
    lgdtl GDT64_PTR
    # Initialize the stack pointer (Rust code always uses the stack)
    movl $stack_start, %esp
    # Set segment registers to a 64-bit segment.
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %gs
    movw %ax, %fs
    movw %ax, %ss
    # Set CS to a 64-bit segment and jump to 64-bit Rust code.
    ljmpl $0x08, $rust64_start
