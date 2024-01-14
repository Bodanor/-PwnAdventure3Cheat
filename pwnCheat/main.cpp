#include "pwnCheat.h"
#include <cstddef>
#include <cstdio>
#include <dirent.h>
#include <dlfcn.h>
#include <functional>
#include <iostream>
#include <link.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define TARGET_LIB "libGameLogic.so"

#define TRAMPOLINE_MAX_SIZE 14

#define PWN_SUCCESS(format, ...) printf("(PWNED)[+] : " format, ##__VA_ARGS__)
#define PWN_FINAL_MSG(format, ...) printf("(PWNED)[++++++] : " format, ##__VA_ARGS__)
#define PWN_FAIL(format, ...) fprintf(stderr,"(PWNED)[-] : " format, ##__VA_ARGS__)
#define PWN_INFO(format, ...) printf("(PWNED)[!] : ", format, ##__VA_ARGS__)


static int patch_symbol(void *handle, const char *target_symbol_name, void *functionToJumpTo);
void *allocate_mem_instructions(uint64_t function_size);
static void trampoline_SetJumpState(bool state);


extern "C" ClientWorld *GameWorld;

unsigned char trampolineInstructions[] = {
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Mov RAX, <replacementFunction>
		0xFF, 0xE0													// JMP RAX
};


static void trampoline_SetJumpState(bool state)
{
    printf("PWNED !!!\n");
}

/* This function is used to allocate memory for a given instructions size */
void *allocate_mem_instructions(size_t function_size)
{
    return mmap(nullptr, function_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

/*
* This function is used to patch the beginning of a symbol and write a trampoline jump to a given replacement function
* Basically the original symbol is still in memory but never gets executed as is begins with a mov rax, replacementSymbol followed
* By a jump to that symbol. And you guessed it, the address we jump to is the replacement symbol. Thus creating a "trampoline"
*/
static int patch_symbol(void *handle, const char *target_symbol_name, void *functionToJumpTo)
{
    size_t pageSize;
    uintptr_t symbolPageStart;
    void *new_trampoline_address_instruction;
    void *target_symbol_address;
    
    /* Look for the target function the inject code to and get it's address */
    target_symbol_address = dlsym(handle, target_symbol_name);
    if (!target_symbol_address) {
        PWN_FAIL("Could not find symbol \"%s\" inside the target library !\n", target_symbol_name);
        return -1;
    }

    PWN_SUCCESS("Found symbol \"%s\" at address %p\n", target_symbol_name, target_symbol_address);

    /* By default pages are read only IIRC, so make the current page read, write and executable*/
    pageSize = getpagesize();
    symbolPageStart = (uintptr_t)target_symbol_address & ~(pageSize - 1);
    mprotect((void*)symbolPageStart, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC);

    /*
     * Allocate virtual memory for the trampoline instructions. We have to allocated memory as we are going
     * to replace the instructions at the target_symbol_address by a jump instruction to the replacement function
    */
    new_trampoline_address_instruction = allocate_mem_instructions(TRAMPOLINE_MAX_SIZE);
    if (new_trampoline_address_instruction == NULL) {
        PWN_FAIL("Failed to allocated virtual memory for the trampoline instructions !\n");
        return -2;
    }

    /* Modify the template trampoline jump instruction by placing the address of the function to jump to. */
    memcpy(&trampolineInstructions[2], &functionToJumpTo, sizeof(void*));

    PWN_INFO("Patching the beginning of the symbol \"%s\"(%p) with a JMP to the replacement symbol %p\n", target_symbol_name, target_symbol_address, functionToJumpTo);
    /* Now we can patch the beginning of the target function by a jump the replacement function*/
    mempcpy(target_symbol_address, trampolineInstructions, sizeof(trampolineInstructions));

    PWN_SUCCESS("Successfully patched the symbol \"%s\"(%p) to redirect to the replacement symbol %p\n", target_symbol_name, target_symbol_address, functionToJumpTo);
    /* Don't forget to restore the original page protections */
    mprotect((void*)symbolPageStart, pageSize, PROT_READ | PROT_EXEC);

    return 0;
}


/* This function gets called for every object dl_iterate_phdr finds and passes the data as parameters */
static int libraryCallback(struct dl_phdr_info *info, size_t size, void *data)
{
    /* Find is libGameLogic is a substring of the current object */
    if (strstr(info->dlpi_name, TARGET_LIB) != NULL) {
        /* We have found our object ! Now let's point to data the opaque handler that dlopen will create for the loaded dynamic shared library */
        PWN_SUCCESS("Found the dynamic shared library \"%s\" in memory at address : %p\n", TARGET_LIB, info->dlpi_addr);
        *(void**)data = dlopen(TARGET_LIB, RTLD_LAZY);
        return 1;
    }
    /* Not the object we are looking for, return 0 and wait for the next call */
    return 0;

}

/* First function to be called when the library gets loaded !*/
__attribute__((constructor))
void initSharedLib()
{
    void* handle = nullptr;

    /* From here, our cheat shared library has been loaded. Let's now find a handler that points to the target library called libGameLogic.so*/
	PWN_SUCCESS("I have been Injected ! I'm alive !\n");

	/* Find the start address of the libGameLogic.so shared library and get back an opaque handler */

    dl_iterate_phdr(libraryCallback, &handle);
    if (!handle) {
        // Handle error if the library handle is not found
        PWN_FAIL("Failed to find the library handle\n");
        // Cleanup and return or handle the error accordingly
        return;
    }
    PWN_SUCCESS("Handle Address is : %p\n", handle);

    PWN_SUCCESS("Trying to patch infinite jump !\n");
    
    if (patch_symbol(handle, "_ZN6Player12SetJumpStateEb", (void*)&trampoline_SetJumpState) != 0) {
        PWN_FAIL("Could not patch the target symbol !\n");
        return;
    }


	PWN_SUCCESS("All patching done !\n");
	PWN_FINAL_MSG("BY Christos.P (Liwinux) : The Game got PWNED !!!!\n");
	dlclose(handle);
}
