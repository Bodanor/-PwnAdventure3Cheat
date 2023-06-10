#include "libGameLogic.h"
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


extern "C" ClientWorld *GameWorld;

using namespace std;

void SpeedHack(void);
void trampoline_SetJumpState(bool state);
int libraryCallback(struct dl_phdr_info *info, size_t size, void *data);

int libraryCallback(struct dl_phdr_info *info, size_t size, void *data)
{
	const char* libraryName = "libGameLogic.so";  // Replace with the name of the original library
    if (strstr(info->dlpi_name, libraryName) != NULL) {
        *(void**)data = dlopen(libraryName, RTLD_LAZY);
		return 1; // Stop iterating after finding the desired library
	}
    return 0;  // Continue iterating
}

void trampoline_SetJumpState(bool state)
{
    printf("PWNED !!!\n");
}

bool InfiniteJump()
{
	return 1;
}

void SpeedHack(void)
{
	
	IPlayer *currentPlayer = GameWorld->m_activePlayer.m_object;
	Player *player = (Player*)currentPlayer;
	player->m_walkingSpeed = 1000;
}
void* createTrampoline(void* handle, const char* symbol, void* replacementFunction)
{
    // Find the symbol address
    void* symbolAddress = dlsym(handle, symbol);
    if (!symbolAddress)
    {
        fprintf(stderr, "(PWNED)[-] : Failed to find the symbol: %s\n", dlerror());
        return nullptr;
    }
	printf("(PWNED)[+] : Found Symbol \"%s\" at address : %p\n", symbol, symbolAddress);
	// Calculate the size of the jump instruction
	const size_t jumpInstructionSize = 14; // Adjust as needed

    // Change the memory protection to allow writing
    const size_t pageSize = getpagesize();
    uintptr_t symbolPageStart = (uintptr_t)symbolAddress & ~(pageSize - 1);
    mprotect((void*)symbolPageStart, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC);

    // Allocate memory for the trampoline function
    void* trampoline = mmap(nullptr, jumpInstructionSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trampoline == MAP_FAILED)
    {
        perror("(PWNED)[-] : Failed to allocate memory for the trampoline");
        return nullptr;
    }
	printf("(PWNED)[+] : Address of the trampoline function : %p\n", trampoline);
	// Write the jump instruction (trampoline) at the trampoline address
	unsigned char jumpInstruction[] = {
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Mov RAX, <replacementFunction>
		0xFF, 0xE0													// JMP RAX
	};
	memcpy(&jumpInstruction[2], &replacementFunction, sizeof(void*));
    memcpy(trampoline, jumpInstruction, sizeof(jumpInstruction));

	printf("(PWNED)[+] : Inserting JUMP to %p inside the trampoline function !\n", replacementFunction);

	// Write the jump instruction (trampoline) at the symbol address
	unsigned char symbolJumpInstruction[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// Mov RAX, <trampoline>
        0xFF, 0xE0 // JMP RAX
    };
	printf("(PWNED)[+] : Patching beginning of the symbol %s(%p) with JUMP to trampoline (%p)\n", symbol, symbolAddress, trampoline);
	memcpy(&symbolJumpInstruction[2], &trampoline, sizeof(void *));
	memcpy(symbolAddress, symbolJumpInstruction, sizeof(symbolJumpInstruction));

	printf("(PWNED)[+] : Symbol got Patched to be redirected to %p !\n", replacementFunction);
	// Restore the original memory protection
	mprotect((void*)symbolPageStart, pageSize, PROT_READ | PROT_EXEC);

    return trampoline;
}

__attribute__((constructor))
void initSharedLib()
{
	printf("(PWNED)[+] : libGameLogic.so is loading ...\n");


	/* Find the start address of the libGameLogic.so function */
    void* handle = nullptr;
    dl_iterate_phdr(libraryCallback, &handle);
    if (!handle) {
        // Handle error if the library handle is not found
        std::cerr << "(PWNED)[-] : Failed to find the library handle." << std::endl;
        // Cleanup and return or handle the error accordingly
        return;
    }
    printf("(PWNED)[+] : Handle Address is : %p\n", handle);

        

	/* Replace the jumpState Function */
	void* trampoline = createTrampoline(handle, "_ZN6Player12SetJumpStateEb", (void*)&trampoline_SetJumpState);
    if (!trampoline)
    {
        // Handle error if trampoline setup fails
        std::cerr << "(PWNED)[-] : Failed to create trampoline." << std::endl;
        dlclose(handle);
        return;
    }
	trampoline = createTrampoline(handle, "_ZN6Player7CanJumpEv", (void*)&InfiniteJump);
    if (!trampoline)
    {
        // Handle error if trampoline setup fails
        std::cerr << "(PWNED)[-] : Failed to create trampoline." << std::endl;
        dlclose(handle);
        return;
    }

	/* Enable speed Hack */
	SpeedHack();
	printf("(PWNED)[+] : Speedhack ENABLED !\n");

	printf("(PWNED)[+] : libGameLogic.so loaded successfully !\n");
	printf("(PWNED)[++++] BY Christos.P (Liwinux) : The Game got PWNED !!!!\n");
	dlclose(handle);
}
