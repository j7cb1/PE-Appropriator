#include <Windows.h>
#include <cstdio>
#include <stdint.h>
#include <fstream>
#include <vector>
#include <string>

#include "utils.hpp"

int main(int argc, char* argv[])
{
	// Check that the user has used this process correctly
	if (argc != 2)
	{
		printf("[!] Drag the your binary onto the executable.\n");

		return 1;
	}

	// Log the inputed binary 
	printf("[i] Target: %s\n", argv[1]);

	// Open a handle to the target binary
	HANDLE file = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	// Check that the handle opened is valid
	if (file == INVALID_HANDLE_VALUE)
	{
		// Log that the handle opened was invalid
		printf("[!] Failed to open a handle to the target binary\n");

		// Await user information
		getchar();

		return 1;
	}

	// Log the handle opened to the target file
	printf("[>] Handle opened to target binary: 0x%p\n", file);

	// Create a file mapped object
	HANDLE map_object = CreateFileMappingA(file, NULL, PAGE_READONLY, NULL, NULL, NULL);

	// Map a view of the file object
	LPVOID base = MapViewOfFile(map_object, FILE_MAP_READ, 0, 0, 0);

	// Log the file base address
	printf("[>] File base address: 0x%p\n\n", base);

	// Load the target file into a file stream
	std::fstream target = std::fstream(argv[1], std::fstream::binary | std::fstream::in);

	// Store the file in a vector so we can pluck sections
	std::vector<uint8_t> file_vector = {};

	// Store each byte from the target file into the file vector
	while (target) file_vector.push_back(target.get());

	// Close the file stream
	target.close();

	// Store the DOS signature (basically the pattern for the pattern scan)
	std::vector<uint8_t> dos_signature = { 0x4D, 0x5A, 0x90, 0x00 };

	// Create a counter to log how many PE's were found
	uint32_t counter = 0;

	// Walk each byte in the file vector and pattern scan for the DOS header. (i == 2 because we want to skip the first DOS signature)
	for (uint32_t i = 2; i < file_vector.size(); i++)
	{
		// Walk the signature
		for (uint32_t u = 0; u < dos_signature.size(); u++)
		{
			// Check to see if the signature matches
			if (file_vector[i + u] != dos_signature[u]) break;

			// Every size of the DOS signature then the sig matches 
			if (u == dos_signature.size() - 1)
			{
				// Step the counter
				counter++;

				// Log that a PE has been found
				printf("[!] Located a PE\t");

				// Cast the VA to a DOS header
				PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(reinterpret_cast<uint64_t>(base) + i);

				// Get the size of the PE
				uint64_t size = Util::GetSizeOfPE(dos_header);

				// Log the PE size
				printf("Size:\t0x%llx\tRVA:\t0x%lx\n", size, i);

				// Create a vector to store the PE 
				std::vector<uint8_t> pe(file_vector.begin() + i, file_vector.begin() + i + size);

				// Create a file stream to the output file
				std::fstream stream(std::string(std::to_string(i) + ".pe"), std::ios::binary | std::ios::out);
				stream.write((char*)pe.data(), size);
				stream.close();
			}
		}
	}

	// Unmap the file
	UnmapViewOfFile(base);

	// Close the handle to the map object
	CloseHandle(map_object);

	// Close the handle to the file 
	CloseHandle(file);

	// Prompt the user to exit the binary
	printf("\n[>] The main routine has completed; Found %d PE's. Press Anything To Exit...\n", counter);

	// Await user input
	getchar();

	return 0;
}