#include <Windows.h>
#include <stdint.h>
#include <cstdio>

namespace Util
{
	uint64_t GetSizeOfPE(PIMAGE_DOS_HEADER dos_header)
	{
		// Get an address to the images nt headers
		PIMAGE_NT_HEADERS image_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uint64_t>(dos_header) + dos_header->e_lfanew);

		if (image_nt_headers->Signature != IMAGE_NT_SIGNATURE)
		{
			// Log that the NT signature is invalid
			printf("[!] Failed to get size of the PE. Invalid NT Signature\n");

			return NULL;
		}

		// Store the size of all the headers
		uint64_t size = image_nt_headers->OptionalHeader.SizeOfHeaders;

		// Walk each section header in the PE, And step the size of each section.
		uint32_t i = 0;
		for (PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(image_nt_headers); i < image_nt_headers->FileHeader.NumberOfSections; section_header++, i++)
			size += section_header->SizeOfRawData;

		return size;
	}
}