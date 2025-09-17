#include <iostream>
#include <fstream>
#include "zlib-1.3.1/zlib.h"
#include <string>
#include <sstream>
#include <filesystem>

namespace fs = std::filesystem;

void gzipCompressFile(const std::string& inputFile, const std::string& outputFile, int compressionLevel) {
	std::ifstream input(inputFile, std::ios::binary);
	if (!input) {
		throw std::runtime_error("Failed to open input file");
	}
	std::ofstream output(outputFile, std::ios::binary);
	if (!output) {
		throw std::runtime_error("Failed to open output file");
	}
	z_stream strm;
	memset(&strm, 0, sizeof(strm));

	if (deflateInit2(&strm, compressionLevel, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
		throw std::runtime_error("deflateInit2 failed");
	}
	unsigned char inBuffer[1024];
	unsigned char outBuffer[1024];
	int ret;
	do {
		input.read(reinterpret_cast<char*>(inBuffer), sizeof(inBuffer));
		strm.avail_in = static_cast<uInt>(input.gcount());
		strm.next_in = inBuffer;

		do {
			strm.avail_out = sizeof(outBuffer);
			strm.next_out = outBuffer;

			ret = deflate(&strm, input.eof() ? Z_FINISH : Z_NO_FLUSH);
			if (ret == Z_STREAM_ERROR) {
				deflateEnd(&strm);
				throw std::runtime_error("deflate failed");
			}

			size_t have = sizeof(outBuffer) - strm.avail_out;
			output.write(reinterpret_cast<char*>(outBuffer), have);
		} while (strm.avail_out == 0);
	} while (!input.eof());
	deflateEnd(&strm);
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		std::cerr << "Usage: <program> <file-to-compress>" << std::endl;
		return 1;
	}

	std::string inputFile = argv[1];
	fs::path inputFilePath(inputFile);

	if (!fs::exists(inputFile)) {
		std::cerr << "Error: File does not exist: " << inputFile << std::endl;
		return 1;
	}
	std::string outputFile = inputFilePath.stem().string() + ".gz.bin";

	try {
		gzipCompressFile(inputFile, outputFile, 9);
		std::cout << "Compressed file saved to: " << outputFile << std::endl;
	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return 1;
	}
	return 0;
}
