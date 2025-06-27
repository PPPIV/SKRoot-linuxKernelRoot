#pragma once
#include <iostream>
#include <string>
#include <array>
#include <random>
#include <chrono>
#include <stdexcept>
namespace {
	static const std::string ALPHABET =
	"0123456789"
	"abcdefghijklmnopqrstuvwxyz"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static const int M = (int)ALPHABET.size(); // 62

	static int random_index() {
		static std::mt19937 rng(
			(unsigned)std::chrono::steady_clock::now().time_since_epoch().count()
		);
		std::uniform_int_distribution<int> dist(0, M - 1);
		return dist(rng);
	}

	static int idx_of(char c) {
		auto pos = ALPHABET.find(c);
		if (pos == std::string::npos) {
			throw std::invalid_argument(std::string("Invalid char: ") + c);
		}
		return (int)pos;
	}

}

static std::string simple_encrypt(const std::string& plain) {
	const size_t N = plain.size();
	if (N == 0) {
		throw std::invalid_argument("Plaintext cannot be empty");
	}
	int ki = random_index();
	char key = ALPHABET[ki];
	std::string cipher;
	cipher.reserve(N + 1);
	cipher.push_back(key);
	for (size_t i = 0; i < N; ++i) {
		int pi = idx_of(plain[i]);
		int ci = (pi + ki + (int)i) % M;
		cipher.push_back(ALPHABET[ci]);
	}
	return cipher;
}

static std::string simple_decrypt(const std::string& cipher) {
	const size_t L = cipher.size();
	if (L <= 1) {
		throw std::invalid_argument("Ciphertext length must be > 1");
	}
	size_t N = L - 1;

	char key = cipher[0];
	int ki = idx_of(key);

	std::string plain;
	plain.reserve(N);

	for (size_t i = 0; i < N; ++i) {
		int ci = idx_of(cipher[i + 1]);
		int pi = (ci - ki - (int)i) % M;
		if (pi < 0) pi += M;
		plain.push_back(ALPHABET[pi]);
	}
	return plain;
}