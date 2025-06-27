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
	static const int M = static_cast<int>(ALPHABET.size()); // 62

	static int random_index() {
		static std::mt19937 rng(
			static_cast<unsigned>(
				std::chrono::steady_clock::now()
				.time_since_epoch().count()
				)
		);
		std::uniform_int_distribution<int> dist(0, M - 1);
		return dist(rng);
	}

	static int idx_of(char c) {
		auto pos = ALPHABET.find(c);
		if (pos == std::string::npos) {
			throw std::invalid_argument(std::string("Invalid char: ") + c);
		}
		return static_cast<int>(pos);
	}
}

static std::string encrypt4(const std::string& plain) {
	size_t N = plain.size();
	if (N == 0) {
		throw std::invalid_argument("Plaintext must not be empty");
	}
	std::array<int, 4> keys;
	for (int j = 0; j < 4; ++j) {
		keys[j] = random_index();
	}
	std::string cipher;
	cipher.reserve(N + 4);
	for (int j = 0; j < 4; ++j) {
		cipher.push_back(ALPHABET[keys[j]]);
	}
	for (size_t i = 0; i < N; ++i) {
		int pi = idx_of(plain[i]);
		int ki = keys[i % 4];
		int ci = (pi + ki + static_cast<int>(i)) % M;
		cipher.push_back(ALPHABET[ci]);
	}
	return cipher;
}

static std::string decrypt4(const std::string& cipher) {
	size_t C = cipher.size();
	if (C < 4) {
		throw std::invalid_argument("Ciphertext length must be >= 4");
	}
	size_t N = C - 4;
	std::array<int, 4> keys;
	for (int j = 0; j < 4; ++j) {
		keys[j] = idx_of(cipher[j]);
	}
	std::string plain;
	plain.reserve(N);
	for (size_t i = 0; i < N; ++i) {
		int ci = idx_of(cipher[i + 4]);
		int ki = keys[i % 4];
		int pi = (ci - ki - static_cast<int>(i)) % M;
		if (pi < 0) pi += M;
		plain.push_back(ALPHABET[pi]);
	}
	return plain;
}
