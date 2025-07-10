#pragma once
#include <iostream>
#include <string>
#include <array>
#include <random>
#include <chrono>
#include <stdexcept>
namespace {
	static const std::string alphabet62 =
	"0123456789"
	"abcdefghijklmnopqrstuvwxyz"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static const int BASE62 = (int)alphabet62.size(); // 62

	static int random_index() {
		static std::mt19937 rng(
			(unsigned)std::chrono::steady_clock::now().time_since_epoch().count()
		);
		std::uniform_int_distribution<int> dist(0, BASE62 - 1);
		return dist(rng);
	}

	static int idx_of(char c) {
		auto pos = alphabet62.find(c);
		return (int)pos;
	}

}

static std::string simple_encrypt_with_key(const std::string& plain, char key) {
	size_t N = plain.size();
	if (N == 0) {
		return {};
	}
	int ki = idx_of(key);
	std::string cipher;
	cipher.reserve(N + 1);
	cipher.push_back(key);
	for (size_t i = 0; i < N; ++i) {
		int pi = idx_of(plain[i]);
		int ci = (pi + ki + static_cast<int>(i)) % BASE62;
		cipher.push_back(alphabet62[ci]);
	}
	return cipher;
}

static std::string simple_encrypt(const std::string& plain) {
	int ki = random_index();
	char key = alphabet62[ki];
	return simple_encrypt_with_key(plain, key);
}

static std::string simple_decrypt_with_key(const std::string& cipher, char key) {
	const size_t L = cipher.size();
	if (L <= 1) {
		return {};
	}
	size_t N = L - 1;

	int ki = idx_of(key);

	std::string plain;
	plain.reserve(N);

	for (size_t i = 0; i < N; ++i) {
		int ci = idx_of(cipher[i + 1]);
		int pi = (ci - ki - static_cast<int>(i)) % BASE62;
		if (pi < 0) pi += BASE62;
		plain.push_back(alphabet62[pi]);
	}
	return plain;
}

static std::string simple_decrypt(const std::string& cipher) {
	if (cipher.size() <= 1) {
		return {};
	}
	return simple_decrypt_with_key(cipher, cipher[0]);
}

static std::string to_base62(std::size_t num) {
	if (num == 0) {
		return std::string(1, alphabet62[0]);
	}
	std::string s;
	while (num > 0) {
		int rem = static_cast<int>(num % BASE62);
		s.push_back(alphabet62[rem]);
		num /= BASE62;
	}
	std::reverse(s.begin(), s.end());
	return s;
}

static std::size_t from_base62(const std::string& s) {
	std::size_t val = 0;
	for (char c : s) {
		std::size_t idx = alphabet62.find(c);
		val = val * BASE62 + idx;
	}
	return val;
}