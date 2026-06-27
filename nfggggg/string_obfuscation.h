#pragma once
#include <string>
#include <cstdint>

// Compile-time multi-byte rotating key encryption
// Much stronger than simple XOR - uses rotating key + position-dependent mixing
// Usage: auto str = OBFUSCATE("my secret string");

namespace StringObfuscation {

    // Compile-time random seed based on compilation timestamp
    // Change these values to randomize the encryption
    constexpr uint64_t SEED1 = 0x9E3779B97F4A7C15ULL;  // Golden ratio
    constexpr uint64_t SEED2 = 0x6C078965D98B3FA7ULL;  // Random prime
    constexpr uint64_t SEED3 = 0xF1357AEA2B34C89BULL;  // Random prime

    // Compile-time key derivation (generates unique key per position)
    constexpr uint8_t DeriveKey(size_t position, size_t length) {
        uint64_t key = SEED1;
        key ^= (position * SEED2);
        key ^= (length * SEED3);
        key = (key >> 32) ^ (key & 0xFFFFFFFF);
        key = (key >> 16) ^ (key & 0xFFFF);
        return static_cast<uint8_t>((key >> 8) ^ (key & 0xFF));
    }

    // Additional mixing function
    constexpr uint8_t MixByte(uint8_t byte, size_t position, size_t length) {
        uint8_t key = DeriveKey(position, length);
        // Multi-step encryption: rotate + XOR + add
        byte = ((byte << 3) | (byte >> 5));  // Rotate left 3 bits
        byte ^= key;                          // XOR with derived key
        byte += static_cast<uint8_t>(position * 7 + length * 13);  // Position-dependent add
        byte ^= 0x55;                         // Additional XOR layer
        return byte;
    }

    // Compile-time string encryptor
    template<size_t N>
    class ObfuscatedString {
    private:
        char encrypted[N];

    public:
        constexpr ObfuscatedString(const char* str) : encrypted{} {
            for (size_t i = 0; i < N; i++) {
                encrypted[i] = MixByte(static_cast<uint8_t>(str[i]), i, N);
            }
        }

        // Runtime decryption (reverse of encryption)
        std::string decrypt() const {
            std::string result;
            result.reserve(N);
            for (size_t i = 0; i < N - 1; i++) { // -1 to skip null terminator
                uint8_t byte = static_cast<uint8_t>(encrypted[i]);

                // Reverse the encryption steps
                byte ^= 0x55;                                              // Reverse final XOR
                byte -= static_cast<uint8_t>(i * 7 + N * 13);             // Reverse add
                byte ^= DeriveKey(i, N);                                   // Reverse key XOR
                byte = ((byte >> 3) | (byte << 5));                       // Reverse rotate

                result += static_cast<char>(byte);
            }
            return result;
        }

        // Decrypt to C-string buffer
        void decrypt(char* buffer, size_t bufferSize) const {
            size_t len = (N - 1 < bufferSize - 1) ? N - 1 : bufferSize - 1;
            for (size_t i = 0; i < len; i++) {
                uint8_t byte = static_cast<uint8_t>(encrypted[i]);

                // Reverse encryption
                byte ^= 0x55;
                byte -= static_cast<uint8_t>(i * 7 + N * 13);
                byte ^= DeriveKey(i, N);
                byte = ((byte >> 3) | (byte << 5));

                buffer[i] = static_cast<char>(byte);
            }
            buffer[len] = '\0';
        }
    };

    // Helper to deduce string length
    template<size_t N>
    constexpr auto MakeObfuscated(const char(&str)[N]) {
        return ObfuscatedString<N>(str);
    }
}

// Convenience macro
#define OBFUSCATE(str) StringObfuscation::MakeObfuscated(str)

// Usage examples:
// std::string decrypted = OBFUSCATE("secret").decrypt();
// char buffer[256];
// OBFUSCATE("secret").decrypt(buffer, sizeof(buffer));
