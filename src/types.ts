// types.ts
import { Key } from './key';


/**
 * Represents the size of entropy in characters for different security levels
 */
export enum EntropyBits {
    // Bits128 represents the length of characters needed in
    // an APIKey entropy segment to provide 128 bits of entropy.
    // It assumes use of a UUIDv7 Base32-Crockford encoded Key
    // and that the entropy is also encoded using Base32-Crockford.
    Bits128 = 14,

    // Bits160 represents the length of characters needed in
    // an APIKey entropy segment to provide 160 bits of entropy.
    // It assumes use of a UUIDv7 Base32-Crockford encoded Key
    // and that the entropy is also encoded using Base32-Crockford.
    Bits160 = 21,

    // Bits256 represents the length of characters needed in
    // an APIKey entropy segment to provide 256 bits of entropy.
    // It assumes use of a UUIDv7 Base32-Crockford encoded Key
    // and that the entropy is also encoded using Base32-Crockford.
    Bits256 = 42
}

/**
 * Configuration options for API key generation and handling
 */
export interface Config {
    hyphens: boolean;
    entropySize: EntropyBits;
}

/**
 * Option function type for configuring API key behavior
 */
export type Option = (c: Config) => void;

/**
 * Constants used throughout the API key system
 */
export const Constants = {
    // KEY_LENGTH_WITH_HYPHENS is the total length of a valid UUID Key, including hyphens.
    KEY_LENGTH_WITH_HYPHENS: 31, // 7 + 1 + 7 + 1 + 7 + 1 + 7 = 31 characters

    // KEY_LENGTH_WITHOUT_HYPHENS is the total length of a valid UUID Key, excluding hyphens.
    KEY_LENGTH_WITHOUT_HYPHENS: 28, // 7 + 7 + 7 + 7 = 28 characters

    // KEY_PART_LENGTH is the length of each part in a UUID Key.
	// A UUID Key consists of 4 parts separated by hyphens.
    KEY_PART_LENGTH: 7,

    // KEY_HYPHEN_COUNT is the number of hyphens in a valid UUID Key.
    KEY_HYPHEN_COUNT: 3,
    
    // KEY_PARTS_COUNT is the number of parts in a valid UUID Key.
    KEY_PARTS_COUNT: 4,

    // UUID_LENGTH is the standard length of a UUID string, including hyphens.
	// Reference: RFC 4122 (https://tools.ietf.org/html/rfc4122)
    UUID_LENGTH: 36,

    CHECKSUM_LENGTH: 8,
    ENTROPY_BYTES_MULTIPLIER: 8 / 5,    // Used for calculating entropy bytes
    INITIAL_ENTROPY_BYTES: 32           // Initial entropy buffer size
} as const;

/**
 * Configuration options for API key generation
 */
export const Options = {
    With128BitEntropy: ((c: Config) => { c.entropySize = EntropyBits.Bits128; }) as Option,
    With160BitEntropy: ((c: Config) => { c.entropySize = EntropyBits.Bits160; }) as Option,
    With256BitEntropy: ((c: Config) => { c.entropySize = EntropyBits.Bits256; }) as Option,
    // WithoutHyphens: ((c: Config) => { c.hyphens = false; }) as Option,
} as const;

/**
 * Default configuration settings
 */
export const DefaultConfig: Config = {
    hyphens: true,
    entropySize: EntropyBits.Bits160
};