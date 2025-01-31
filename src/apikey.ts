// apikey.ts
import { crc32 } from 'crc';
import { randomBytes } from 'crypto';
import { createHash } from 'crypto';
import { Config, Option, EntropyBits, Constants, DefaultConfig, Options } from './types';
import { Key } from './key';
import { c32encode } from 'c32check';

/**
 * APIKey represents a compound key consisting of four parts or segments:
 * - Prefix: A company or application identifier (e.g., "AGNTSTNP")
 * - Key: A UUID-based identifier encoded in Base32-Crockford
 * - Entropy: Additional segment of random data for increased uniqueness
 * - Checksum: CRC32 checksum of the previous components (8 characters)
 * 
 * Format:
 * 
 * 	[Prefix]_[UUID Key][Entropy]_[Checksum]
 * 
 * 	AGNTSTNP_38QARV01ET0G6Z2CJD9VA2ZZAR0XJJLSO7WBNWY3F_A1B2C3D8
 * 	└─────┘ └──────────────────────────┘└────────────┘ └──────┘
 * 	Prefix        Key (crock32 UUID)        Entropy      Checksum
 */
export class APIKey {
    /** Prefix identifying the application or service */
    prefix: string;
    /** Base32-Crockford encoded UUID */
    key: Key;
    /** Additional entropy for uniqueness */
    entropy: string;
    /** CRC32 checksum of other components */
    checksum: string;

    constructor(prefix: string, key: Key, entropy: string, checksum: string) {
        this.prefix = prefix;
        this.key = key;
        this.entropy = entropy;
        this.checksum = checksum || calculateChecksum(this);
    }

    toString(): string {
        return `${this.prefix}_${this.key.toString()}${this.entropy}_${this.checksum}`;
    }
}

/**
 * newAPIKey creates a new APIKey from a string prefix, string UUID, and option.
 */
export function newAPIKey(
    prefix: string,
    uuid: string,
    opt: Option = Options.With160BitEntropy
): APIKey {
    if (!prefix) {
        throw new Error('prefix cannot be empty');
    }

    const config = applyOptions(opt);
    const key = Key.encode(uuid, false);
    const entropy = generateEntropy(config.entropySize);

    const apiKey: APIKey = new APIKey(
        prefix,
        key,
        entropy,
        ''
    );

    return apiKey;
}

/**
 * Creates a new API key from a prefix and [16]byte UUID, and option.
 */
export function newAPIKeyFromBytes(prefix: string, uuid: Buffer, opt: Option = Options.With160BitEntropy): APIKey {
    if (uuid.length !== 16) {
        throw new Error('UUID must be exactly 16 bytes');
    }
    const uuidStr = formatUUID(uuid);
    return newAPIKey(prefix, uuidStr, opt);
}

/**
 * Parses an API key string into an APIKey type.
 */
export function parse(apikey: string): APIKey {
    if (!apikey) {
        throw new Error('invalid APIKey format');
    }
    const parts = apikey.split('_');
    if (parts.length !== 3) {
        throw new Error(`invalid APIKey format: expected 3 parts, got ${parts.length}`);
    }
    const [prefix, remainder, checksum] = parts;
    if (!prefix) {
        throw new Error('invalid prefix: cannot be empty');
    }
    if (remainder.length < Constants.KEY_LENGTH_WITHOUT_HYPHENS) {
        throw new Error('invalid Key format: insufficient length');
    }
    if (!isValidChecksum(checksum)) {
        throw new Error('invalid checksum format: must be 8 hexadecimal characters');
    }
    const keyPart = remainder.slice(0, Constants.KEY_LENGTH_WITHOUT_HYPHENS);
    const key = Key.parse(keyPart);
    const entropy = remainder.slice(Constants.KEY_LENGTH_WITHOUT_HYPHENS);
    const apiKey = new APIKey(
        prefix,
        key,
        entropy,
        checksum
    );

    const expectedChecksum = calculateChecksum(apiKey);
    if (checksum !== expectedChecksum) {
        throw new Error(`invalid checksum: expected ${expectedChecksum}, got ${checksum}`);
    }
    return apiKey;
}

/**
 * Generates random entropy of specified size
 */
function generateEntropy(size: EntropyBits): string {
    const bytes = Math.ceil(Number(size) * Constants.ENTROPY_BYTES_MULTIPLIER);
    const buffer = randomBytes(bytes);

    // Use SHA-256 for entropy generation
    const hash = createHash('sha256').update(buffer).digest();
    return encodeBase32Crockford(hash).slice(0, size);
}

/**
 * Encodes buffer as Base32-Crockford string
 */
function encodeBase32Crockford(buffer: Buffer): string {
    return c32encode(buffer.toString('hex')).toUpperCase();
}

/**
 * calculateChecksum generates an 8-character hexadecimal CRC32 checksum
 */
function calculateChecksum(apiKey: APIKey): string {
    const data = `${apiKey.prefix}_${apiKey.key.toString()}${apiKey.entropy}`;
    const checksum = crc32(data);
    return checksum.toString(16).toUpperCase().padStart(8, '0');
}

function applyOptions(opt: Option): Config {
    const config = { ...DefaultConfig };
    opt(config);
    return config;
}

/**
 * Formats a UUID buffer into a string
 */
function formatUUID(buffer: Buffer): string {
    const hex = buffer.toString('hex');
    return [
        hex.slice(0, 8),
        hex.slice(8, 12),
        hex.slice(12, 16),
        hex.slice(16, 20),
        hex.slice(20)
    ].join('-');
}

/**
 * Validates checksum format
 */
function isValidChecksum(checksum: string): boolean {
    if (checksum.length !== Constants.CHECKSUM_LENGTH) {
        return false;
    }
    return /^[0-9A-F]{8}$/.test(checksum);
}