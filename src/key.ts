import { Constants } from './types';
import { c32encode, c32decode } from 'c32check';

export class Key {
    private readonly value: string;

    constructor(value: string) {
        if (!Key.isValid(value)) {
            throw new Error('Invalid Key format');
        }
        this.value = value;
    }

    /**
     * Creates a Key from a string value with validation
     */
    static parse(key: string): Key {
        if (!Key.isValid(key)) {
            throw new Error('Invalid UUID Key');
        }
        return new Key(key);
    }

    /**
     * Gets the string representation of the key
     */
    toString(): string {
        return this.value;
    }

    /**
     * Validates if a string meets the key format requirements
     */
    static isValid(key: string): boolean {
        const length = key.length;
        if (length === Constants.KEY_LENGTH_WITH_HYPHENS) {
            // Check hyphens position
            if (key[7] !== '-' || key[15] !== '-' || key[23] !== '-') {
                return false;
            }
            // Validate each part between hyphens
            return this.isValidPart(key.slice(0, 7)) &&
                this.isValidPart(key.slice(8, 15)) &&
                this.isValidPart(key.slice(16, 23)) &&
                this.isValidPart(key.slice(24, 31));
        }

        if (length === Constants.KEY_LENGTH_WITHOUT_HYPHENS) {
            // Validate each part without hyphens
            return this.isValidPart(key.slice(0, 7)) &&
                this.isValidPart(key.slice(7, 14)) &&
                this.isValidPart(key.slice(14, 21)) &&
                this.isValidPart(key.slice(21, 28));
        }

        return false;
    }

    /**
     * Validates a single part of the key
     */
    private static isValidPart(part: string): boolean {
        if (part.length !== Constants.KEY_PART_LENGTH) {
            return false;
        }

        // Check each character is valid Base32-Crockford
        return ![...part].some(c => {
            const code = c.charCodeAt(0);
            return code > 90 || // Above 'Z'
                (code < 48 || (code > 57 && code < 65)) || // Not 0-9 or A-Z
                c === 'I' || c === 'L' || c === 'O' || c === 'U'; // Invalid in Crockford base32
        });
    }

    /**
     * Converts the key to a UUID string
     */
    toUUID(): string {
        if (!Key.isValid(this.value)) {
            throw new Error('Invalid UUID key');
        }
        return this.decode();
    }

    /**
     * Decodes the key to its original UUID format
     */
    private decode(): string {
        const parts = this.getParts();
        const decoded = parts.map(part => c32decode(part.toLowerCase()));

        return [
            decoded[0],
            '-',
            decoded[1].substring(0, 4),
            '-',
            decoded[1].substring(4),
            '-',
            decoded[2].substring(0, 4),
            '-',
            decoded[2].substring(4),
            decoded[3]
        ].join('');
    }

    /**
     * Gets the parts of the key based on whether it has hyphens
     */
    private getParts(): string[] {
        const hasHyphens = this.value.length === Constants.KEY_LENGTH_WITH_HYPHENS;

        if (hasHyphens) {
            return [
                this.value.slice(0, 7),
                this.value.slice(8, 15),
                this.value.slice(16, 23),
                this.value.slice(24, 31)
            ];
        }

        return [
            this.value.slice(0, 7),
            this.value.slice(7, 14),
            this.value.slice(14, 21),
            this.value.slice(21, 28)
        ];
    }

    private static encodePart(hex: string) {
        const buf = Buffer.from(hex, 'hex');
        const encoded = c32encode(buf.toString('hex'));
        return encoded.padStart(7, '0').toUpperCase();
    }

    /**
     * Creates a Key from a UUID string
     */
    static encode(uuid: string, withHyphens: boolean = true): Key {
        if (uuid.length !== Constants.UUID_LENGTH) {
            throw new Error('Invalid UUID length');
        }

        const parts = [
            this.encodePart(uuid.slice(0, 8)),
            this.encodePart(uuid.slice(9, 13) + uuid.slice(14, 18)),
            this.encodePart(uuid.slice(19, 23) + uuid.slice(24, 28)),
            this.encodePart(uuid.slice(28, 36)),
        ];

        const value = withHyphens ? parts.join('-') : parts.join('');
        return new Key(value);
    }
}