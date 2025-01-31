import { newAPIKey, parse, Options, EntropyBits, Key, newAPIKeyFromBytes, APIKey } from '../src/index';

const UUID_KEY_PAIRS = {
  uuid: "d1756360-5da0-40df-9926-a76abff5601d",
  key: "38QARV01ET0G6Z2CJD9VA2ZZAR0X",
  keyWithHyphens: "38QARV0-1ET0G6Z-2CJD9VA-2ZZAR0X",
};

describe('ApiKey Module', () => {
  test('default newAPIKey is 160', () => {
    let apiKeyDefault = newAPIKey('MYPREFIX', 'd1756360-5da0-40df-9926-a76abff5601d');

    expect(apiKeyDefault.entropy.length == EntropyBits.Bits160)
  });

  test('entropy is identical incase using different EntropyBits', () => {
    let api160 = newAPIKey('MYPREFIX', 'd1756360-5da0-40df-9926-a76abff5601d');
    let api128 = newAPIKey('MYPREFIX', 'd1756360-5da0-40df-9926-a76abff5601d', Options.With128BitEntropy);
    let api256 = newAPIKey('MYPREFIX', 'd1756360-5da0-40df-9926-a76abff5601d', Options.With256BitEntropy);

    expect(api160.entropy == api128.entropy);
    expect(api160.entropy == api256.entropy);
  });

  test('encode uuid to key using Key', () => {
    const key = Key.encode(UUID_KEY_PAIRS.uuid, false);
    expect(key.toString() == UUID_KEY_PAIRS.key)
  });

  test('should throw exception in case prefix is empty', () => {
    try {
      newAPIKey('', 'd1756360-5da0-40df-9926-a76abff5601d');
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe('prefix cannot be empty')
    }
  });

  test('toString() reproduce same key as origin', () => {
    const key = "MYPREFIX_38QARV01ET0G6Z2CJD9VA2ZZAR0XVNBP1HX5VMAJDWWHK7TZJ_E4809599"
    const apiKey = parse(key);

    expect(apiKey.toString() == key)
  });

  test('wrong checksum', () => {
    const key = "MYPREFIX_38QARV01ET0G6Z2CJD9VA2ZZAR0XVNBP1HX5VMAJDWWHK7TZJJ_E4809523"
    try {
      const apiKey = parse(key);
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toContain('invalid checksum')
    }
  });

  test('wrong key', () => {
    const keyStr = "38QARV01ET0G6Z2CJD9VA2ZZAR0XZ"
    try {
      const key = new Key(keyStr);
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toContain('Invalid Key format')
    }
  });

  test('wrong apikey format', () => {
    const key = "MYPREFIX_38QARV01ET0G6Z2CJD9VA2ZZAR0XVNBP1HX5VMAJDWWHK7TZJ"
    try {
      const apiKey = parse(key);
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toContain('invalid APIKey format: expected 3 parts')
    }
  });

  test('wrong apikey format', () => {
    const key = ""
    try {
      const apiKey = parse(key);
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toContain('invalid APIKey format')
    }
  });

  test('wrong apikey format: prefix is empty', () => {
    const key = "_38QARV01ET0G6Z2CJD9VA2ZZAR0XVNBP1HX5VMAJDWWHK7TZJ_E4809523"
    try {
      const apiKey = parse(key);
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe('invalid prefix: cannot be empty')
    }
  });

  test('create api by uuid bytes: error case', () => {
    try {
      newAPIKeyFromBytes('MYPREFIX', Buffer.from("d1756360-5da0-40df-9926-a76abff5601d", "hex"));
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
    }
  });

  test('create api by uuid bytes: normal case', () => {
    let apiKey = newAPIKeyFromBytes('MYPREFIX', Buffer.from("d17563605da040df9926a76abff5601d", "hex"));
    expect(apiKey).toBeInstanceOf(APIKey);
  });

  test('decode key to uuid', () => {
    const key = new Key(UUID_KEY_PAIRS.key);
    const uuid = key.toUUID();

    const keyWithHyphens = new Key(UUID_KEY_PAIRS.keyWithHyphens);
    const uuid2 = keyWithHyphens.toUUID();

    expect(uuid == UUID_KEY_PAIRS.uuid);
    expect(uuid2 == UUID_KEY_PAIRS.uuid);
  });

  test('encode using invalid uuid', () => {
    try {
      newAPIKey('MYPREFIX', 'd1756360-5da0-40df-9926-a76abff5601');
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe('Invalid UUID length')
    }
  });

  test('invalid checksum format', () => {
    try {
      const key = "MYPREFIX_38QARV01ET0G6Z2CJD9VA2ZZAR0XVNBP1HX5VMAJDWWHK7TZJJ_E480952332"
      const apiKey = parse(key);
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe('invalid checksum format: must be 8 hexadecimal characters')
    }
  });
});