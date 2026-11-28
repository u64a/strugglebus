using System.Buffers.Binary;
using System.Text;

namespace StruggleBusMonitor;

/// <summary>
/// What an OpenSSH signature file (SSHSIG) says about itself: which key made it, for which
/// namespace, and, for a hardware key, what the key attests about the person (the flags byte).
/// Reading these proves nothing; <c>ssh-keygen -Y verify</c> does the proving. They are read so
/// that the app can refuse a signature before it is published: one made by a key this PC does not
/// hold, for another purpose, or by a hardware key that was not asked for touch and PIN.
/// </summary>
internal sealed record SshSignature(string KeyType, string KeyBase64, string Namespace, string HashAlgorithm, byte? Flags)
{
    public const string Begin = "-----BEGIN SSH SIGNATURE-----";
    public const string End = "-----END SSH SIGNATURE-----";

    /// <summary>The longest signature file read. A hardware-key signature is a few hundred characters.</summary>
    public const int MaxLength = 4200;

    private static readonly string[] HardwareKeyTypes = ["sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"];

    /// <summary>The signature's own description, or null when the text is not exactly one well-formed signature file.</summary>
    public static SshSignature? Read(string? text)
    {
        if (Unwrap(text) is not { } blob) return null;
        try
        {
            return FromBlob(blob);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>The bytes between the two marker lines, or null when the markers or the base64 are wrong.</summary>
    private static byte[]? Unwrap(string? text)
    {
        if (text is null || text.Length > MaxLength || Inside(text) is not { } encoded) return null;
        var blob = new byte[text.Length];
        return Convert.TryFromBase64String(encoded, blob, out var written) ? blob[..written] : null;
    }

    /// <summary>What is between the two marker lines, joined, or null when either marker is missing.</summary>
    private static string? Inside(string text)
    {
        var lines = text.Replace("\r\n", "\n").Trim('\n').Split('\n');
        return lines.Length >= 3 && lines[0] == Begin && lines[^1] == End ? string.Concat(lines[1..^1]) : null;
    }

    private static SshSignature FromBlob(byte[] blob)
    {
        var reader = new SshReader(blob);
        reader.Expect("SSHSIG"u8);
        if (reader.Number() != 1) throw new FormatException();
        var key = reader.Bytes();
        var purpose = reader.Text();
        reader.Bytes();
        var hash = reader.Text();
        var signature = reader.Bytes();
        reader.ExpectEnd();

        var keyType = new SshReader(key).Text();
        return new SshSignature(keyType, Convert.ToBase64String(key), purpose, hash, FlagsOf(keyType, signature));
    }

    /// <summary>
    /// A hardware key's signature ends with one flags byte and a four-byte counter. Bit 0 says a
    /// person touched the key, bit 2 that they were verified (the PIN). Other keys have neither.
    /// </summary>
    private static byte? FlagsOf(string keyType, byte[] signature)
    {
        var reader = new SshReader(signature);
        if (!SignatureTypeFits(keyType, reader.Text())) throw new FormatException();
        reader.Bytes();
        if (!HardwareKeyTypes.Contains(keyType))
        {
            reader.ExpectEnd();
            return null;
        }

        var flags = reader.Byte();
        reader.Number();
        reader.ExpectEnd();
        return flags;
    }

    /// <summary>A signature names its key's type, except that an RSA key signs as rsa-sha2-256 or rsa-sha2-512.</summary>
    private static bool SignatureTypeFits(string keyType, string signatureType) =>
        signatureType == keyType || (keyType == "ssh-rsa" && signatureType is "rsa-sha2-256" or "rsa-sha2-512");

    /// <summary>Reads OpenSSH's wire format: four-byte big-endian lengths before every string. Anything short or over is a <see cref="FormatException"/>.</summary>
    private ref struct SshReader(ReadOnlySpan<byte> bytes)
    {
        private ReadOnlySpan<byte> _rest = bytes;

        private ReadOnlySpan<byte> Take(int count)
        {
            if (count < 0 || count > _rest.Length) throw new FormatException();
            var taken = _rest[..count];
            _rest = _rest[count..];
            return taken;
        }

        public void Expect(ReadOnlySpan<byte> marker)
        {
            if (!Take(marker.Length).SequenceEqual(marker)) throw new FormatException();
        }

        public uint Number() => BinaryPrimitives.ReadUInt32BigEndian(Take(4));

        public byte Byte() => Take(1)[0];

        public byte[] Bytes()
        {
            var length = Number();
            if (length > int.MaxValue) throw new FormatException();
            return Take((int)length).ToArray();
        }

        public string Text()
        {
            var bytes = Bytes();
            if (bytes.Any(value => value is < 0x21 or > 0x7E)) throw new FormatException();
            return Encoding.ASCII.GetString(bytes);
        }

        public readonly void ExpectEnd()
        {
            if (!_rest.IsEmpty) throw new FormatException();
        }
    }
}
