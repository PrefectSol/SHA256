public class SHA256 
{
    private final short m_byteSize = 8;

    private int[] m_hash = 
    {
        0x6a09e667, 0xbb67ae85, 0x6a09e667, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    private int[] m_hashVariables = 
    {
        0x6a09e667, 0xbb67ae85, 0x6a09e667, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    private int[] m_dependedHashBytes = 
    { 
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    private String m_string;

    public SHA256()
    {
        this("Hello world!");
    }

    public SHA256(String string)
    {
        m_string = string;
    }

    public void setString(String string)
    {
        m_string = string;
    }

    public String getString()
    {
        return m_string;
    }

    public String getHash()
    {
        String hash = "";
        for (int hashValue : m_hash) 
        {
            hash += String.format("%02x", hashValue);
        }

        return hash;
    }

    public void compile()
    {
        byte[] stringChunk = get512Chunk();

        for (int i = 0; i < stringChunk.length; i += 64) 
        {
            int[] word = scheduleWord(stringChunk, i);

            for (int j = 0; j < 64; j++) 
            {
                final int S1 = Integer.rotateRight(m_hashVariables[4], 6) ^ Integer.rotateRight(m_hashVariables[4], 11) ^ Integer.rotateRight(m_hashVariables[4], 25);
                final int ch = (m_hashVariables[4] & m_hashVariables[5]) ^ (~m_hashVariables[4] & m_hashVariables[6]);
                final int temp1 = m_hashVariables[7] + S1 + ch + m_dependedHashBytes[j] + word[j];
                final int S0 = Integer.rotateRight(m_hashVariables[0], 2) ^ Integer.rotateRight(m_hashVariables[0], 13) ^ Integer.rotateRight(m_hashVariables[0], 22);
                final int maj = (m_hashVariables[0] & m_hashVariables[1]) ^ (m_hashVariables[0] & m_hashVariables[2]) ^ (m_hashVariables[1] & m_hashVariables[2]);
                final int temp2 = S0 + maj;

                m_hashVariables[7] = m_hashVariables[6];
                m_hashVariables[6] = m_hashVariables[5];
                m_hashVariables[5] = m_hashVariables[4];
                m_hashVariables[4] = m_hashVariables[3] + temp1;
                m_hashVariables[3] = m_hashVariables[2];
                m_hashVariables[2] = m_hashVariables[1];
                m_hashVariables[1] = m_hashVariables[0];
                m_hashVariables[0] = temp1 + temp2;
            }

            updateHash();
        }
    }

    private byte[] get512Chunk() 
    {
        byte[] stringBytes = m_string.getBytes();
        byte[] chunk = new byte[stringBytes.length + 1];

        System.arraycopy(stringBytes, 0, chunk, 0, stringBytes.length);
        chunk[stringBytes.length] = (byte)0x80;

        final int zerosSize = (448 / m_byteSize) - (stringBytes.length + m_byteSize + 1) % (512 / m_byteSize);
        byte[] zeros = new byte[zerosSize];
        chunk = concatBytes(chunk, zeros);

        byte[] lengthBytes = numberToBytes(stringBytes.length * m_byteSize);
        chunk = concatBytes(chunk, lengthBytes);

        return chunk;
    }

    private int[] scheduleWord(byte[] chunk, int chunkIndex)
    {
        int[] word = new int[64];

        for (int i = 0; i < 16; i++) 
        {
            word[i] = bytesToNumber(chunk, chunkIndex + i * 4);
        }

        for (int i = 16; i < 64; i++) 
        {
            final int s0 = Integer.rotateRight(word[i - 15], 7) ^ Integer.rotateRight(word[i - 15], 18) ^ (word[i - 15] >>> 3);
            final int s1 = Integer.rotateRight(word[i - 2], 17) ^ Integer.rotateRight(word[i - 2], 19) ^ (word[i - 2] >>> 10);
            
            word[i] = word[i - 16] + s0 + word[i - 7] + s1;
        }

        return word;
    }

    private void updateHash()
    {
        for(int i = 0; i < m_hash.length; i++)
        {
            m_hash[i] += m_hashVariables[i];
        }
    }

    private byte[] concatBytes(byte[] bytes1, byte[] bytes2) 
    {
        byte[] concatBytes = new byte[bytes1.length + bytes2.length];
        
        System.arraycopy(bytes1, 0, concatBytes, 0, bytes1.length);
        System.arraycopy(bytes2, 0, concatBytes, bytes1.length, bytes2.length);

        return concatBytes;
    }

    private int bytesToNumber(byte[] bytes, int start) 
    {
        int number = 0;
        try
        {
            number |= ((bytes[start + 0] & 0xFF) << 24);
            number |= ((bytes[start + 1] & 0xFF) << 16);
            number |= ((bytes[start + 2] & 0xFF) << 8);
            number |= ((bytes[start + 3] & 0xFF) << 0);
        }
        catch(Exception exception)
        {
            return number;
        }

        return number;
    }

    private byte[] numberToBytes(int number) 
    {
        byte[] bytes = new byte[m_byteSize];

        for (int i = 0; i < m_byteSize; i++) 
        {
            bytes[i] = (byte)((number >>> (56 - i * m_byteSize)) & 0xFF);
        }
        
        return bytes;
    }
}
