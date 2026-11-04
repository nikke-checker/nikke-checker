using System;
using System.Collections.Generic;
using System.IO;

namespace NikkeChecker
{
    /// <summary>
    /// LevelDB 테이블(.ldb) 읽기 (MotherSphere 0.4.1). LevelDB 는 .log 의 기록을 나중에 .ldb 로 옮기는데,
    /// .ldb 블록은 Snappy 로 압축되고 키 앞부분이 앞 키와 공유되어 그냥 글자 검색으로는 k2f.agent 를 놓칠 수 있다.
    /// 블록을 풀고 키를 온전히 복원한 "키+값" 바이트를 돌려준다. 형식이 맞지 않으면 빈 결과.
    /// </summary>
    public static class LevelDb
    {
        private const ulong TableMagic = 0xdb4775248b80fb57UL;

        public static byte[] ExpandTable(byte[] file)
        {
            try
            {
                if (file == null || file.Length < 48) return Array.Empty<byte>();
                if (BitConverter.ToUInt64(file, file.Length - 8) != TableMagic) return Array.Empty<byte>();
                int p = file.Length - 48;
                ReadVarint(file, ref p); ReadVarint(file, ref p);   // metaindex 핸들
                long idxOff = (long)ReadVarint(file, ref p), idxSize = (long)ReadVarint(file, ref p);
                var index = ReadBlock(file, idxOff, idxSize);
                if (index == null) return Array.Empty<byte>();

                var output = new MemoryStream();
                foreach (var (_, value) in Entries(index))
                {
                    int vp = 0;
                    long off = (long)ReadVarint(value, ref vp), size = (long)ReadVarint(value, ref vp);
                    var block = ReadBlock(file, off, size);
                    if (block == null) continue;
                    foreach (var (k, v) in Entries(block))
                    {
                        output.Write(k, 0, k.Length); output.WriteByte(0);
                        output.Write(v, 0, v.Length); output.WriteByte(0);
                    }
                    if (output.Length > 256L * 1024 * 1024) break;
                }
                return output.ToArray();
            }
            catch { return Array.Empty<byte>(); }
        }

        private static byte[] ReadBlock(byte[] file, long off, long size)
        {
            if (off < 0 || size < 0 || off + size + 5 > file.Length) return null;
            var raw = new byte[size];
            Buffer.BlockCopy(file, (int)off, raw, 0, (int)size);
            byte type = file[off + size];   // 0 = 압축 없음, 1 = Snappy
            if (type == 0) return raw;
            if (type == 1) return Snappy(raw);
            return null;
        }

        /// <summary>블록 안의 (키, 값). 키는 앞 키와 공유한 부분까지 붙여 온전히 복원한다.</summary>
        private static IEnumerable<(byte[], byte[])> Entries(byte[] block)
        {
            if (block.Length < 4) yield break;
            int restarts = BitConverter.ToInt32(block, block.Length - 4);
            int limit = block.Length - 4 - restarts * 4;
            if (restarts < 0 || limit < 0) yield break;
            var key = new List<byte>();
            int p = 0;
            while (p < limit)
            {
                int shared = (int)ReadVarint(block, ref p), unshared = (int)ReadVarint(block, ref p), vlen = (int)ReadVarint(block, ref p);
                if (shared > key.Count || unshared < 0 || vlen < 0 || p + unshared + vlen > limit) yield break;
                key.RemoveRange(shared, key.Count - shared);
                for (int i = 0; i < unshared; i++) key.Add(block[p + i]);
                p += unshared;
                var v = new byte[vlen];
                Buffer.BlockCopy(block, p, v, 0, vlen);
                p += vlen;
                yield return (key.ToArray(), v);
            }
        }

        private static ulong ReadVarint(byte[] b, ref int p)
        {
            ulong r = 0; int shift = 0;
            while (p < b.Length && shift < 64)
            {
                byte x = b[p++];
                r |= (ulong)(x & 0x7F) << shift;
                if ((x & 0x80) == 0) return r;
                shift += 7;
            }
            throw new InvalidDataException("varint");
        }

        /// <summary>Snappy 블록 압축 해제.</summary>
        public static byte[] Snappy(byte[] src)
        {
            int p = 0;
            long len = (long)ReadVarint(src, ref p);
            if (len < 0 || len > 64L * 1024 * 1024) throw new InvalidDataException("snappy length");
            var dst = new byte[len];
            int d = 0;
            while (p < src.Length)
            {
                byte tag = src[p++];
                int type = tag & 3;
                if (type == 0)
                {
                    int n = tag >> 2;
                    if (n >= 60)
                    {
                        int bytes = n - 59; n = 0;
                        for (int i = 0; i < bytes; i++) n |= src[p++] << (8 * i);
                    }
                    n += 1;
                    if (p + n > src.Length || d + n > dst.Length) throw new InvalidDataException("snappy literal");
                    Buffer.BlockCopy(src, p, dst, d, n);
                    p += n; d += n;
                    continue;
                }
                int length, offset;
                if (type == 1) { length = ((tag >> 2) & 7) + 4; offset = ((tag >> 5) << 8) | src[p++]; }
                else if (type == 2) { length = (tag >> 2) + 1; offset = src[p] | (src[p + 1] << 8); p += 2; }
                else { length = (tag >> 2) + 1; offset = src[p] | (src[p + 1] << 8) | (src[p + 2] << 16) | (src[p + 3] << 24); p += 4; }
                if (offset <= 0 || offset > d || d + length > dst.Length) throw new InvalidDataException("snappy copy");
                for (int i = 0; i < length; i++, d++) dst[d] = dst[d - offset];   // 겹치는 복사 허용
            }
            if (d != dst.Length) throw new InvalidDataException("snappy size");
            return dst;
        }
    }
}
