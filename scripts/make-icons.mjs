// Draws public/icon-*.png from the same geometry as public/icon.svg: two rings on sage. Run: node scripts/make-icons.mjs
import fs from 'node:fs';
import zlib from 'node:zlib';

const BG = [0x4f, 0x6f, 0x5f], FG = [0xff, 0xfd, 0xf9];
const RINGS = [[191, 256], [321, 256]], R = 84, HALF = 7.5; // in a 512 box

const crcTable = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc = b => { let c = ~0; for (const x of b) c = crcTable[(c ^ x) & 255] ^ (c >>> 8); return ~c >>> 0; };
const chunk = (type, data) => { const len = Buffer.alloc(4), t = Buffer.from(type), sum = Buffer.alloc(4); len.writeUInt32BE(data.length); sum.writeUInt32BE(crc(Buffer.concat([t, data]))); return Buffer.concat([len, t, data, sum]); };

function png(size) {
  const k = 512 / size, N = 4, rows = [];
  for (let y = 0; y < size; y++) {
    const row = Buffer.alloc(1 + size * 3);
    for (let x = 0; x < size; x++) {
      let hit = 0;
      for (let i = 0; i < N; i++) for (let j = 0; j < N; j++) {
        const px = (x + (i + .5) / N) * k, py = (y + (j + .5) / N) * k;
        if (RINGS.some(([cx, cy]) => Math.abs(Math.hypot(px - cx, py - cy) - R) <= HALF)) hit++;
      }
      const a = hit / (N * N);
      for (let c = 0; c < 3; c++) row[1 + x * 3 + c] = Math.round(BG[c] + (FG[c] - BG[c]) * a);
    }
    rows.push(row);
  }
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4); ihdr[8] = 8; ihdr[9] = 2;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(Buffer.concat(rows))), chunk('IEND', Buffer.alloc(0))]);
}

const out = new URL('../public/', import.meta.url);
for (const [name, size] of [['icon-192.png', 192], ['icon-512.png', 512], ['apple-touch-icon.png', 180]]) fs.writeFileSync(new URL(name, out), png(size));
