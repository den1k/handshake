// Draws public/icon-*.png: the H mark set in a black station sign (white top rule, a blue and an orange line,
// a white transfer station across them), full bleed so it can be masked. Run: node scripts/make-icons.mjs
import fs from 'node:fs';
import zlib from 'node:zlib';

const BLACK = [0, 0, 0], WHITE = [255, 255, 255], BLUE = [0x00, 0x80, 0xc7], ORANGE = [0xf3, 0x84, 0x00];
// In a 512 box: the sign's rule, the two lines running off the bottom, and the station (a pill) across them.
const RULE = [72, 94], LINES = [[[142, 204], BLUE], [[308, 370], ORANGE]], PILL = { x0: 121, x1: 391, cy: 256, r: 47 };

function colorAt(px, py) {
  const { x0, x1, cy, r } = PILL;
  const cx = Math.min(Math.max(px, x0 + r), x1 - r);
  if (Math.hypot(px - cx, py - cy) <= r) return WHITE;
  if (py >= RULE[0] && py < RULE[1]) return WHITE;
  for (const [[a, b], c] of LINES) if (px >= a && px < b && py >= RULE[1]) return c;
  return BLACK;
}

const crcTable = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc = b => { let c = ~0; for (const x of b) c = crcTable[(c ^ x) & 255] ^ (c >>> 8); return ~c >>> 0; };
const chunk = (type, data) => { const len = Buffer.alloc(4), t = Buffer.from(type), sum = Buffer.alloc(4); len.writeUInt32BE(data.length); sum.writeUInt32BE(crc(Buffer.concat([t, data]))); return Buffer.concat([len, t, data, sum]); };

function png(size) {
  const k = 512 / size, N = 4, rows = [];
  for (let y = 0; y < size; y++) {
    const row = Buffer.alloc(1 + size * 3);
    for (let x = 0; x < size; x++) {
      const sum = [0, 0, 0];
      for (let i = 0; i < N; i++) for (let j = 0; j < N; j++) {
        const c = colorAt((x + (i + .5) / N) * k, (y + (j + .5) / N) * k);
        for (let ch = 0; ch < 3; ch++) sum[ch] += c[ch];
      }
      for (let ch = 0; ch < 3; ch++) row[1 + x * 3 + ch] = Math.round(sum[ch] / (N * N));
    }
    rows.push(row);
  }
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4); ihdr[8] = 8; ihdr[9] = 2;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(Buffer.concat(rows))), chunk('IEND', Buffer.alloc(0))]);
}

const out = new URL('../public/', import.meta.url);
for (const [name, size] of [['icon-192.png', 192], ['icon-512.png', 512], ['apple-touch-icon.png', 180]]) fs.writeFileSync(new URL(name, out), png(size));
