// Builds the world map once, offline, so the Pi only serves a static SVG.
//
//   cd tools && npm install && node build_world.mjs
//
// Shapes come from Natural Earth (public domain) via the world-atlas package.
// Country outlines use the 1:110m data, which is light enough for a Pi to serve
// but leaves out small countries like Singapore and Bahrain. Those get a dot
// instead, placed using the more detailed 1:50m data, so every country can still
// be shown when a story mentions it.
import { readFileSync, writeFileSync } from "node:fs";
import { feature } from "topojson-client";
import { geoArea, geoCentroid, geoNaturalEarth1, geoPath } from "d3-geo";
import countries from "i18n-iso-countries";

const WIDTH = 960;
const load = (name) => JSON.parse(readFileSync(new URL(`node_modules/world-atlas/${name}`, import.meta.url)));
const toFeatures = (topo) => feature(topo, topo.objects.countries).features;

const ANTARCTICA = "010";
const alpha2 = (f) => (f.id ? countries.numericToAlpha2(f.id) : undefined);

const outlines = toFeatures(load("countries-110m.json")).filter((f) => f.id !== ANTARCTICA && alpha2(f));
const detailed = toFeatures(load("countries-50m.json")).filter((f) => f.id !== ANTARCTICA && alpha2(f));

const projection = geoNaturalEarth1().fitWidth(WIDTH, { type: "FeatureCollection", features: outlines });
const path = geoPath(projection).digits(1);
const [[, y0], [, y1]] = path.bounds({ type: "FeatureCollection", features: outlines });
const height = Math.ceil(y1 - y0 + 4);
const top = Math.floor(y0) - 2;

// The centre of a country's largest piece of land, so France lands in Europe
// rather than being dragged towards French Guiana, and the US isn't pulled north by Alaska.
function anchor(f) {
  const polys = f.geometry.type === "MultiPolygon" ? f.geometry.coordinates : [f.geometry.coordinates];
  let best = null, bestArea = -1;
  for (const coordinates of polys) {
    const poly = { type: "Polygon", coordinates };
    const area = geoArea(poly);
    if (area > bestArea) { bestArea = area; best = poly; }
  }
  const [x, y] = projection(geoCentroid(best));
  return [Math.round(x * 10) / 10, Math.round(y * 10) / 10];
}

const points = {};
for (const f of detailed) points[alpha2(f)] = anchor(f);
for (const f of outlines) points[alpha2(f)] ??= anchor(f);

const drawn = new Set();
const shapes = outlines.map((f) => {
  const cc = alpha2(f);
  drawn.add(cc);
  return `<path class="country" data-cc="${cc}" d="${path(f)}"/>`;
});
const dots = Object.entries(points)
  .filter(([cc]) => !drawn.has(cc))
  .map(([cc, [x, y]]) => `<circle class="country dot" data-cc="${cc}" cx="${x}" cy="${y}" r="3.5"/>`);

const names = Object.fromEntries(Object.keys(points).map((cc) => [cc, countries.getName(cc, "en", { select: "alias" }) || countries.getName(cc, "en")]));

writeFileSync(
  new URL("../templates/_world.svg", import.meta.url),
  `<svg id="world" viewBox="0 ${top} ${WIDTH} ${height}" role="group" aria-label="World map of stories">\n` +
  `<g id="countries">\n${shapes.join("\n")}\n${dots.join("\n")}\n</g>\n<g id="links"></g>\n</svg>\n`,
);
writeFileSync(
  new URL("../templates/_world_points.json", import.meta.url),
  JSON.stringify({ points, names }) + "\n",
);
console.log(`${shapes.length} outlines, ${dots.length} dots, viewBox 0 ${top} ${WIDTH} ${height}`);
