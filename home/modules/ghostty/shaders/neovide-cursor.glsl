// Neovide-inspired cursor smear + pixiedust for Ghostty 1.3+.
// Equations/defaults: neovide/src/renderer/{animation_utils,cursor_renderer/*}.rs.
// This is a stateless approximation; see docs/ghostty-cursor.md.

// Metal has a downward Y axis; set -1.0 for Ghostty's OpenGL renderer.
#ifndef PIXIE_Y_SIGN
#define PIXIE_Y_SIGN 1.0
#endif

const float ANIMATION_LENGTH = 0.150;
const float SHORT_ANIMATION_LENGTH = 0.040;
const float TRAIL_SIZE = 1.0;
const float PARTICLE_LIFETIME = 0.5;
const float PARTICLE_DENSITY = 0.7;
const float PARTICLE_SPEED = 10.0;
const float PARTICLE_CURL = 1.0;
const float PARTICLE_OPACITY = 200.0 / 255.0;
const int MAX_PARTICLES = 96;

float random01(float seed) {
    return fract(sin(seed * 127.1 + 311.7) * 43758.5453);
}

vec2 centerOf(vec4 cursor) {
    // Ghostty reports the -X,+Y edge, on both Metal and OpenGL.
    return cursor.xy + cursor.zw * vec2(0.5, -0.5);
}

float boxDistance(vec2 point, vec2 center, vec2 halfSize) {
    vec2 q = abs(point - center) - halfSize;
    return length(max(q, 0.0)) + min(max(q.x, q.y), 0.0);
}

float quadCoverage(vec2 p, vec2 a, vec2 b, vec2 c, vec2 d) {
    vec2 corners[4] = vec2[4](a, b, c, d);
    float distanceSquared = 1e20;
    bool inside = false;
    for (int i = 0; i < 4; ++i) {
        vec2 start = corners[i];
        vec2 end = corners[(i + 1) % 4];
        vec2 edge = end - start;
        vec2 delta = p - start;
        vec2 nearest = delta - edge * clamp(dot(delta, edge) /
                                            max(dot(edge, edge), 0.0001), 0.0, 1.0);
        distanceSquared = min(distanceSquared, dot(nearest, nearest));
        if ((start.y > p.y) != (end.y > p.y)) {
            if (p.x < start.x + edge.x * (p.y - start.y) / edge.y) inside = !inside;
        }
    }
    return smoothstep(-0.5, 0.5, sqrt(distanceSquared) * (inside ? 1.0 : -1.0));
}

float springProgress(float age, float duration, float distanceToTravel) {
    if (duration <= 0.0001) return 1.0;
    float omega = 4.0 / duration;
    float residual = (1.0 + omega * age) * exp(-omega * age);
    // Match Neovide's subpixel spring rest threshold.
    if (residual * distanceToTravel < 0.01) return 1.0;
    return 1.0 - residual;
}

vec2 animatedCorner(vec2 corner, vec2 previous, vec2 current,
                    vec2 previousSize, vec2 currentSize,
                    vec2 direction, float age, bool shortJump) {
    float alignment = dot(direction, corner) /
                      max(abs(direction.x) + abs(direction.y), 0.001);
    alignment = alignment * 0.5 + 0.5;
    float duration = shortJump ? SHORT_ANIMATION_LENGTH : ANIMATION_LENGTH;
    duration *= 1.0 - clamp(TRAIL_SIZE, 0.0, 1.0) * alignment;
    vec2 start = previous + corner * previousSize * 0.5;
    vec2 end = current + corner * currentSize * 0.5;
    return mix(start, end, springProgress(age, duration, length(end - start)));
}

vec2 particleDisplacement(vec2 velocity, float rotation, float age) {
    // Analytic integral of a velocity rotating at constant angular speed.
    if (abs(rotation) < 0.001) return velocity * age;
    float angle = rotation * age;
    vec2 perpendicular = vec2(-velocity.y, velocity.x);
    return (velocity * sin(angle) + perpendicular * (1.0 - cos(angle))) / rotation;
}

void over(inout vec4 base, vec3 color, float opacity) {
    // Preserve premultiplied transparency, including the 85% terminal background.
    base = vec4(color * opacity + base.rgb * (1.0 - opacity),
                opacity + base.a * (1.0 - opacity));
}

void mainImage(out vec4 fragColor, in vec2 fragCoord) {
    fragColor = texture(iChannel0, fragCoord / iResolution.xy);
    float age = max(iTime - iTimeCursorChange, 0.0);
    if (iFocus == 0 || iCursorVisible == 0 ||
        iCurrentCursorStyle == CURSORSTYLE_BLOCK_HOLLOW ||
        iCurrentCursorStyle == CURSORSTYLE_LOCK ||
        min(iCurrentCursor.z, iCurrentCursor.w) <= 0.0 ||
        min(iPreviousCursor.z, iPreviousCursor.w) <= 0.0 ||
        iTimeCursorChange < iTimeFocus || age > 1.0) return;

    vec2 current = centerOf(iCurrentCursor);
    vec2 previous = centerOf(iPreviousCursor);
    vec2 travel = current - previous;
    float distanceTravelled = length(travel);
    // Ignore color-only updates and shape changes at the same cursor anchor.
    if (length(iCurrentCursor.xy - iPreviousCursor.xy) < 0.5 ||
        distanceTravelled < 0.5) return;

    float cellHeight = max(iCurrentCursor.w, iPreviousCursor.w);
    // Bar/underline uniforms describe the glyph, not its enclosing terminal cell.
    float cellWidth = max(iCurrentCursor.z, cellHeight * 0.5);
    if (iCurrentCursorStyle == CURSORSTYLE_UNDERLINE &&
        iPreviousCursorStyle == CURSORSTYLE_UNDERLINE) cellHeight = cellWidth * 2.0;
    vec2 margin = max(iCurrentCursor.zw, iPreviousCursor.zw) +
                  vec2(PARTICLE_SPEED * 4.5 * PARTICLE_LIFETIME + cellWidth);
    vec2 boundsMin = min(previous, current) - margin;
    vec2 boundsMax = max(previous, current) + margin;
    if (any(lessThan(fragCoord, boundsMin)) ||
        any(greaterThan(fragCoord, boundsMax))) return;

    // Keep Ghostty's real cursor and its glyph intact: a post-process cannot
    // reconstruct the original colored text underneath an already drawn cursor.
    if (boxDistance(fragCoord, current, iCurrentCursor.zw * 0.5) <= 0.5) return;

    vec2 direction = travel / distanceTravelled;
    bool shortJump = abs(travel.x) <= 2.001 * cellWidth && abs(travel.y) < 0.5;
    vec2 a = animatedCorner(vec2(-1.0, -1.0), previous, current,
        iPreviousCursor.zw, iCurrentCursor.zw, direction, age, shortJump);
    vec2 b = animatedCorner(vec2( 1.0, -1.0), previous, current,
        iPreviousCursor.zw, iCurrentCursor.zw, direction, age, shortJump);
    vec2 c = animatedCorner(vec2( 1.0,  1.0), previous, current,
        iPreviousCursor.zw, iCurrentCursor.zw, direction, age, shortJump);
    vec2 d = animatedCorner(vec2(-1.0,  1.0), previous, current,
        iPreviousCursor.zw, iCurrentCursor.zw, direction, age, shortJump);
    float smear = quadCoverage(fragCoord, a, b, c, d);
    over(fragColor, iCurrentCursorColor.rgb, smear * iCurrentCursorColor.a);

    if (age >= PARTICLE_LIFETIME) return;
    float seed = dot(previous, vec2(0.1031, 0.11369)) +
                 dot(current, vec2(0.13787, 0.09987)) +
                 mod(iTimeCursorChange, 100.0) * 11.17;
    // Stochastic rounding preserves density without a persistent emission remainder.
    int count = int(min(floor(distanceTravelled / cellHeight * PARTICLE_DENSITY +
                              random01(seed)), float(MAX_PARTICLES)));
    for (int i = 0; i < MAX_PARTICLES; ++i) {
        if (i >= count) break;
        float id = float(i);
        float lifetime = (id + 1.0) / float(count) * PARTICLE_LIFETIME;
        if (age >= lifetime) continue;
        float particleSeed = seed + id * 17.31;
        vec2 randomDirection = vec2(random01(particleSeed + 1.0),
                                    random01(particleSeed + 2.0)) * 2.0 - 1.0;
        randomDirection /= max(length(randomDirection), 0.001);
        vec2 velocity = vec2(randomDirection.x * 0.5,
                             (0.4 + abs(randomDirection.y)) * PIXIE_Y_SIGN) *
                        3.0 * PARTICLE_SPEED;
        float rotation = (random01(particleSeed + 3.0) - 0.5) *
                         1.57079632679 * PARTICLE_CURL * PIXIE_Y_SIGN;
        vec2 position = mix(previous, current, random01(particleSeed + 4.0)) +
                        vec2(0.0, cellHeight * 0.5 * PIXIE_Y_SIGN) +
                        particleDisplacement(velocity, rotation, age);
        float square = boxDistance(fragCoord, position, vec2(cellWidth * 0.1));
        float opacity = (lifetime - age) / PARTICLE_LIFETIME * PARTICLE_OPACITY;
        over(fragColor, iCurrentCursorColor.rgb,
             (1.0 - smoothstep(-0.5, 0.5, square)) * opacity * iCurrentCursorColor.a);
    }
}
