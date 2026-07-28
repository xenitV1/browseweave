const RELEASE_VERSION_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(alpha|beta|rc)\.(0|[1-9]\d*))?$/u;

export function parseReleaseVersion(value) {
  if (typeof value !== "string") {
    throw new Error("The release version must be a string.");
  }
  const match = RELEASE_VERSION_PATTERN.exec(value);
  if (!match) {
    throw new Error("The release version must be stable SemVer or alpha.N, beta.N, or rc.N.");
  }
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  const channel = match[4] ?? "stable";
  const sequence = match[5] === undefined ? undefined : Number(match[5]);
  if ([major, minor, patch].some((component) => component > 65_535)) {
    throw new Error("Release version components must fit the browser-extension range 0..65535.");
  }
  if (sequence !== undefined && sequence > 9_999) {
    throw new Error("Prerelease sequence must be between 0 and 9999.");
  }
  return { major, minor, patch, channel, sequence };
}

/**
 * Browser stores require one to four numeric components. The fourth component
 * preserves alpha < beta < rc < stable ordering while version_name keeps the
 * public SemVer visible to people.
 */
export function browserExtensionVersion(releaseVersion) {
  const parsed = parseReleaseVersion(releaseVersion);
  const sequence = parsed.sequence ?? 0;
  const build = parsed.channel === "alpha"
    ? 1 + sequence
    : parsed.channel === "beta"
      ? 10_001 + sequence
      : parsed.channel === "rc"
        ? 20_001 + sequence
        : 65_535;
  return `${parsed.major}.${parsed.minor}.${parsed.patch}.${build}`;
}

/** Keep prereleases off npm's latest tag while preserving their explicit channel. */
export function releaseDistTag(releaseVersion) {
  const { channel } = parseReleaseVersion(releaseVersion);
  return channel === "stable" ? "latest" : channel;
}
