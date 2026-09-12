//frontend/utils/globalSearch.js

const normalize = (value = "") =>
  value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();

const editDistance = (left, right) => {
  // Fast reject: if length difference alone exceeds threshold, skip computation
  if (Math.abs(left.length - right.length) > 1) return 999;

  const previous = Array.from(
    { length: right.length + 1 },
    (_, index) => index,
  );
  for (let row = 1; row <= left.length; row += 1) {
    let diagonal = previous[0];
    previous[0] = row;
    for (let column = 1; column <= right.length; column += 1) {
      const current = previous[column];
      previous[column] = Math.min(
        previous[column] + 1,
        previous[column - 1] + 1,
        diagonal + (left[row - 1] === right[column - 1] ? 0 : 1),
      );
      diagonal = current;
    }
  }
  return previous[right.length];
};

const fieldScore = (query, field, weight) => {
  const text = normalize(field);
  if (!text) return 0;
  if (text === query) return 1000 * weight;
  if (text.startsWith(query)) return 750 * weight;
  if (text.includes(query)) return 500 * weight;

  const tokens = text.split(" ");
  const queryTokens = query.split(" ");
  const matchedTokens = queryTokens.filter((queryToken) =>
    tokens.some(
      (token) => token.startsWith(queryToken) || token.includes(queryToken),
    ),
  );
  if (matchedTokens.length === queryTokens.length) return 350 * weight;

  if (
    query.length >= 3 &&
    tokens.some((token) => editDistance(query, token) <= 1)
  ) {
    return 150 * weight;
  }
  return 0;
};

export function searchIndex(index, value, limit = 8) {
  const query = normalize(value);
  if (!query) return [];

  return index
    .map((item) => {
      const title = item.title;
      const pageTitle = item.pageTitle || item.title;
      const score = Math.max(
        fieldScore(query, title, item.type === "page" ? 1.4 : 1.2),
        fieldScore(query, pageTitle, 1.15),
        fieldScore(query, item.description, 0.7),
        ...(item.keywords || []).map((keyword) =>
          fieldScore(query, keyword, 0.9),
        ),
      );
      return { ...item, score };
    })
    .filter((item) => item.score > 0)
    .sort(
      (left, right) =>
        right.score - left.score || left.title.localeCompare(right.title),
    )
    .slice(0, limit);
}

export function highlightMatch(text, query) {
  const terms = normalize(query).split(" ").filter(Boolean);
  if (!terms.length) return [text];
  const expression = new RegExp(
    `(${terms.map((term) => term.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&")).join("|")})`,
    "ig",
  );
  return String(text).split(expression);
}
