'use strict';

var crypto = require('crypto');
var superjson = require('superjson');
var zod = require('zod');

function _interopDefault (e) { return e && e.__esModule ? e : { default: e }; }

var crypto__default = /*#__PURE__*/_interopDefault(crypto);
var superjson__default = /*#__PURE__*/_interopDefault(superjson);

// src/codec/base64Url.ts
var base64UrlCodec = {
  encode: (s) => Buffer.from(s, "utf8").toString("base64url"),
  decode: (s) => Buffer.from(s, "base64url").toString("utf8")
};

// src/codec/codec.ts
var codecPipe = (...codecs) => ({
  encode: (value) => codecs.reduce((acc, codec) => acc.then((v) => codec.encode(v)), Promise.resolve(value)),
  decode: (value) => codecs.reduceRight((acc, codec) => acc.then((v) => codec.decode(v)), Promise.resolve(value))
});
var createAesCodec = (secret) => {
  const VERSION = Buffer.from([1]);
  const SALT_LEN = 16;
  const IV_LEN = 12;
  const TAG_LEN = 16;
  const KEY_LEN = 32;
  const SCRYPT_N = 1 << 15, SCRYPT_r = 8, SCRYPT_p = 1;
  const kdf = (salt) => new Promise((resolve, reject) => {
    crypto__default.default.scrypt(
      secret,
      salt,
      KEY_LEN,
      { N: SCRYPT_N, r: SCRYPT_r, p: SCRYPT_p, maxmem: 256 * 1024 * 1024 },
      (err, dk) => err ? reject(err) : resolve(dk)
    );
  });
  const concat = (...parts) => Buffer.concat(parts);
  return {
    encode: async (plain) => {
      const salt = crypto__default.default.randomBytes(SALT_LEN);
      const key = await kdf(salt);
      const iv = crypto__default.default.randomBytes(IV_LEN);
      try {
        const cipher = crypto__default.default.createCipheriv("aes-256-gcm", key, iv);
        const aad = concat(VERSION, salt);
        cipher.setAAD(aad, {
          plaintextLength: Buffer.byteLength(plain, "utf8")
        });
        const ciphertext = concat(cipher.update(plain, "utf8"), cipher.final());
        const tag = cipher.getAuthTag();
        return concat(VERSION, salt, iv, tag, ciphertext).toString("base64");
      } finally {
        key.fill(0);
      }
    },
    decode: async (payload) => {
      const buf = Buffer.from(payload, "base64");
      const HEADER = 1 + SALT_LEN + IV_LEN + TAG_LEN;
      if (buf.length < HEADER) throw new Error("Invalid payload: too short");
      const ver = buf.subarray(0, 1);
      if (ver[0] !== 1) throw new Error(`Unsupported version: ${ver[0]}`);
      const salt = buf.subarray(1, 1 + SALT_LEN);
      const iv = buf.subarray(1 + SALT_LEN, 1 + SALT_LEN + IV_LEN);
      const tag = buf.subarray(1 + SALT_LEN + IV_LEN, HEADER);
      const ciphertext = buf.subarray(HEADER);
      const key = await kdf(salt);
      try {
        const decipher = crypto__default.default.createDecipheriv("aes-256-gcm", key, iv);
        const aad = concat(ver, salt);
        decipher.setAAD(aad, { plaintextLength: ciphertext.length });
        decipher.setAuthTag(tag);
        const plaintext = concat(decipher.update(ciphertext), decipher.final());
        return plaintext.toString("utf8");
      } finally {
        key.fill(0);
      }
    }
  };
};
var stashCodec = (stash) => ({
  decode: (value) => stash.get(value),
  encode: async (value) => {
    const key = crypto.randomUUID();
    await stash.set(key, value);
    return key;
  }
});
var superJsonCodec = {
  encode: (value) => superjson__default.default.stringify(value),
  decode: (value) => superjson__default.default.parse(value)
};

// src/error.ts
var PaginationError = class extends Error {
  code;
  constructor(opts) {
    super(opts.message, { cause: opts.cause });
    this.code = opts.code;
  }
};

// src/sorting.ts
var applyDefaultDirection = (dir) => dir ?? "asc";

// src/cursor.ts
var CursorPayloadSchema = zod.z.object({
  sig: zod.z.string(),
  k: zod.z.record(zod.z.string(), zod.z.any())
});
var decodeCursor = async (cursor, keysetCodec) => {
  if ("nextPage" in cursor)
    return {
      type: "next",
      payload: await decodeCursorPayload(cursor.nextPage, keysetCodec)
    };
  if ("prevPage" in cursor)
    return {
      type: "prev",
      payload: await decodeCursorPayload(cursor.prevPage, keysetCodec)
    };
  if ("offset" in cursor) return { type: "offset", offset: cursor.offset };
  throw new PaginationError({ message: "Invalid cursor", code: "INVALID_TOKEN" });
};
var decodeCursorPayload = async (token, keysetCodec) => {
  const decoded = await keysetCodec.decode(token);
  return CursorPayloadSchema.parse(decoded);
};
var resolvePageTokens = async (rows, sorts, cursorCodec, decodedCursor, overFetched) => {
  if (rows.length === 0) return {};
  const inverted = decodedCursor?.type === "prev";
  const isFirst = !decodedCursor || decodedCursor.type === "offset" && decodedCursor.offset === 0;
  const first = rows.at(0);
  const last = rows.at(-1);
  const startCursor = first ? await cursorCodec.encode(resolveCursor(first, sorts)) : void 0;
  const endCursor = last ? await cursorCodec.encode(resolveCursor(last, sorts)) : void 0;
  return {
    startCursor,
    endCursor,
    prevPage: (!inverted || overFetched) && !isFirst ? startCursor : void 0,
    nextPage: inverted || overFetched ? endCursor : void 0
  };
};
var resolveEdges = async (rows, sorts, cursorCodec) => {
  if (rows.length === 0) return [];
  return await Promise.all(
    rows.map(async (row) => {
      const cursor = await cursorCodec.encode(resolveCursor(row, sorts));
      return { node: row, cursor };
    })
  );
};
var getSortOutput = (sort) => "output" in sort ? sort.output : sort.col.split(".").at(-1);
var sortSignature = (sorts) => {
  const sig = sorts.map((s) => `${"output" in s ? s.output : s.col}:${s.dir ?? "asc"}`).join("|");
  return crypto.createHash("sha256").update(sig).digest("hex").slice(0, 8);
};
var resolveCursor = (item, sorts) => {
  const sig = sortSignature(sorts);
  const k = Object.fromEntries(
    sorts.map((s) => {
      const key = getSortOutput(s);
      return [key, item[key]];
    })
  );
  return { sig, k };
};
var buildCursorPredicateRecursive = (eb, sorts, decoded, idx = 0) => {
  const sort = sorts[idx];
  if (!sort) throw new PaginationError({ message: "Sort index out of bounds", code: "UNEXPECTED_ERROR" });
  const dir = applyDefaultDirection(sort.dir);
  const col = sort.col;
  const key = getSortOutput(sort);
  if (!(key in decoded.k))
    throw new PaginationError({
      message: `Missing pagination cursor value for "${key}"`,
      code: "INVALID_TOKEN"
    });
  const value = decoded.k[key];
  const cmp = dir === "desc" ? "<" : ">";
  if (idx === sorts.length - 1) {
    return eb(col, cmp, value);
  }
  const next = buildCursorPredicateRecursive(eb, sorts, decoded, idx + 1);
  if (value === null)
    return dir === "asc" ? eb.or([eb(col, "is", null).and(next), eb(col, "is not", null)]) : eb.and([eb(col, "is", null), next]);
  return eb.or([
    eb(col, cmp, value),
    // current column moves cursor forward
    eb.and([eb(col, "=", value), next]),
    // tie on current col → check next one
    ...dir === "desc" ? [eb(col, "is", null)] : []
    // include NULLs in DESC order
  ]);
};
var baseApplyCursor = (builder, sorts, cursor) => builder.where((eb) => buildCursorPredicateRecursive(eb, sorts, cursor.payload));

// src/dialect/mssql.ts
var MssqlPaginationDialect = {
  applyLimit: (builder, limit, cursorType) => cursorType === "offset" ? builder.fetch(limit) : builder.top(limit),
  applyOffset: (builder, offset) => builder.offset(offset),
  applySort: (builder, sorts) => {
    for (const s of sorts) {
      const dir = s.dir ?? "asc";
      builder = builder.orderBy(s.col, dir);
    }
    return builder;
  },
  applyCursor: baseApplyCursor
};

// src/dialect/mysql.ts
var MysqlPaginationDialect = {
  applyLimit: (builder, limit) => builder.limit(limit),
  applyOffset: (builder, offset) => builder.offset(offset),
  applySort: (builder, sorts) => {
    for (const s of sorts) {
      const dir = s.dir ?? "asc";
      builder = builder.orderBy(s.col, dir);
    }
    return builder;
  },
  applyCursor: baseApplyCursor
};

// src/dialect/postgres.ts
var PostgresPaginationDialect = {
  applyLimit: (builder, limit) => builder.limit(limit),
  applyOffset: (builder, offset) => builder.offset(offset),
  applySort: (builder, sorts) => {
    for (const s of sorts) {
      const dir = s.dir ?? "asc";
      builder = builder.orderBy(
        s.col,
        (a) => dir === "asc" ? a.asc().nullsFirst() : a.desc().nullsLast()
      );
    }
    return builder;
  },
  applyCursor: baseApplyCursor
};

// src/dialect/sqlite.ts
var SqlitePaginationDialect = {
  applyLimit: (builder, limit) => builder.limit(limit),
  applyOffset: (builder, offset) => builder.offset(offset),
  applySort: (builder, sorts) => {
    for (const s of sorts) {
      const dir = s.dir ?? "asc";
      builder = builder.orderBy(s.col, dir);
    }
    return builder;
  },
  applyCursor: baseApplyCursor
};

// src/paginator.ts
var DEFAULT_CURSOR_CODEC = codecPipe(superJsonCodec, base64UrlCodec);
var createPaginator = (opts) => ({
  paginate: (args) => paginate({ ...args, ...opts }),
  paginateWithEdges: (args) => paginateWithEdges({ ...args, ...opts })
});
var paginate = async ({
  query,
  sorts,
  limit,
  cursor,
  dialect,
  cursorCodec = DEFAULT_CURSOR_CODEC
}) => {
  assertLimitSorts(limit, sorts);
  try {
    const decodedCursor = cursor ? await decodeCursor(cursor, cursorCodec) : null;
    const sortsApplied = decodedCursor?.type === "prev" ? invertSorts(sorts) : sorts;
    let q = dialect.applySort(query, sortsApplied);
    q = dialect.applyLimit(q, limit + 1, decodedCursor?.type);
    if (decodedCursor) {
      if (decodedCursor.type === "offset") {
        q = dialect.applyOffset(q, decodedCursor.offset);
      } else {
        const sig = sortSignature(sorts);
        if (decodedCursor.payload.sig !== sig)
          throw new PaginationError({ message: "Page token does not match sort order", code: "INVALID_TOKEN" });
        q = dialect.applyCursor(q, sortsApplied, decodedCursor);
      }
    }
    const rows = await q.execute();
    const items = decodedCursor?.type === "prev" ? rows.slice(0, limit).reverse() : rows.slice(0, limit);
    const { startCursor, endCursor, prevPage, nextPage } = await resolvePageTokens(
      items,
      sorts,
      cursorCodec,
      decodedCursor,
      rows.length > limit
    );
    return {
      items,
      prevPage,
      nextPage,
      startCursor,
      endCursor,
      hasPrevPage: !!prevPage,
      hasNextPage: !!nextPage
    };
  } catch (error) {
    if (error instanceof PaginationError) throw error;
    throw new PaginationError({ message: "Failed to paginate", cause: error, code: "UNEXPECTED_ERROR" });
  }
};
var paginateWithEdges = async (args) => {
  const { sorts, cursorCodec = DEFAULT_CURSOR_CODEC } = args;
  const { items, ...paginated } = await paginate(args);
  try {
    const edges = await resolveEdges(items, sorts, cursorCodec);
    return {
      ...paginated,
      edges
    };
  } catch (error) {
    if (error instanceof PaginationError) throw error;
    throw new PaginationError({ message: "Failed to generate edges", cause: error, code: "UNEXPECTED_ERROR" });
  }
};
var assertLimitSorts = (limit, sorts) => {
  if (!(Number.isInteger(limit) && limit > 0))
    throw new PaginationError({ message: "Invalid page size limit", code: "INVALID_LIMIT" });
  if (!Array.isArray(sorts) || sorts.length < 1)
    throw new PaginationError({ message: "Cannot paginate without sorting", code: "INVALID_SORT" });
};
var invertSorts = (sorts) => sorts.map((s) => ({
  ...s,
  dir: applyDefaultDirection(s.dir) === "desc" ? "asc" : "desc"
}));

exports.MssqlPaginationDialect = MssqlPaginationDialect;
exports.MysqlPaginationDialect = MysqlPaginationDialect;
exports.PaginationError = PaginationError;
exports.PostgresPaginationDialect = PostgresPaginationDialect;
exports.SqlitePaginationDialect = SqlitePaginationDialect;
exports.base64UrlCodec = base64UrlCodec;
exports.baseApplyCursor = baseApplyCursor;
exports.buildCursorPredicateRecursive = buildCursorPredicateRecursive;
exports.codecPipe = codecPipe;
exports.createAesCodec = createAesCodec;
exports.createPaginator = createPaginator;
exports.stashCodec = stashCodec;
exports.superJsonCodec = superJsonCodec;
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map