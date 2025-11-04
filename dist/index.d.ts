import { OrderByDirection, ReferenceExpression, StringReference, SelectQueryBuilder, ExpressionBuilder, ExpressionWrapper, SqlBool } from 'kysely';
import { z } from 'zod';

/**
 * A bidirectional transformer between two value types: input `I` and output `O`.
 *
 * @template I The type accepted by `encode` and produced by `decode`.
 * @template O The type produced by `encode` and accepted by `decode`.
 *
 * @property {(value: I) => Promise<O> | O} encode
 * Transform an input value `I` into an output value `O`. May be sync or async.
 *
 * @property {(value: O) => Promise<I> | I} decode
 * Inverse transform: turn an output value `O` back into an input value `I`. May be sync or async.
 */
type Codec<I = any, O = any> = {
    encode: (value: I) => Promise<O> | O;
    decode: (value: O) => Promise<I> | I;
};
type InOf<C> = C extends Codec<infer I, any> ? I : never;
type OutOf<C> = C extends Codec<any, infer O> ? O : never;
type First<T extends readonly unknown[]> = T extends readonly [infer F, ...unknown[]] ? F : never;
type Last<T extends readonly unknown[]> = T extends readonly [...unknown[], infer L] ? L : never;
type Composable<Cs extends readonly Codec[]> = Cs extends readonly [] ? true : Cs extends readonly [Codec] ? true : Cs extends readonly [infer A, infer B, ...infer R] ? A extends Codec<any, infer AO> ? B extends Codec<infer BI, any> ? [AO] extends [BI] ? Composable<[B, ...(R extends readonly Codec[] ? R : never)]> : false : false : false : false;
/**
 * Compose a non-empty list of codecs into a single codec.
 * Validates that the codecs are type-composable: the input of each codec must be the output of the previous.
 *
 * - `encode` runs **left → right** through the provided codecs.
 * - `decode` runs **right → left** (the inverse order).
 *
 * @template Cs A non-empty readonly tuple of codecs to compose.
 * @param {...Cs} codecs The codecs to compose, in the order their `encode` functions should run.
 * @returns Codec<InOf<First<Cs>>, OutOf<Last<Cs>>> A codec representing the composition, or `never` if the codecs are not type-composable.
 */
declare const codecPipe: <Cs extends readonly [Codec, ...Codec[]]>(...codecs: Cs) => Composable<Cs> extends true ? Codec<InOf<First<Cs>>, OutOf<Last<Cs>>> : never;

/**
 * Base64 string codec. URL friendly
 */
declare const base64UrlCodec: Codec<string, string>;

/**
 * AES-256-GCM string codec using scrypt-derived keys.
 *
 * ## Usage
 * ```ts
 * const codec = createAesCodec(process.env.SECRET!);
 *
 * const encrypted = await codec.encode("hello");
 * const decrypted = await codec.decode(encrypted);
 * ```
 *
 * ## Notes
 * - Uses `scrypt` (N=2^15, r=8, p=1) to derive a 256-bit key from `secret` + random 16-byte salt.
 * - Encrypts with random 12-byte IV and includes a 16-byte auth tag.
 * - Payload = Base64 of `[1-byte ver][salt][iv][tag][ciphertext]`.
 * - Tampering or wrong secret throws on decode.
 * - Works in Node.js with built-in `crypto`.
 *
 * @param secret - The secret key to use for the codec.
 * @returns The codec.
 */
declare const createAesCodec: (secret: string) => Codec<string, string>;

/**
 * A simple asynchronous key-value storage interface.
 *
 * Each key and value must be a string.
 * Implementations could be in-memory, filesystem-based, Redis-backed, etc.
 */
type Stash = {
    /**
     * Retrieve a value by key.
     * @param key The key to retrieve.
     * @returns The value.
     */
    get: (key: string) => Promise<string>;
    /**
     * Store a value under a specific key.
     * @param key The key to store the value under.
     * @param value The value to store.
     */
    set: (key: string, value: string) => Promise<void>;
};
/**
 * Creates a {@link Codec} that encodes strings into stash keys and decodes keys back into their stored strings.
 *
 * - **encode(value)**: stores the given string `value` in the provided {@link Stash} under a randomly generated UUID key.
 *   Returns the generated key.
 * - **decode(key)**: retrieves and returns the original string value stored under `key`.
 *
 * This is useful for scenarios where you want to replace large or sensitive strings
 * with short unique identifiers and retrieve them later.
 *
 * @param stash The stash instance to use for storage and retrieval.
 */
declare const stashCodec: (stash: Stash) => Codec<string, string>;

/**
 * SuperJSON object codec.
 * Superjson is used to preserve types like Date & BigInt
 */
declare const superJsonCodec: Codec<unknown, string>;

type MatchingKeys<Obj, M> = Extract<{
    [K in keyof Obj]-?: Obj[K] extends M ? K : never;
}[keyof Obj], string>;
type OptionallyQualified<TB, O, Allowed> = TB extends string ? MatchingKeys<O, Allowed> | `${TB}.${MatchingKeys<O, Allowed>}` : never;
type SortItem<DB, TB extends keyof DB, O, Allowed> = {
    dir?: OrderByDirection;
} & ({
    col: ReferenceExpression<DB, TB>;
    output: MatchingKeys<O, Allowed>;
} | {
    col: StringReference<DB, TB> & OptionallyQualified<TB, O, Allowed>;
});
type Sortable = string | number | boolean | Date | bigint;
type SortSet<DB, TB extends keyof DB, O> = readonly [
    ...SortItem<DB, TB, O, Sortable | null>[],
    SortItem<DB, TB, O, Sortable>
];

declare const CursorPayloadSchema: z.ZodObject<{
    sig: z.ZodString;
    k: z.ZodRecord<z.ZodString, z.ZodAny>;
}, z.core.$strip>;
type CursorPayload = z.output<typeof CursorPayloadSchema>;
type CursorIncoming = {
    nextPage: string;
} | {
    prevPage: string;
} | {
    offset: number;
};
type DecodedCursorNextPrev = {
    type: 'next' | 'prev';
    payload: CursorPayload;
};
type CursorOutgoing = {
    startCursor?: string;
    endCursor?: string;
    nextPage?: string;
    prevPage?: string;
};
type EdgeOutgoing<T> = {
    node: T;
    cursor: string;
};
declare const buildCursorPredicateRecursive: <DB, TB extends keyof DB, S extends SortSet<any, any, any>>(eb: ExpressionBuilder<DB, TB>, sorts: S, decoded: CursorPayload, idx?: number) => ExpressionWrapper<DB, TB, SqlBool>;
declare const baseApplyCursor: <DB, TB extends keyof DB, O>(builder: SelectQueryBuilder<DB, TB, O>, sorts: SortSet<DB, TB, O>, cursor: DecodedCursorNextPrev) => SelectQueryBuilder<DB, TB, O>;

type PaginationDialect = {
    applyLimit: <DB, TB extends keyof DB, O>(builder: SelectQueryBuilder<DB, TB, O>, limit: number, cursorType?: 'next' | 'prev' | 'offset') => SelectQueryBuilder<DB, TB, O>;
    applyOffset: <DB, TB extends keyof DB, O>(builder: SelectQueryBuilder<DB, TB, O>, offset: number) => SelectQueryBuilder<DB, TB, O>;
    applySort: <DB, TB extends keyof DB, O>(builder: SelectQueryBuilder<DB, TB, O>, sorts: SortSet<DB, TB, O>) => SelectQueryBuilder<DB, TB, O>;
    applyCursor: <DB, TB extends keyof DB, O>(query: SelectQueryBuilder<DB, TB, O>, sorts: SortSet<DB, TB, O>, cursor: DecodedCursorNextPrev) => SelectQueryBuilder<DB, TB, O>;
};
type PaginatorOptions = {
    dialect: PaginationDialect;
    /**
     * Defaults to superJson & base64Url
     */
    cursorCodec?: Codec<any, string>;
};
type PaginateArgs<DB, TB extends keyof DB, O, S extends SortSet<DB, TB, O>> = {
    query: SelectQueryBuilder<DB, TB, O>;
    sorts: S;
    limit: number;
    cursor?: CursorIncoming;
};
type PaginatedResult<T> = {
    items: T[];
    hasNextPage: boolean;
    hasPrevPage: boolean;
} & CursorOutgoing;
type PaginatedResultWithEdges<T> = Omit<PaginatedResult<T>, 'items'> & {
    edges: EdgeOutgoing<T>[];
};
type Paginator = {
    paginate: <DB, TB extends keyof DB, O, S extends SortSet<DB, TB, O>>(args: PaginateArgs<DB, TB, O, S>) => Promise<PaginatedResult<O>>;
    paginateWithEdges: <DB, TB extends keyof DB, O, S extends SortSet<DB, TB, O>>(args: PaginateArgs<DB, TB, O, S>) => Promise<PaginatedResultWithEdges<O>>;
};

/**
 * A dialect for SQL Server
 */
declare const MssqlPaginationDialect: PaginationDialect;

/**
 * A dialect for MySQL
 */
declare const MysqlPaginationDialect: PaginationDialect;

/**
 * A dialect for PostgreSQL
 */
declare const PostgresPaginationDialect: PaginationDialect;

/**
 * A dialect for SQLite
 */
declare const SqlitePaginationDialect: PaginationDialect;

type ErrorCode = 'INVALID_TOKEN' | 'INVALID_SORT' | 'INVALID_LIMIT' | 'UNEXPECTED_ERROR';
type ErrorOpts = {
    message: string;
    code: ErrorCode;
    cause?: Error;
};
declare class PaginationError extends Error {
    code: ErrorCode;
    constructor(opts: ErrorOpts);
}

declare const createPaginator: (opts: PaginatorOptions) => Paginator;

export { type Codec, type CursorIncoming, type ErrorCode, MssqlPaginationDialect, MysqlPaginationDialect, type PaginateArgs, type PaginatedResult, type PaginationDialect, PaginationError, type Paginator, type PaginatorOptions, PostgresPaginationDialect, SqlitePaginationDialect, base64UrlCodec, baseApplyCursor, buildCursorPredicateRecursive, codecPipe, createAesCodec, createPaginator, stashCodec, superJsonCodec };
