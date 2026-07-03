// ============================================================
// Compile-time compatibility proof against the REAL `pg` type
// declarations (@types/pg devDependency; verified against
// pg 8.22.0 / @types/pg 8.20.0).
//
// `PostgresAuditStore` duck-types the pool (`PgPoolLike`) to avoid a
// hard runtime dependency on `pg` — this file guarantees at `tsc -b`
// time that the duck types stay structurally compatible with the
// actual driver surface:
//
//   1. A real `pg.Pool` instance satisfies `PgPoolLike`, so
//      `new PostgresAuditStore({ pool })` accepts a real pool.
//   2. A real `pg.QueryResult` satisfies `PgQueryResultLike`.
//
// Not exported from the package entry point — types only, no runtime.
// ============================================================

import type { Pool, QueryResult } from "pg";
import type { PgPoolLike, PgQueryResultLike } from "./postgres.js";

type Extends<A, B> = A extends B ? true : false;
type Assert<T extends true> = T;

/** 1. Real pool satisfies the duck-typed pool interface. */
export type PoolCompat = Assert<Extends<Pool, PgPoolLike>>;

/** 2. Real query result satisfies the duck-typed result. */
export type ResultCompat = Assert<Extends<QueryResult, PgQueryResultLike>>;
