import type { AuditRecord } from "../types.js";
import type { AuditStore } from "./types.js";

// ============================================================
// PostgreSQL Audit Store — persists audit records to Postgres
//
// Design notes:
// - `pg` stays an OPTIONAL peer dependency. This module never imports
//   it statically: either inject a ready pool (anything satisfying the
//   structural `PgPoolLike` — a real `pg.Pool` does, see
//   `pg-compat-check.ts`) or pass connection config, in which case the
//   store lazily `await import("pg")`s when the pool is first needed.
// - Records carry HASHES + metadata only (`inputHash`, `userIdHash` —
//   see AuditLogger). Raw input/content is never persisted (DSGVO).
// - Write failures NEVER throw into the caller. Audit is best-effort
//   forensic logging: `AuditLogger.log()` awaits `flush()` when the
//   batch fills up, so a throwing store would propagate straight into
//   the LLM request path (`shield.scan()`). Failures are reported as a
//   single concise stderr warning and the batch is dropped.
// ============================================================

/** Minimal structural query result (a real `pg.QueryResult` satisfies this). */
export interface PgQueryResultLike {
  rowCount?: number | null;
}

/**
 * Minimal structural connection-pool interface. A real `pg.Pool`
 * satisfies it (compile-time proof in `pg-compat-check.ts`), but any
 * object with a parameterized `query()` and an `end()` works — core
 * never hard-imports `pg` types.
 */
export interface PgPoolLike {
  query(text: string, values?: unknown[]): Promise<PgQueryResultLike>;
  end(): Promise<void>;
}

/**
 * Discrete connection options, passed through untouched to
 * `new pg.Pool(...)`. Only the most common fields are typed —
 * any further `pg.PoolConfig` option can be supplied as well.
 */
export interface PostgresConnectionOptions {
  host?: string;
  port?: number;
  user?: string;
  password?: string;
  database?: string;
  connectionString?: string;
  ssl?: boolean | Record<string, unknown>;
  /** Pool size cap (pg default: 10). */
  max?: number;
  idleTimeoutMillis?: number;
  connectionTimeoutMillis?: number;
  /** Passthrough for any other `pg.PoolConfig` option. */
  [option: string]: unknown;
}

export interface PostgresAuditStoreConfig {
  /**
   * Injected, ready-to-use pool. The caller owns its lifecycle:
   * `close()` will NOT call `end()` on an injected pool.
   */
  pool?: PgPoolLike;
  /** Connection string, e.g. `postgres://user:pass@host:5432/db`. Ignored when `pool` is injected. */
  connectionString?: string;
  /** Discrete `pg.Pool` options (alternative to `connectionString`). Ignored when `pool` is injected. */
  connection?: PostgresConnectionOptions;
  /**
   * Run `ensureSchema()` once before the first write (default: true).
   * Set to false when migrations are managed externally or the DB role
   * has no DDL permission.
   */
  autoEnsureSchema?: boolean;
  /**
   * Overrides the dynamic `import("pg")` used to load the driver when
   * no pool is injected. Intended for tests / dependency injection.
   */
  pgImport?: () => Promise<unknown>;
}

/**
 * Audit table name. Deliberately NOT configurable so that SQL
 * identifiers are never built from user input.
 */
const AUDIT_TABLE = "ai_shield_audit";

/**
 * Rows per INSERT statement. 16 bind parameters per row; Postgres caps
 * a single statement at 65_535 parameters, so 1_000 rows (16_000
 * params) leaves an order-of-magnitude margin. `AuditLogger`'s default
 * batch size is 100 — chunking only engages for large manual batches.
 */
const MAX_ROWS_PER_INSERT = 1_000;

/**
 * Column order for INSERTs — must stay in sync with `buildInsert()`'s
 * row array. `"timestamp"` is quoted (type-name keyword).
 */
const AUDIT_COLUMNS = [
  "id",
  '"timestamp"',
  "session_id",
  "agent_id",
  "user_id_hash",
  "request_type",
  "input_hash",
  "input_token_count",
  "model",
  "security_decision",
  "security_reason",
  "violations",
  "scan_duration_ms",
  "output_token_count",
  "tools_called",
  "cost_usd",
] as const;

/**
 * Idempotent runtime schema. Matches the reference `schema.sql` column
 * layout with three deliberate differences:
 * - no monthly partitioning (that stays an opt-in ops concern),
 * - `session_id` / `agent_id` / `model` are TEXT — these values are
 *   caller-supplied free-form strings, not guaranteed UUIDs / <64 chars,
 * - `scan_duration_ms` is DOUBLE PRECISION — scans finish in fractional
 *   milliseconds and INTEGER would reject values like `1.53`.
 *
 * `id` stays UUID: `AuditLogger` mints ids via `crypto.randomUUID()`.
 */
const SCHEMA_DDL = `
CREATE TABLE IF NOT EXISTS ${AUDIT_TABLE} (
  id UUID PRIMARY KEY,
  "timestamp" TIMESTAMPTZ NOT NULL,
  session_id TEXT,
  agent_id TEXT,
  user_id_hash VARCHAR(64),
  request_type VARCHAR(20) NOT NULL,
  input_hash VARCHAR(64) NOT NULL,
  input_token_count INTEGER,
  model TEXT,
  security_decision VARCHAR(10) NOT NULL,
  security_reason TEXT,
  violations JSONB NOT NULL DEFAULT '[]',
  scan_duration_ms DOUBLE PRECISION,
  output_token_count INTEGER,
  tools_called TEXT[],
  cost_usd NUMERIC(10, 6)
);
CREATE INDEX IF NOT EXISTS idx_ai_shield_audit_timestamp ON ${AUDIT_TABLE} ("timestamp");
CREATE INDEX IF NOT EXISTS idx_ai_shield_audit_agent ON ${AUDIT_TABLE} (agent_id, "timestamp");
`;

/**
 * PostgreSQL-backed {@link AuditStore}.
 *
 * @example
 * ```ts
 * // Via AIShield config (lazy-imports the optional `pg` package):
 * const shield = new AIShield({
 *   audit: { store: "postgresql", connectionString: process.env.DATABASE_URL },
 * });
 *
 * // Or standalone with an injected pool (caller keeps pool ownership):
 * const store = new PostgresAuditStore({ pool: myPgPool });
 * const shield2 = new AIShield({ audit: { store } });
 * ```
 */
export class PostgresAuditStore implements AuditStore {
  private pool: PgPoolLike | null;
  private poolPromise: Promise<PgPoolLike> | null = null;
  private schemaPromise: Promise<void> | null = null;
  private closed = false;

  private readonly ownsPool: boolean;
  private readonly autoEnsureSchema: boolean;
  private readonly connectionString?: string;
  private readonly connection?: PostgresConnectionOptions;
  private readonly pgImport: () => Promise<unknown>;

  constructor(config: PostgresAuditStoreConfig) {
    if (!config.pool && !config.connectionString && !config.connection) {
      throw new Error(
        "PostgresAuditStore: no connection information — provide an injected " +
          "`pool`, a `connectionString`, or discrete `connection` options.",
      );
    }
    this.pool = config.pool ?? null;
    this.ownsPool = !config.pool;
    this.autoEnsureSchema = config.autoEnsureSchema !== false;
    this.connectionString = config.connectionString;
    this.connection = config.connection;
    this.pgImport = config.pgImport ?? (() => import("pg" as string));
  }

  /**
   * Resolve the underlying pool. For config-based stores this performs
   * the lazy `import("pg")` and constructs the pool (no connection is
   * opened yet — pg pools connect on first query). Call this explicitly
   * to FAIL FAST when `pg` is not installed: it throws a clear,
   * actionable error. The write path itself never throws — there,
   * failures become a stderr warning and the batch is dropped.
   */
  async init(): Promise<void> {
    await this.resolvePool();
  }

  /**
   * Create the audit table + indexes when missing (idempotent DDL,
   * memoized per successful run). Runs automatically once before the
   * first write unless `autoEnsureSchema: false`; call it yourself for
   * eager, fail-fast setup — unlike the write path, this method DOES
   * throw on failure.
   */
  ensureSchema(): Promise<void> {
    this.schemaPromise ??= this.runSchemaDDL().catch((err: unknown) => {
      // Reset so the next write retries — e.g. a missing DDL grant that
      // an operator fixes later shouldn't permanently poison the store.
      this.schemaPromise = null;
      throw err;
    });
    return this.schemaPromise;
  }

  /** Write a single record (delegates to {@link writeBatch}). */
  async write(record: AuditRecord): Promise<void> {
    return this.writeBatch([record]);
  }

  /**
   * Persist a batch via a single multi-row parameterized INSERT
   * (chunked only above {@link MAX_ROWS_PER_INSERT} rows).
   * NEVER throws — see the module header for why.
   */
  async writeBatch(records: AuditRecord[]): Promise<void> {
    if (records.length === 0 || this.closed) return;
    try {
      const pool = await this.resolvePool();
      if (this.autoEnsureSchema) await this.ensureSchema();
      for (let offset = 0; offset < records.length; offset += MAX_ROWS_PER_INSERT) {
        const chunk = records.slice(offset, offset + MAX_ROWS_PER_INSERT);
        const { text, values } = buildInsert(chunk);
        await pool.query(text, values);
      }
    } catch (err) {
      // Best-effort forensics: a database failure must never break the
      // LLM request path (AuditLogger awaits writeBatch on batch-full).
      process.stderr.write(
        `[AI-Shield] PostgresAuditStore: write failed — ${records.length} audit record(s) dropped: ${errorMessage(err)}\n`,
      );
    }
  }

  /** No internal buffer — batching lives in {@link AuditLogger}. */
  async flush(): Promise<void> {
    /* noop */
  }

  /**
   * Close the store. Ends the pool ONLY when this store created it —
   * injected pools are owned by the caller and stay open. Idempotent;
   * never throws.
   */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (!this.ownsPool) return;
    const pending = this.poolPromise;
    if (!pending) return; // pool was never created — nothing to end
    try {
      const pool = await pending;
      await pool.end();
    } catch {
      // Pool never materialized (e.g. `pg` missing) or end() failed —
      // nothing further to release; the write path already warned.
    }
  }

  // --- Private ---

  private async runSchemaDDL(): Promise<void> {
    const pool = await this.resolvePool();
    await pool.query(SCHEMA_DDL);
  }

  private resolvePool(): Promise<PgPoolLike> {
    if (this.pool) return Promise.resolve(this.pool);
    this.poolPromise ??= this.createPool().catch((err: unknown) => {
      // Reset so a later write can retry instead of caching the rejection.
      this.poolPromise = null;
      throw err;
    });
    return this.poolPromise;
  }

  private async createPool(): Promise<PgPoolLike> {
    let mod: unknown;
    try {
      mod = await this.pgImport();
    } catch (err) {
      throw new Error(
        'ai-shield-core: audit store "postgresql" needs the optional `pg` package, ' +
          "but it could not be loaded. Install it with: npm install pg\n" +
          `Underlying error: ${errorMessage(err)}`,
      );
    }
    const PoolCtor = resolvePoolConstructor(mod);
    if (!PoolCtor) {
      throw new Error(
        "ai-shield-core: the `pg` module did not expose a Pool constructor " +
          "(expected `Pool` as a named or default export).",
      );
    }
    const poolConfig: Record<string, unknown> = { ...this.connection };
    if (this.connectionString) {
      poolConfig["connectionString"] = this.connectionString;
    }
    const pool = new PoolCtor(poolConfig);
    this.pool = pool;
    return pool;
  }
}

// --- Helpers ---

type PgPoolConstructor = new (config?: Record<string, unknown>) => PgPoolLike;

/**
 * Extract the `Pool` constructor from whatever shape `import("pg")`
 * produced: pg >= 8.15 ships an ESM wrapper with a named `Pool` export;
 * older CommonJS-only builds surface it on the `default` namespace.
 */
function resolvePoolConstructor(mod: unknown): PgPoolConstructor | null {
  const named = readPoolProperty(mod);
  if (named) return named;
  if (typeof mod === "object" && mod !== null && "default" in mod) {
    return readPoolProperty((mod as { default: unknown }).default);
  }
  return null;
}

function readPoolProperty(candidate: unknown): PgPoolConstructor | null {
  if (typeof candidate !== "object" || candidate === null) return null;
  const pool = (candidate as { Pool?: unknown }).Pool;
  return typeof pool === "function" ? (pool as PgPoolConstructor) : null;
}

interface InsertStatement {
  text: string;
  values: unknown[];
}

/**
 * Build ONE multi-row parameterized INSERT: `$1..$n` placeholders only,
 * values always passed out-of-band — record data is never interpolated
 * into the SQL text.
 */
function buildInsert(records: AuditRecord[]): InsertStatement {
  const values: unknown[] = [];
  const rowPlaceholders: string[] = [];

  for (const record of records) {
    // Order must match AUDIT_COLUMNS.
    const row: unknown[] = [
      record.id,
      record.timestamp,
      record.sessionId ?? null,
      record.agentId ?? null,
      record.userIdHash ?? null,
      record.requestType,
      record.inputHash,
      record.inputTokenCount ?? null,
      record.model ?? null,
      record.securityDecision,
      record.securityReason ?? null,
      // Explicit stringify → predictable jsonb input independent of the
      // driver's object serialization.
      JSON.stringify(record.violations ?? []),
      record.scanDurationMs,
      record.outputTokenCount ?? null,
      record.toolsCalled ?? null,
      record.costUsd ?? null,
    ];
    const base = values.length;
    rowPlaceholders.push(
      `(${row.map((_, i) => `$${base + i + 1}`).join(", ")})`,
    );
    values.push(...row);
  }

  const text =
    `INSERT INTO ${AUDIT_TABLE} (${AUDIT_COLUMNS.join(", ")}) ` +
    `VALUES ${rowPlaceholders.join(", ")}`;
  return { text, values };
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
