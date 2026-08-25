// database.js
// Optional PostgreSQL persistence. Matkap runs fully in memory when
// DATABASE_URL is not set; every function below becomes a no-op in that case.
import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

const dbEnabled = !!process.env.DATABASE_URL && process.env.MATKAP_DISABLE_DATABASE !== 'true';

const pool = dbEnabled
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    })
  : null;

async function initDatabase() {
  if (!dbEnabled) {
    console.log('No DATABASE_URL set - running in memory only (no persistence).');
    return;
  }
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS matkap_logs (
        id SERIAL PRIMARY KEY,
        user_key VARCHAR(64),
        bot_token TEXT,
        bot_username VARCHAR(255),
        chat_id VARCHAR(50),
        log_type VARCHAR(50),
        message TEXT,
        file_id TEXT,
        file_type VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS captured_messages (
        id SERIAL PRIMARY KEY,
        user_key VARCHAR(64),
        bot_token TEXT,
        bot_username VARCHAR(255),
        message_id BIGINT,
        from_id VARCHAR(50),
        chat_id VARCHAR(50),
        message_text TEXT,
        file_id TEXT,
        file_type VARCHAR(50),
        raw_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS feed_cache (
        feed_key VARCHAR(64) PRIMARY KEY,
        data JSONB,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Database tables initialized.');
  } catch (err) {
    console.error('Database initialization error:', err);
  } finally {
    client.release();
  }
}

async function saveFeedCache(key, data) {
  if (!dbEnabled) return;
  const client = await pool.connect();
  try {
    await client.query(
      `INSERT INTO feed_cache (feed_key, data, updated_at) VALUES ($1, $2, CURRENT_TIMESTAMP)
       ON CONFLICT (feed_key) DO UPDATE SET data = $2, updated_at = CURRENT_TIMESTAMP`,
      [key, JSON.stringify(data)]
    );
  } catch (err) {
    console.error('saveFeedCache error:', err);
  } finally {
    client.release();
  }
}

async function getFeedCache(key) {
  if (!dbEnabled) return null;
  const client = await pool.connect();
  try {
    const r = await client.query(`SELECT data, updated_at FROM feed_cache WHERE feed_key = $1`, [key]);
    if (!r.rows[0]) return null;
    return { data: r.rows[0].data, updated_at: r.rows[0].updated_at };
  } catch (err) {
    console.error('getFeedCache error:', err);
    return null;
  } finally {
    client.release();
  }
}

async function saveLog(data) {
  if (!dbEnabled) return null;
  const client = await pool.connect();
  try {
    const result = await client.query(
      `INSERT INTO matkap_logs
       (user_key, bot_token, bot_username, chat_id, log_type, message, file_id, file_type)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id`,
      [
        data.userKey || null,
        data.botToken || null,
        data.botUsername || null,
        data.chatId || null,
        data.logType || 'info',
        data.message || null,
        data.fileId || null,
        data.fileType || null,
      ]
    );
    return result.rows[0];
  } catch (err) {
    console.error('saveLog error:', err);
    return null;
  } finally {
    client.release();
  }
}

async function saveCapturedMessage(data) {
  if (!dbEnabled) return null;
  const client = await pool.connect();
  try {
    const result = await client.query(
      `INSERT INTO captured_messages
       (user_key, bot_token, bot_username, message_id, from_id, chat_id, message_text, file_id, file_type, raw_data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id`,
      [
        data.userKey || null,
        data.botToken || null,
        data.botUsername || null,
        data.messageId || null,
        data.fromId || null,
        data.chatId || null,
        data.messageText || null,
        data.fileId || null,
        data.fileType || null,
        data.rawData ? JSON.stringify(data.rawData) : null,
      ]
    );
    return result.rows[0];
  } catch (err) {
    console.error('saveCapturedMessage error:', err);
    return null;
  } finally {
    client.release();
  }
}

export {
  dbEnabled,
  pool,
  initDatabase,
  saveLog,
  saveCapturedMessage,
  saveFeedCache,
  getFeedCache,
};
